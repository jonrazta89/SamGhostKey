package com.EternalTimes.GhostKey.ksu

/**
 * KSUD_STAGE：从设备已装的 KernelSU 系管理器 APK 中提取 ksud（libksud.so）。
 *
 * 机制背景（对齐 ghostlock-app-main 的 ManagerScanner + PC 端 ksu_activate.sh 实测）：
 *  - KernelSU 系管理器把 ksud 可执行文件伪装成 `libksud.so` 打进 APK，
 *    安装后落在 `<apk目录>/lib/arm64/libksud.so`（即 nativeLibraryDir）；
 *  - ksud 内置多套 KMI 的 kernelsu.ko（android15-6.6_kernelsu.ko 等），
 *    `late-load --kmi <KMI>` 时自动选内置对应 ko，并自动替换 vermagic，
 *    因此「同一 KMI 任意构建号」的内核都能加载；
 *  - 从**设备已装管理器**提取 ksud，版本天然与管理器配套 —— 管理器升级即
 *    获得新 KMI 支持，无需重打本 APK（对比：内置固定 ksud 的 KMI 集冻结在打包时刻）。
 *
 * 脚本在 Shizuku UserService（uid=shell/2000 或 root）上下文执行：
 * `pm path`、读 `/data/local/tmp` 均为 shell 权限内操作。
 */
object KsudStage {

    /** 提取目标路径（shell uid 可写；同时也在 ksu.c find_ksud 兜底链里）。 */
    const val TARGET: String = "/data/local/tmp/ksud"

    /** KSU 管理器候选包名（优先级顺序，对齐参考 ManagerScanner 的家族列表）。
     *
     * 覆盖 KernelSU 官方 + 主流 fork（KernelSU-Next / SukiSU Ultra / ReSukiSU / Bakasu 等）。
     * SukiSU 系（`com.sukisu.ultra`）是 KernelSU fork：其管理器仍带 `libksud.so`、late-load
     * 语义一致、模块仍注册为 `kernelsu`，故可直接复用本接管链路（无需内置 SuKiSu 产物）。
     * 这只是**快速通道**；未列出的自编译 fork 由下方 `scanManagerLib` 的全量「认文件不认包名」扫描兜住。
     */
    private val MANAGER_PACKAGES = listOf(
        "me.weishu.kernelsu",
        "me.weishu.kernelsu.prerelease",
        "me.weishu.kernelsu.next",
        "com.rifsxd.ksunext",
        "com.sukisu.ultra",
        "com.resukisu.resukisu",
        "org.bakasu.bakasu",
        "com.kowx712.supermanager",
    )

    /** 管理器 APK 内 ksud 的常规伪装文件名（KernelSU / Next 等）。 */
    private const val LIB_NAME = "libksud.so"

    /**
     * ksud 体积下限：真 ksud 是内嵌多套 .ko 的大 ELF（~5–6.5 MB），远大于普通
     * JNI 库。用它过滤全量扫描里的无关小 .so，避免逐个读大文件。
     */
    private const val KSUD_MIN_SIZE = 512L * 1024

    /**
     * 纯函数：给定字节判断是否 ksud —— ELF 魔数 + 带 late-load / kernelsu 语义串。
     *
     * 用于识别**随机改名**的混淆 fork：如 SukiSU Ultra（com.sukisu.ultra）把 ksud
     * 打成 `libtqqfthevwb.so`，常规名 libksud.so 在设备上根本不存在，只按文件名找必漏。
     */
    fun containsKsudSignature(bytes: ByteArray): Boolean {
        if (bytes.size < KSUD_MIN_SIZE) return false
        // ELF 魔数：0x7f 'E' 'L' 'F'
        if (bytes[0] != 0x7f.toByte() || bytes[1] != 'E'.code.toByte() ||
            bytes[2] != 'L'.code.toByte() || bytes[3] != 'F'.code.toByte()
        ) return false
        // ISO_8859_1 保证字节→字符 1:1，可安全做 ASCII 子串检索
        val s = String(bytes, Charsets.ISO_8859_1)
        return s.contains("late-load") && s.contains("kernelsu", ignoreCase = true)
    }

    /** nativeLibraryDir 下定位 ksud：先常规名，再按内容扫（覆盖混淆改名）。 */
    private fun findKsudInDir(dir: java.io.File): java.io.File? {
        if (!dir.isDirectory) return null
        val named = java.io.File(dir, LIB_NAME)
        if (named.isFile && isKsudFile(named)) return named
        val sos = runCatching {
            dir.listFiles { f: java.io.File ->
                f.isFile && f.name.endsWith(".so") && f.length() >= KSUD_MIN_SIZE
            }
        }.getOrNull() ?: return null
        // ksud 通常是目录里最大的 .so，从大到小试，尽早命中、少读文件
        return sos.sortedByDescending { it.length() }.firstOrNull { isKsudFile(it) }
    }

    private fun isKsudFile(f: java.io.File): Boolean = runCatching {
        if (f.length() < KSUD_MIN_SIZE) return@runCatching false
        f.inputStream().use { input ->
            val head = ByteArray(4)
            if (input.read(head) != 4) return@use false
            if (head[0] != 0x7f.toByte() || head[1] != 'E'.code.toByte() ||
                head[2] != 'L'.code.toByte() || head[3] != 'F'.code.toByte()
            ) return@use false
            /*
             * 分块扫两个语义串，不再把整个文件读进内存。
             *
             * 真 ksud 有 5~6.5 MB；原来的 readBytes() + String(bytes) 会为**每个**
             * 候选分配几十 MB 临时对象（6 MB 字节数组 + 12 MB 字符数组），
             * 全量扫包时几十个候选叠起来就是几百 MB 垃圾 —— 主线程上做这件事
             * 就是「应用启动很慢」的主因。
             */
            var lateLoad = false
            var kernelSu = false
            val buf = ByteArray(256 * 1024)
            var carry = ""
            while (!lateLoad || !kernelSu) {
                val n = input.read(buf)
                if (n <= 0) break
                val s = carry + String(buf, 0, n, Charsets.ISO_8859_1)
                if (!lateLoad && s.contains("late-load")) lateLoad = true
                if (!kernelSu && s.contains("kernelsu", ignoreCase = true)) kernelSu = true
                /* 保留尾部避免语义串正好跨块边界而漏检。 */
                carry = s.takeLast(32)
            }
            lateLoad && kernelSu
        }
    }.getOrDefault(false)

    /**
     * 【主路径】PackageManager 扫描已装应用找 ksud（v1.0.9 起）。
     *
     * 认「内容」不认「文件名/包名」——自编译 fork 包名不可预知，混淆 fork
     * （SukiSU Ultra 等）还会把 ksud 随机改名，故既不能只按包名、也不能只按
     * libksud.so 文件名找。
     *
     * 顺序：
     *  1. 已知家族包名逐个查（nativeLibraryDir 直读，最快最准）；
     *  2. 全量扫描 getInstalledPackages，找 nativeLibraryDir 内含 ksud 的应用
     *     （需 QUERY_ALL_PACKAGES，manifest 已声明；shell uid 下 PM 调用亦可用）。
     *
     * 返回 (ksud 文件, 来源包名)；找不到返回 null。
     */
    fun scanManagerLib(
        pm: android.content.pm.PackageManager,
    ): Pair<java.io.File, String>? = scanManagerLibs(pm).firstOrNull()

    /**
     * 已知家族包名（供 UI 展示与优先排序）。
     */
    val managerPackages: List<String> get() = MANAGER_PACKAGES

    /**
     * 【枚举全部】扫描设备上所有携带 ksud 的管理器（v2.2.0 多管理器选择）。
     *
     * 与 [scanManagerLib] 同源，但**不命中即返回**——真机上可能同时装了
     * KernelSU 与 SukiSU 两个管理器，只取第一个就无法让用户挑选要接管哪一个
     * （接管需加载与管理器同源的 ksud，见 [KsuResolver]）。返回顺序：
     *  1. 已知家族包名（按 [MANAGER_PACKAGES] 优先级）；
     *  2. 其余 getInstalledPackages 全量扫描命中；
     * 按包名去重。
     */
    fun scanManagerLibs(
        pm: android.content.pm.PackageManager,
    ): List<Pair<java.io.File, String>> {
        val out = ArrayList<Pair<java.io.File, String>>()
        val seen = HashSet<String>()
        for (pkg in MANAGER_PACKAGES) {
            val lib = findKsudForPackage(pm, pkg) ?: continue
            if (seen.add(pkg)) out.add(lib to pkg)
        }
        val infos = runCatching { pm.getInstalledPackages(0) }.getOrDefault(emptyList())
        for (info in infos) {
            val pkg = info.packageName
            if (pkg in seen) continue
            val dirS = info.applicationInfo?.nativeLibraryDir ?: continue
            val lib = findKsudInDir(java.io.File(dirS)) ?: continue
            if (seen.add(pkg)) out.add(lib to pkg)
        }
        return out
    }

    /** 指定包名的管理器 APK 里定位 ksud；未安装/未命中返回 null。 */
    fun scanManagerLibFor(
        pm: android.content.pm.PackageManager,
        pkg: String,
    ): Pair<java.io.File, String>? {
        val lib = findKsudForPackage(pm, pkg) ?: return null
        return lib to pkg
    }

    /** 在某个包名的 nativeLibraryDir 下找 ksud。 */
    private fun findKsudForPackage(
        pm: android.content.pm.PackageManager,
        pkg: String,
    ): java.io.File? {
        val dir = runCatching {
            java.io.File(pm.getApplicationInfo(pkg, 0).nativeLibraryDir)
        }.getOrNull() ?: return null
        return findKsudInDir(dir)
    }

    /**
     * 【回退路径】shell 脚本提取（包名列表循环 + lib 目录直拷 + unzip 兜底）。
     *
     * 流程：
     *  1. 逐个候选包名 `pm path` 找已装管理器 APK；
     *  2. 优先直接拷 `<apk目录>/lib/arm64/libksud.so`（已解压的 native lib，最快）；
     *  3. 常规名不存在时（混淆 fork，如 SukiSU Ultra 随机改名），扫 lib/arm64 目录下的 .so
     *     按内容签名挑出 ksud；
     *  4. 回退 `unzip -p <apk> lib/arm64-v8a/libksud.so`（部分 ROM 未解压时）；
     *  5. chmod 755 后回报 `KSUD_STAGE_OK md5=.. size=..`，失败回报
     *     `KSUD_STAGE_FAIL <reason>`，两标记供宿主解析（改名需同步 parser）。
     */
    val SCRIPT: String = """
        T=/data/local/tmp/ksud
        APK=""
        for PKG in ${MANAGER_PACKAGES.joinToString(" ")}; do
          APK="${'$'}(pm path "${'$'}PKG" 2>/dev/null | head -1 | sed 's/^package://')"
          if [ -n "${'$'}APK" ]; then break; fi
        done
        if [ -z "${'$'}APK" ]; then echo "KSUD_STAGE_FAIL manager_not_installed"; exit 0; fi
        LIB="${'$'}(dirname "${'$'}APK")/lib/arm64/libksud.so"
        if [ -r "${'$'}LIB" ]; then cp -f "${'$'}LIB" "${'$'}T" 2>/dev/null; fi
        if [ ! -s "${'$'}T" ]; then
          for L in "${'$'}(dirname "${'$'}APK")/lib/arm64"/*.so; do
            [ -r "${'$'}L" ] || continue
            if grep -q late-load "${'$'}L" 2>/dev/null && grep -q -i kernelsu "${'$'}L" 2>/dev/null; then
              cp -f "${'$'}L" "${'$'}T" 2>/dev/null; break
            fi
          done
        fi
        if [ ! -s "${'$'}T" ]; then
          if command -v unzip >/dev/null 2>&1; then
            unzip -p "${'$'}APK" lib/arm64-v8a/libksud.so > "${'$'}T" 2>/dev/null
          fi
        fi
        if [ ! -s "${'$'}T" ]; then echo "KSUD_STAGE_FAIL no_source apk=${'$'}APK"; exit 0; fi
        chmod 755 "${'$'}T" 2>/dev/null
        MD5="${'$'}(md5sum "${'$'}T" 2>/dev/null | awk '{print ${'$'}1}')"
        echo "KSUD_STAGE_OK md5=${'$'}MD5 size=${'$'}(wc -c < "${'$'}T" 2>/dev/null)"
    """.trimIndent()

    /** 脚本输出解析结果。 */
    sealed interface Outcome {
        /** 提取成功：md5 与字节数（可能为空串/0，取不到时不阻塞主链路）。 */
        data class Ok(val md5: String, val size: Long) : Outcome

        /** 提取失败：原因标记（manager_not_installed / no_source / 无输出=执行异常）。 */
        data class Fail(val reason: String) : Outcome
    }

    /** 解析脚本 stdout（纯函数，便于单测）。取最后一个 OK/FAIL 标记行。 */
    fun parse(output: String): Outcome {
        var result: Outcome = Outcome.Fail("no_output")
        for (line in output.lines()) {
            val t = line.trim()
            when {
                t.startsWith("KSUD_STAGE_OK") -> {
                    val md5 = Regex("md5=([0-9a-fA-F]*)").find(t)?.groupValues?.get(1).orEmpty()
                    val size = Regex("size=(\\d+)").find(t)?.groupValues?.get(1)?.toLongOrNull() ?: 0L
                    result = Outcome.Ok(md5, size)
                }
                t.startsWith("KSUD_STAGE_FAIL") -> {
                    val reason = t.removePrefix("KSUD_STAGE_FAIL").trim().ifBlank { "unknown" }
                    result = Outcome.Fail(reason)
                }
            }
        }
        return result
    }
}
