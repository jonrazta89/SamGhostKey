package com.EternalTimes.GhostKey.ksu

import android.content.Context

/** KSU 来源（v1.0.9：检测与实际执行共用同一套「认文件不认包名」机制）。 */
sealed class KsuSource {
    /** 设备上安装了可用的 Root 管理器（含自编译 fork）。 */
    data class DeviceManager(val packageName: String, val versionName: String?) : KsuSource()

    /** 回退到 APK 内置的 ksud。 */
    data class Bundled(val note: String = "内置 ksud") : KsuSource()

    /** 均不可用。 */
    data class Unavailable(val reason: String) : KsuSource()
}

/**
 * KSU 管理器解析器（Kotlin 层，best-effort）。
 *
 * v1.0.9 起与 [KsudStage] 对齐：扫描设备上已安装的管理器时**认 ksud 内容签名**
 * （ELF + late-load/kernelsu），既兼容常规名 libksud.so，也覆盖混淆 fork（如
 * SukiSU Ultra）的**随机改名**；不认包名——自编译 fork 包名不可预知，逐包名
 * 探测会漏（1.0.8 真机教训）。
 *
 * 该检测结果同时就是执行路径：提权时优先把命中的管理器 libksud.so 提取为
 * ksud（经 CVE98260_KSUD 环境变量传给原生 find_ksud，第一优先候选），
 * 未检测到才回落 APK 内置 ksud——全程不改原生 C。
 *
 * 注意：Android 11+ 包可见性依赖 manifest 的 QUERY_ALL_PACKAGES（已声明）；
 * <queries> 中保留的已知包名仅作快速通道补充。
 */
class KsuResolver(private val context: Context) {

    /** 扫描结果缓存（时间戳）。同一批候选不重复全量扫包。 */
    private var cached: List<KsuSource.DeviceManager>? = null
    private var cachedAt = 0L

    /**
     * 扫描设备上所有携带 ksud 的管理器（**只扫一次**，检测与选择共用）。
     *
     * [force] = true 时忽略缓存（设置页的「重新检测」按钮）。
     *
     * 为什么要缓存：全量扫包要枚举已装应用、逐个看 nativeLibraryDir、再按内容
     * 签名验证候选 .so —— 在真机上是几百毫秒到几秒的 IO。原来 ViewModel 一次
     * 启动里会做**两轮**（detect + detectAll），而且在主线程上做。
     */
    @Synchronized
    fun scan(force: Boolean = false): List<KsuSource.DeviceManager> {
        val now = System.currentTimeMillis()
        val hit = cached
        if (!force && hit != null && now - cachedAt < CACHE_TTL_MS) return hit
        val pm = context.packageManager
        val out = KsudStage.scanManagerLibs(pm).mapNotNull { (file, pkg) ->
            if (!file.isFile || file.length() <= 0L) return@mapNotNull null
            val version = runCatching { pm.getPackageInfo(pkg, 0).versionName }.getOrNull()
            KsuSource.DeviceManager(pkg, version)
        }
        /*
         * 空结果**不写缓存**。
         *
         * 之前无论扫没扫到都写缓存，于是「一次扫空」会把「未检测到」钉死 5 分钟
         * （CACHE_TTL_MS）：用户刚装好管理器就点「重新检测」，界面仍然是
         * 「未检测到」，除非等满 5 分钟或重启 APP —— 看上去就是「检测不到管理器」。
         *
         * 空结果本来就说明「此刻设备上还没有带 ksud 的管理器」，不是稳定结论，
         * 缓存它没有意义；下一次调用重新扫即可（扫包只在 IO 线程发生）。
         */
        if (out.isNotEmpty()) {
            cached = out
            cachedAt = now
        } else {
            cached = null
            cachedAt = 0L
        }
        return out
    }

    /**
     * 从扫描结果里选出接管用的管理器。
     *
     * [selected] 为空或不在候选里 → 取优先级首个（[scan] 的返回顺序即优先级）。
     */
    fun pick(candidates: List<KsuSource.DeviceManager>, selected: String?): KsuSource {
        if (candidates.isEmpty()) return KsuSource.Bundled()
        val chosen = selected
            ?.takeIf { s -> candidates.any { it.packageName == s } }
            ?.let { pkg -> candidates.first { it.packageName == pkg } }
            ?: candidates.first()
        return chosen
    }

    fun detect(): KsuSource = pick(scan(), null)

    /**
     * 枚举设备上所有携带 ksud 的管理器（v2.2.0 多管理器选择）。
     *
     * 供 UI 在检出多个管理器时列出候选让用户挑选；接管与 [detect] 一致，
     * 认内容签名不认包名。无命中时返回空列表（= 只有内置 ksud 可用）。
     */
    fun detectAll(): List<KsuSource.DeviceManager> = scan()

    /**
     * 按用户选定包名解析来源；[selected] 为空或该包名无 ksud 时，回落到 [detect]。
     */
    fun detect(selected: String?): KsuSource = pick(scan(), selected)

    fun label(source: KsuSource): String = when (source) {
        is KsuSource.DeviceManager ->
            "设备管理器 ${source.packageName}" + (source.versionName?.let { " v$it" } ?: "")
        is KsuSource.Bundled -> source.note
        is KsuSource.Unavailable -> "不可用：${source.reason}"
    }

    private companion object {
        /** 扫描结果缓存时长（毫秒）。设置页的「重新检测」走强制刷新。 */
        const val CACHE_TTL_MS = 5 * 60 * 1000L
    }
}
