package com.EternalTimes.GhostKey.ksu

import android.content.Context

/** KSU 来源（v1.0.9：检测与实际执行共用同一套「认文件不认包名」机制）。 */
sealed class KsuSource {
    /** 设备上安装了可用的 Root 管理器（含自编译 fork）。 */
    data class DeviceManager(val packageName: String, val versionName: String?) : KsuSource()

    /** 回退到 APK 内置的 ksud。 */
    data class Bundled(val note: String = "Bundled ksud") : KsuSource()

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
 *
 * **两条通道**（2.2.0-alpha08 起）：
 *  - 应用侧（[scan]）：只查 PackageManager 的包存在性。ksud 在别的应用的
 *    nativeLibraryDir 里，App 进程（untrusted_app）读它会被 SELinux 拒绝，
 *    所以内容签名扫描在 App 进程里恒为空 —— 界面永远「未检测到管理器」。
 *    包存在性不依赖 Shizuku，毫秒级可用。
 *  - 服务侧（[mergeServiceScan]）：UserService 跑在 shell（uid 2000），读得到
 *    别的应用的 ksud，由它做权威的内容签名扫描（含随机改名的混淆 fork）。
 */
class KsuResolver(private val context: Context) {

    /** 应用侧结果（包存在性）：上次刷新的时间戳。 */
    private var installedAt = 0L

    /** 应用侧结果（包存在性）。 */
    private var installed: List<KsuSource.DeviceManager> = emptyList()

    /** 服务侧结果（shell uid 的内容签名扫描），权威。 */
    private var service: List<KsuSource.DeviceManager> = emptyList()

    /**
     * 扫描设备上已安装的 Root 管理器（**应用侧通道**：包存在性）。
     *
     * [force] = true 时忽略缓存（设置页的「重新检测」按钮）。
     *
     * 为什么应用侧只看包存在性：ksud 在**别的应用**的 nativeLibraryDir 里，
     * 那是别的应用的 `apk_data_file`，App 进程（untrusted_app）读它会被
     * SELinux 拒绝 —— 内容签名扫描在 App 进程里恒为空，真机表现就是界面一直
     * 「未检测到管理器」。包存在性只查 PackageManager 元数据，App 进程有权限，
     * 而且不依赖 Shizuku。
     *
     * 要「确实带 ksud」的权威结论，用 [mergeServiceScan] 合入服务侧结果。
     */
    @Synchronized
    fun scan(force: Boolean = false): List<KsuSource.DeviceManager> {
        val now = System.currentTimeMillis()
        if (force || installedAt == 0L || now - installedAt >= CACHE_TTL_MS) {
            val pm = context.packageManager
            installed = KsudStage.scanInstalledManagers(pm).map { toSource(it) }
            installedAt = now
        }
        return merged()
    }

    /**
     * 合入服务侧（shell uid）扫出来的管理器列表，并返回合并后的候选。
     *
     * 服务侧结果**覆盖**同名包的应用侧结果（它的版本号更准），但不会把应用侧
     * 已知的包名抹掉 —— 万一服务侧这次没扫到（比如 Shizuku 刚启动还没连上），
     * 界面也不至于从「有」变回「无」。
     */
    @Synchronized
    fun mergeServiceScan(entries: List<KsudStage.ManagerEntry>): List<KsuSource.DeviceManager> {
        if (entries.isEmpty()) return merged()
        service = entries.map { toSource(it) }
        return merged()
    }

    /** 服务侧结果（最近一次），供 UI 展示「已验证带 ksud」的来源。 */
    @Synchronized
    fun serviceVerified(): Set<String> = service.map { it.packageName }.toSet()

    /** 合并两条通道：服务侧优先，同名只保留一条。 */
    private fun merged(): List<KsuSource.DeviceManager> {
        val out = ArrayList<KsuSource.DeviceManager>(service.size + installed.size)
        val seen = HashSet<String>()
        for (m in service) {
            if (seen.add(m.packageName)) out.add(m)
        }
        for (m in installed) {
            if (seen.add(m.packageName)) out.add(m)
        }
        return out
    }

    private fun toSource(entry: KsudStage.ManagerEntry) =
        KsuSource.DeviceManager(entry.packageName, entry.versionName)

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
            "Device manager ${source.packageName}" + (source.versionName?.let { " v$it" } ?: "")
        is KsuSource.Bundled -> source.note
        is KsuSource.Unavailable -> "Unavailable: ${source.reason}"
    }

    private companion object {
        /** 扫描结果缓存时长（毫秒）。设置页的「重新检测」走强制刷新。 */
        const val CACHE_TTL_MS = 5 * 60 * 1000L
    }
}
