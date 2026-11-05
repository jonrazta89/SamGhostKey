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

    fun detect(): KsuSource {
        val pm = context.packageManager
        val lib = KsudStage.scanManagerLib(pm) ?: return KsuSource.Bundled()
        val (file, pkg) = lib
        val version = runCatching {
            pm.getPackageInfo(pkg, 0).versionName
        }.getOrNull()
        if (!file.isFile || file.length() <= 0L) return KsuSource.Bundled()
        return KsuSource.DeviceManager(pkg, version)
    }

    /**
     * 枚举设备上所有携带 ksud 的管理器（v2.2.0 多管理器选择）。
     *
     * 供 UI 在检出多个管理器时列出候选让用户挑选；接管与 [detect] 一致，
     * 认内容签名不认包名。无命中时返回空列表（= 只有内置 ksud 可用）。
     */
    fun detectAll(): List<KsuSource.DeviceManager> {
        val pm = context.packageManager
        return KsudStage.scanManagerLibs(pm).mapNotNull { (file, pkg) ->
            if (!file.isFile || file.length() <= 0L) return@mapNotNull null
            val version = runCatching { pm.getPackageInfo(pkg, 0).versionName }.getOrNull()
            KsuSource.DeviceManager(pkg, version)
        }
    }

    /**
     * 按用户选定包名解析来源；[selected] 为空或该包名无 ksud 时，回落到 [detect]。
     */
    fun detect(selected: String?): KsuSource {
        if (selected.isNullOrBlank()) return detect()
        val pm = context.packageManager
        val lib = KsudStage.scanManagerLibFor(pm, selected) ?: return detect()
        val (file, pkg) = lib
        if (!file.isFile || file.length() <= 0L) return KsuSource.Bundled()
        val version = runCatching { pm.getPackageInfo(pkg, 0).versionName }.getOrNull()
        return KsuSource.DeviceManager(pkg, version)
    }

    fun label(source: KsuSource): String = when (source) {
        is KsuSource.DeviceManager ->
            "设备管理器 ${source.packageName}" + (source.versionName?.let { " v$it" } ?: "")
        is KsuSource.Bundled -> source.note
        is KsuSource.Unavailable -> "不可用：${source.reason}"
    }
}
