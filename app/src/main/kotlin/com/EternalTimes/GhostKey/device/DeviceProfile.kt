package com.EternalTimes.GhostKey.device

import com.EternalTimes.GhostKey.data.HoconSupport
import com.EternalTimes.GhostKey.data.coerceLong

/**
 * 机型配置（device profile）—— **加速层**，不是准入闸门。
 *
 * 与内核 profile（`kernel_profiles/` 目录下的 `.conf`，按 `uname -r` 精确匹配）
 * 是**正交**的两件事：
 *  - 内核 profile 决定**正确性**：符号偏移、结构体尺寸、锚点；
 *  - 机型 profile 决定**快慢**：同一台机器上每次都不变的编译期常量、
 *    以及这台机器特有的坑。
 *
 * 为什么要有这一层：漏洞能否跑通取决于**内核参数**，与商用机型无关
 * （见 [DeviceBinding] 的注释：「机型锁会误伤同 SoC 同 KMI 的设备」），
 * 所以机型**绝不能**成为放行条件。但反过来，有几个量是**编译期常量**——
 * 线性映射基址 PAGE_OFFSET、内核线程栈大小——每次启动都重新扫一遍纯属浪费，
 * 记进机型配置就能直接省掉（真机实测 calibrate-b 占 9 秒 / 全程 39 秒）。
 *
 * 明确**不**放进机型配置的量：**KASLR slide**。它每次启动都变，必须运行时解，
 * 写死会直接让注入失败。
 *
 * 文件命名与回落：
 *  - **专属**：`assets/device_profiles/<product>-<device>.conf`（如 `creek-creek.conf`），
 *    只写这一台机器特有的项；
 *  - **通用**：`assets/device_profiles/<product>.conf`（如 `creek.conf`），家族共用项。
 *
 * 回落是**字段级**的：专属配置里没写的字段自动继承通用配置；专属写了就以专属为准
 * （连 `page_offset_trusted = 0` 这种"显式否定"也算数，不会被通用配置里的 1 覆盖）。
 * 两份都没有 → 无机型配置，退回运行时全量扫描（老行为，宁慢不错）。
 */
data class DeviceProfile(
    /** 配置 id（文件名去掉 `.conf`）。 */
    val id: String,
    val product: String,
    val device: String,
    val model: String? = null,
    val soc: String? = null,
    /** 运行时页大小（字节）。4K/16K/64K 的 PAGE_OFFSET 不同，必须对上。 */
    val pageSize: Int? = null,
    /** 线性映射基址（PAGE_OFFSET）。 */
    val pageOffset: Long? = null,
    /**
     * page_offset 是否经过人工确认、可直接使用（可信才允许跳过 calibrate-b）。
     *
     * `null` = 该文件**没写**这一项（字段级回落时继承通用配置的值）；
     * `false` = 显式写了 0 / false（**否定**通用配置里的 1，不能被继承覆盖）。
     */
    val pageOffsetTrusted: Boolean? = null,
    /** task_struct 的 slab object_size 实测值（含内嵌内核栈）。 */
    val taskStructObjectSize: Long? = null,
    /** calibrate-a 的探针次数 / 保持秒数（覆盖原生体默认值）。 */
    val calibAProbe: Int? = null,
    val calibAHold: Int? = null,
    val notes: String? = null,
    /** 合成来源：通用配置 id 在前、专属配置 id 在后（只有一份时就是它自己）。 */
    val mergedFrom: List<String> = emptyList(),
    /** 最终值来自通用配置的字段名（专属没写 → 继承）。 */
    val inheritedFields: List<String> = emptyList(),
) {
    companion object {
        /**
         * 解析一份机型配置文本。
         * `product` / `device` 缺失或为空 → 返回 null（视为无效配置）。
         */
        fun parse(
            id: String,
            text: String,
            allowMissingDevice: Boolean = false,
        ): DeviceProfile? {
            val root = runCatching { HoconSupport.parseObject(text) }.getOrNull() ?: return null
            val product = root["product"]?.toString()?.trim().orEmpty()
            val device = root["device"]?.toString()?.trim().orEmpty()
            if (product.isEmpty()) return null
            // 专属配置必须写明 device；通用配置（<product>.conf）覆盖整个家族，可不写。
            if (device.isEmpty() && !allowMissingDevice) return null
            return DeviceProfile(
                id = id,
                product = product,
                device = device,
                model = root["model"]?.toString()?.trim()?.takeIf { it.isNotEmpty() },
                soc = root["soc"]?.toString()?.trim()?.takeIf { it.isNotEmpty() },
                pageSize = coerceLong(root["page_size"])?.toInt(),
                pageOffset = coerceLong(root["page_offset"]),
                pageOffsetTrusted = root["page_offset_trusted"]?.let { truthy(it) },
                taskStructObjectSize = coerceLong(root["task_struct_object_size"]),
                calibAProbe = coerceLong(nested(root, "flow", "calib_a", "probe"))?.toInt(),
                calibAHold = coerceLong(nested(root, "flow", "calib_a", "hold"))?.toInt(),
                notes = root["_notes"]?.toString()?.trim()?.takeIf { it.isNotEmpty() },
            )
        }

        private fun nested(root: Map<String, Any?>, vararg path: String): Any? {
            var cur: Any? = root
            for (p in path) {
                cur = (cur as? Map<*, *>)?.get(p) ?: return null
            }
            return cur
        }

        private fun truthy(v: Any?): Boolean = when (v) {
            null -> false
            is Boolean -> v
            is Number -> v.toLong() != 0L
            is String -> v.trim().lowercase() !in setOf("", "0", "false", "no", "off")
            else -> false
        }

        /**
         * 字段级回落：把**通用**配置（家族级）与**专属**配置（机型级）合成一份。
         *
         * 规则：
         *  - 专属写了 → 用专属的值（连 `page_offset_trusted = 0` 这种显式否定也算）；
         *  - 专属没写 → 继承通用的值，并把字段名记进 [DeviceProfile.inheritedFields]；
         *  - 通用也没有 → 留 null。
         *
         * 只有一份时原样返回（mergedFrom 记自己）；两份都没有返回 null。
         */
        fun merge(generic: DeviceProfile?, specific: DeviceProfile?): DeviceProfile? {
            if (generic == null && specific == null) return null
            if (generic == null) return specific!!.copy(mergedFrom = listOf(specific.id))
            if (specific == null) return generic.copy(mergedFrom = listOf(generic.id))

            val inherited = ArrayList<String>()
            fun <T : Any> pick(name: String, genericValue: T?, specificValue: T?): T? {
                if (specificValue != null) return specificValue
                if (genericValue != null) inherited.add(name)
                return genericValue
            }
            return DeviceProfile(
                id = specific.id,
                product = specific.product,
                device = specific.device.ifEmpty { generic.device },
                model = pick("model", generic.model, specific.model),
                soc = pick("soc", generic.soc, specific.soc),
                pageSize = pick("page_size", generic.pageSize, specific.pageSize),
                pageOffset = pick("page_offset", generic.pageOffset, specific.pageOffset),
                pageOffsetTrusted = pick(
                    "page_offset_trusted",
                    generic.pageOffsetTrusted,
                    specific.pageOffsetTrusted,
                ),
                taskStructObjectSize = pick(
                    "task_struct_object_size",
                    generic.taskStructObjectSize,
                    specific.taskStructObjectSize,
                ),
                calibAProbe = pick("flow.calib_a.probe", generic.calibAProbe, specific.calibAProbe),
                calibAHold = pick("flow.calib_a.hold", generic.calibAHold, specific.calibAHold),
                notes = specific.notes ?: generic.notes,
                mergedFrom = listOf(generic.id, specific.id),
                inheritedFields = inherited,
            )
        }
    }
}

/**
 * page_offset 的取值决策（纯函数，便于宿主单测）。
 *
 * @param value   最终使用的 page_offset（未签名字节序，转成 hex 字符串给原生体）
 * @param trusted 是否**可以跳过 calibrate-b**
 * @param reason  决策理由（直接进日志，便于事后复盘）
 */
data class PageOffsetPlan(
    val value: Long?,
    val trusted: Boolean,
    val reason: String,
)

/**
 * 机型配置的使用策略（纯函数，便于宿主单测）。
 */
object DeviceProfilePolicy {

    /**
     * 这份配置是否确实属于本机。
     *
     * 套错机型的 page_offset 是「注入成功但偏移全错」的隐性故障 —— 与其事后
     * 复盘，不如在这里直接拒掉。通用配置（家族级，`<product>.conf`）可以不写
     * device；写了就必须与本机一致。
     */
    fun belongsTo(profile: DeviceProfile, product: String, device: String): Boolean {
        if (profile.product != product) return false
        if (profile.device.isEmpty()) return true
        return profile.device == device
    }

    /**
     * 决定 page_offset 怎么来。
     *
     * `trusted = true` 时宿主可以**跳过 calibrate-b**（真机实测省 ~9 秒）。
     * 三个前提缺一不可：
     *  1. 机型配置里有 `page_offset`；
     *  2. 显式标记 `page_offset_trusted = 1`（人工确认过的值）；
     *  3. 页大小与运行时一致 —— 4K / 16K / 64K 的 PAGE_OFFSET 不同，
     *     拿错页大小就是「注入成功但偏移全错」的隐性故障。
     *
     * 任何一条不满足 → 退回运行时 calibrate-b 扫描（老行为）。
     */
    fun planPageOffset(profile: DeviceProfile?, runtimePageSize: Int?): PageOffsetPlan {
        if (profile == null) return PageOffsetPlan(null, false, "no device profile")
        val po = profile.pageOffset
            ?: return PageOffsetPlan(null, false, "device profile has no page_offset")
        if (profile.pageOffsetTrusted != true) {
            return PageOffsetPlan(
                po,
                false,
                if (profile.pageOffsetTrusted == null) {
                    "device profile page_offset is not marked trusted (flag absent)"
                } else {
                    "device profile page_offset is explicitly marked untrusted"
                },
            )
        }
        val ps = profile.pageSize
        if (ps != null && runtimePageSize != null && ps != runtimePageSize) {
            return PageOffsetPlan(
                po,
                false,
                "page size mismatch (profile=$ps runtime=$runtimePageSize)",
            )
        }
        return PageOffsetPlan(po, true, "trusted by device profile ${profile.id}")
    }

    /**
     * 统一格式化成 `0x<hex>`（无符号语义，与原生体 `strtoull(..., 0)` 一致）。
     */
    fun formatHexU(value: Long): String =
        "0x" + java.lang.Long.toUnsignedString(value, 16)
}
