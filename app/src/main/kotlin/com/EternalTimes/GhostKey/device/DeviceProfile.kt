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
 * 文件命名：`assets/device_profiles/<product>-<device>.conf`，
 * 例如 `madrid-madrid.conf`；找不到时回退 `<product>.conf`。
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
    /** page_offset 是否经过人工确认、可直接使用（可信才允许跳过 calibrate-b）。 */
    val pageOffsetTrusted: Boolean = false,
    /** task_struct 的 slab object_size 实测值（含内嵌内核栈）。 */
    val taskStructObjectSize: Long? = null,
    /** calibrate-a 的探针次数 / 保持秒数（覆盖原生体默认值）。 */
    val calibAProbe: Int? = null,
    val calibAHold: Int? = null,
    val notes: String? = null,
) {
    companion object {
        /**
         * 解析一份机型配置文本。
         * `product` / `device` 缺失或为空 → 返回 null（视为无效配置）。
         */
        fun parse(id: String, text: String): DeviceProfile? {
            val root = runCatching { HoconSupport.parseObject(text) }.getOrNull() ?: return null
            val product = root["product"]?.toString()?.trim().orEmpty()
            val device = root["device"]?.toString()?.trim().orEmpty()
            if (product.isEmpty() || device.isEmpty()) return null
            return DeviceProfile(
                id = id,
                product = product,
                device = device,
                model = root["model"]?.toString()?.trim()?.takeIf { it.isNotEmpty() },
                soc = root["soc"]?.toString()?.trim()?.takeIf { it.isNotEmpty() },
                pageSize = coerceLong(root["page_size"])?.toInt(),
                pageOffset = coerceLong(root["page_offset"]),
                pageOffsetTrusted = truthy(root["page_offset_trusted"]),
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
        if (!profile.pageOffsetTrusted) {
            return PageOffsetPlan(po, false, "device profile page_offset is not marked trusted")
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
