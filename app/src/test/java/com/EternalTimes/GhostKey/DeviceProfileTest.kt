package com.EternalTimes.GhostKey.device

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 机型配置（device profile）的解析、回落合并与决策单测。
 *
 * 这里锁死四件事：
 *  1. HOCON 解析（无符号 64 位 hex 的 page_offset、嵌套 flow 块）；
 *  2. page_offset 的「可信 → 允许跳过 calibrate-b」判定，含**页大小校验**
 *     （4K/16K/64K 的 PAGE_OFFSET 不同，页大小对不上就是隐性故障）；
 *  3. 任何前提不满足时都退回运行时扫描（宁慢不错）；
 *  4. **专属 + 通用**两级回落的字段级合并语义。
 */
class DeviceProfileTest {

    private val MADRID = """
        {
          product = "madrid"
          device = "madrid"
          model = "Xiaomi M154FF"
          soc = "SM8975"
          page_size = 4096
          page_offset = 0xffffff8000000000
          page_offset_trusted = 1
          task_struct_object_size = 5760
          flow = {
            calib_a = {
              probe = 2048
              hold = 2
            }
          }
          _notes = "unit test fixture"
        }
    """.trimIndent()

    // ---------------------------------------------------------------- 解析

    @Test
    fun parsesAllFields() {
        val p = DeviceProfile.parse("madrid-madrid", MADRID)
        assertNotNull(p)
        requireNotNull(p)
        assertEquals("madrid-madrid", p.id)
        assertEquals("madrid", p.product)
        assertEquals("madrid", p.device)
        assertEquals("Xiaomi M154FF", p.model)
        assertEquals("SM8975", p.soc)
        assertEquals(4096, p.pageSize)
        assertEquals(5760L, p.taskStructObjectSize)
        assertEquals(2048, p.calibAProbe)
        assertEquals(2, p.calibAHold)
        assertEquals(true, p.pageOffsetTrusted)
    }

    @Test
    fun parsesUnsignedHexPageOffset() {
        val p = DeviceProfile.parse("madrid-madrid", MADRID)
        requireNotNull(p)
        // 0xffffff8000000000 是负的 signed Long，原生体那边按 uint64 用
        assertEquals(-549755813888L, p.pageOffset)
        assertEquals("0xffffff8000000000", DeviceProfilePolicy.formatHexU(p.pageOffset!!))
    }

    @Test
    fun rejectsProfileWithoutProductOrDevice() {
        assertNull(DeviceProfile.parse("x", """{ device = "madrid" }"""))
        assertNull(DeviceProfile.parse("x", """{ product = "madrid" }"""))
        assertNull(DeviceProfile.parse("x", """{ product = "", device = "madrid" }"""))
    }

    @Test
    fun missingOptionalFieldsAreNull() {
        val p = DeviceProfile.parse("bare", """{ product = "a", device = "b" }""")
        requireNotNull(p)
        assertNull(p.pageOffset)
        assertNull(p.pageSize)
        assertNull(p.taskStructObjectSize)
        assertNull(p.calibAProbe)
        // 没写 = 未设置（字段级回落时继承通用配置的值），而不是「显式否认可信」
        assertNull(p.pageOffsetTrusted)
    }

    @Test
    fun untrustedFlagAcceptsZeroAndFalse() {
        val p = DeviceProfile.parse(
            "x",
            """{ product = "a", device = "b", page_offset = 0x1000, page_offset_trusted = 0 }""",
        )
        requireNotNull(p)
        assertEquals(false, p.pageOffsetTrusted)
    }

    // ---------------------------------------------------------------- 决策

    @Test
    fun noProfileMeansNoTrust() {
        val plan = DeviceProfilePolicy.planPageOffset(null, 4096)
        assertFalse(plan.trusted)
        assertNull(plan.value)
    }

    @Test
    fun trustedProfileWithMatchingPageSizeIsTrusted() {
        val p = DeviceProfile.parse("madrid-madrid", MADRID)
        val plan = DeviceProfilePolicy.planPageOffset(p, 4096)
        assertTrue(plan.trusted)
        assertEquals(-549755813888L, plan.value)
    }

    @Test
    fun pageSizeMismatchBlocksTrust() {
        val p = DeviceProfile.parse("madrid-madrid", MADRID)
        val plan = DeviceProfilePolicy.planPageOffset(p, 16384)
        assertFalse(plan.trusted)
        assertTrue(plan.reason.contains("page size mismatch"))
    }

    @Test
    fun unknownRuntimePageSizeStillTrusts() {
        val p = DeviceProfile.parse("madrid-madrid", MADRID)
        val plan = DeviceProfilePolicy.planPageOffset(p, null)
        assertTrue(plan.trusted)
    }

    @Test
    fun untrustedFlagBlocksSkipEvenWithValue() {
        val p = DeviceProfile.parse(
            "x",
            """{ product = "a", device = "b", page_offset = 0xffffff8000000000 }""",
        )
        val plan = DeviceProfilePolicy.planPageOffset(p, 4096)
        assertFalse(plan.trusted)
        assertEquals(-549755813888L, plan.value)
    }

    @Test
    fun profileWithoutPageOffsetIsNeverTrusted() {
        val p = DeviceProfile.parse("x", """{ product = "a", device = "b", page_offset_trusted = 1 }""")
        val plan = DeviceProfilePolicy.planPageOffset(p, 4096)
        assertFalse(plan.trusted)
        assertNull(plan.value)
    }

    @Test
    fun formatHexUIsUnsigned() {
        assertEquals("0xffffff8000000000", DeviceProfilePolicy.formatHexU(-549755813888L))
        assertEquals("0x0", DeviceProfilePolicy.formatHexU(0L))
        assertEquals("0xff", DeviceProfilePolicy.formatHexU(255L))
    }

    // ---------------------------------------------------------------- 回落合并

    /** 家族通用层：`<product>.conf`，可以不写 device。 */
    private val GENERIC = """
        {
          product = "creek"
          page_size = 4096
          page_offset = 0xffffff8000000000
          page_offset_trusted = 1
          task_struct_object_size = 5760
          flow = {
            calib_a = {
              probe = 2048
              hold = 2
            }
          }
          _notes = "generic layer"
        }
    """.trimIndent()

    /** 机型专属层：`<product>-<device>.conf`，只写本机型特有的项。 */
    private val SPECIFIC = """
        {
          product = "creek"
          device = "creek"
          model = "POCO M7"
        }
    """.trimIndent()

    @Test
    fun genericProfileMayOmitDevice() {
        val p = DeviceProfile.parse("creek", GENERIC, allowMissingDevice = true)
        requireNotNull(p)
        assertEquals("creek", p.id)
        assertEquals("creek", p.product)
        assertEquals("", p.device)
        assertEquals(4096, p.pageSize)
        assertEquals(true, p.pageOffsetTrusted)
    }

    @Test
    fun genericProfileWithoutDeviceIsRejectedByDefault() {
        // 默认（专属配置语义）下缺 device = 无效配置
        assertNull(DeviceProfile.parse("creek", GENERIC))
    }

    @Test
    fun specificInheritsMissingFieldsFromGeneric() {
        val g = DeviceProfile.parse("creek", GENERIC, allowMissingDevice = true)
        val s = DeviceProfile.parse("creek-creek", SPECIFIC)
        val merged = DeviceProfile.merge(g, s)
        requireNotNull(merged)
        assertEquals("creek-creek", merged.id)
        assertEquals("POCO M7", merged.model)
        // 专属没写的字段全部继承通用
        assertEquals(4096, merged.pageSize)
        assertEquals(-549755813888L, merged.pageOffset)
        assertEquals(true, merged.pageOffsetTrusted)
        assertEquals(5760L, merged.taskStructObjectSize)
        assertEquals(2048, merged.calibAProbe)
        assertEquals(2, merged.calibAHold)
        assertEquals(listOf("creek", "creek-creek"), merged.mergedFrom)
        assertTrue(merged.inheritedFields.contains("page_size"))
        assertTrue(merged.inheritedFields.contains("page_offset_trusted"))
    }

    @Test
    fun specificOverridesGenericField() {
        val g = DeviceProfile.parse("creek", GENERIC, allowMissingDevice = true)
        val s = DeviceProfile.parse(
            "creek-creek",
            """{ product = "creek", device = "creek", page_size = 16384 }""",
        )
        val merged = DeviceProfile.merge(g, s)
        requireNotNull(merged)
        assertEquals(16384, merged.pageSize)
        // 未被覆盖的字段仍然继承通用
        assertEquals(-549755813888L, merged.pageOffset)
    }

    @Test
    fun explicitUntrustedInSpecificBeatsTrustedInGeneric() {
        val g = DeviceProfile.parse("creek", GENERIC, allowMissingDevice = true)
        val s = DeviceProfile.parse(
            "creek-creek",
            """{ product = "creek", device = "creek", page_offset_trusted = 0 }""",
        )
        val merged = DeviceProfile.merge(g, s)
        requireNotNull(merged)
        assertEquals(false, merged.pageOffsetTrusted)
        // 显式否定 → 不允许跳过 calibrate-b
        val plan = DeviceProfilePolicy.planPageOffset(merged, 4096)
        assertFalse(plan.trusted)
    }

    @Test
    fun mergeWithoutAnyProfileIsNull() {
        assertNull(DeviceProfile.merge(null, null))
    }

    @Test
    fun mergeWithOnlyGenericKeepsGeneric() {
        val g = DeviceProfile.parse("creek", GENERIC, allowMissingDevice = true)
        val merged = DeviceProfile.merge(g, null)
        requireNotNull(merged)
        assertEquals("creek", merged.id)
        assertEquals(listOf("creek"), merged.mergedFrom)
        assertEquals(4096, merged.pageSize)
    }

    @Test
    fun mergeWithOnlySpecificKeepsSpecific() {
        val s = DeviceProfile.parse("creek-creek", SPECIFIC)
        val merged = DeviceProfile.merge(null, s)
        requireNotNull(merged)
        assertEquals("creek-creek", merged.id)
        assertEquals(listOf("creek-creek"), merged.mergedFrom)
        assertNull(merged.pageSize)
    }

    // ---------------------------------------------------------------- 归属校验

    @Test
    fun genericProfileBelongsToWholeFamily() {
        val g = DeviceProfile.parse("creek", GENERIC, allowMissingDevice = true)
        requireNotNull(g)
        assertTrue(DeviceProfilePolicy.belongsTo(g, "creek", "creek"))
        assertTrue(DeviceProfilePolicy.belongsTo(g, "creek", "creek-2"))
        assertFalse(DeviceProfilePolicy.belongsTo(g, "madrid", "madrid"))
    }

    @Test
    fun specificProfileIsRejectedOnOtherDevice() {
        val s = DeviceProfile.parse("creek-creek", SPECIFIC)
        requireNotNull(s)
        assertTrue(DeviceProfilePolicy.belongsTo(s, "creek", "creek"))
        assertFalse(DeviceProfilePolicy.belongsTo(s, "creek", "creek-2"))
        assertFalse(DeviceProfilePolicy.belongsTo(s, "madrid", "madrid"))
    }
}
