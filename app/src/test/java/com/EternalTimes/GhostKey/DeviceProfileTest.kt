package com.EternalTimes.GhostKey.device

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 机型配置（device profile）的解析与决策单测。
 *
 * 这里锁死三件事：
 *  1. HOCON 解析（无符号 64 位 hex 的 page_offset、嵌套 flow 块）；
 *  2. page_offset 的「可信 → 允许跳过 calibrate-b」判定，含**页大小校验**
 *     （4K/16K/64K 的 PAGE_OFFSET 不同，页大小对不上就是隐性故障）；
 *  3. 任何前提不满足时都退回运行时扫描（宁慢不错）。
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
        assertTrue(p.pageOffsetTrusted)
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
        assertFalse(p.pageOffsetTrusted)
    }

    @Test
    fun untrustedFlagAcceptsZeroAndFalse() {
        val p = DeviceProfile.parse(
            "x",
            """{ product = "a", device = "b", page_offset = 0x1000, page_offset_trusted = 0 }""",
        )
        requireNotNull(p)
        assertFalse(p.pageOffsetTrusted)
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
}
