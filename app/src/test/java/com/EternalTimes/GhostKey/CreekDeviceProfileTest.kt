package com.EternalTimes.GhostKey.device

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * creek（POCO M7）机型配置的**资产级**回归。
 *
 * 机型配置分两层：家族通用（`creek.conf`）+ 机型专属（`creek-creek.conf`），
 * 宿主按字段级合并。这里把两层的内容与合并结果钉死：
 *
 *  - 通用层**不写 device**（覆盖整个 creek 家族），但 page_offset 必须**显式**
 *    标成不可信 —— 它会否决任何继承来的 1，且真机确认前宿主照旧走运行时扫描；
 *  - 专属层只写这台机器特有的项（机型名），家族共用项不重复写；
 *  - 合并后专属项 + 继承项各归其位，且**不允许**跳过 calibrate-b。
 *
 * 配置写错（HOCON 语法、字段名笔误、误把推算值标成可信）在这里就会红，
 * 不用等真机才发现。
 */
class CreekDeviceProfileTest {

    private fun assetFile(name: String): File? =
        listOf(
            "app/src/main/assets/device_profiles/$name",
            "src/main/assets/device_profiles/$name",
        ).firstNotNullOfOrNull { p -> File(p).takeIf { it.isFile } }

    private fun genericProfile(): DeviceProfile {
        val f = assetFile("creek.conf")
        assertTrue("找不到通用机型配置 creek.conf", f != null)
        val p = DeviceProfile.parse("creek", f!!.readText(), allowMissingDevice = true)
        assertNotNull("creek.conf 解析失败", p)
        return p!!
    }

    private fun specificProfile(): DeviceProfile {
        val f = assetFile("creek-creek.conf")
        assertTrue("找不到专属机型配置 creek-creek.conf", f != null)
        val p = DeviceProfile.parse("creek-creek", f!!.readText())
        assertNotNull("creek-creek.conf 解析失败", p)
        return p!!
    }

    @Test
    fun `通用层不写 device 且显式不可信`() {
        val g = genericProfile()
        assertEquals("creek", g.product)
        assertEquals("", g.device)
        assertEquals(4096, g.pageSize)
        assertEquals(-549755813888L, g.pageOffset)
        // 未真机确认前必须显式为 false：显式否定会否决继承来的 1
        assertEquals(false, g.pageOffsetTrusted)
    }

    @Test
    fun `专属层只写机型特有项`() {
        val s = specificProfile()
        assertEquals("creek", s.product)
        assertEquals("creek", s.device)
        assertEquals("POCO M7", s.model)
        // 这些属于家族通用，专属层不该重复写
        assertNull(s.pageOffset)
        assertNull(s.pageSize)
        assertNull(s.pageOffsetTrusted)
    }

    @Test
    fun `两级合并后拿到家族通用的常量`() {
        val merged = DeviceProfile.merge(genericProfile(), specificProfile())
        requireNotNull(merged)
        assertEquals("creek-creek", merged.id)
        assertEquals("POCO M7", merged.model)
        assertEquals(4096, merged.pageSize)
        assertEquals(-549755813888L, merged.pageOffset)
        assertEquals(false, merged.pageOffsetTrusted)
        assertTrue(merged.inheritedFields.contains("page_size"))
        assertTrue(merged.inheritedFields.contains("page_offset"))
        assertTrue(merged.inheritedFields.contains("page_offset_trusted"))
    }

    @Test
    fun `未确认的 page_offset 不允许跳过 calibrate-b`() {
        val merged = DeviceProfile.merge(genericProfile(), specificProfile())
        requireNotNull(merged)
        val plan = DeviceProfilePolicy.planPageOffset(merged, 4096)
        assertFalse(plan.trusted)
    }

    @Test
    fun `madrid 专属配置仍可正常解析且未被通用层影响`() {
        val f = assetFile("madrid-madrid.conf")
        assertTrue("找不到 madrid-madrid.conf", f != null)
        val p = DeviceProfile.parse("madrid-madrid", f!!.readText())
        assertNotNull("madrid-madrid.conf 解析失败", p)
        assertEquals("madrid", p!!.product)
        assertEquals("madrid", p.device)
        assertEquals(4096, p.pageSize)
        assertEquals(true, p.pageOffsetTrusted)
        assertTrue(DeviceProfilePolicy.belongsTo(p, "madrid", "madrid"))
        // 归属校验：别让它跑到别的机型上
        assertFalse(DeviceProfilePolicy.belongsTo(p, "creek", "creek"))
    }
}
