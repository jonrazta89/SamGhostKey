package com.EternalTimes.GhostKey.data.ota

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * [AllocCallSiteResolver] 的合成镜像回归。
 *
 * 真机 boot.img 不入库，所以这里用一段「手搓的代码段」代替：
 * 按 arm64 编码放一条 BL，再配一张假符号表，检查解析器能不能
 * 复原出正确的调用点（BL 的下一条指令地址）。
 */
class AllocCallSiteResolverTest {

    /** 链接期基址（超过 Long 正数范围，按无符号解析）。 */
    private val base: Long = java.lang.Long.parseUnsignedLong("ffffffc008000000", 16)

    /** 在 [image] 的 [fileOff] 处写入一条跳到 [targetVa] 的 BL。 */
    private fun putBl(image: ByteArray, fileOff: Int, insnVa: Long, targetVa: Long) {
        val imm = ((targetVa - insnVa) ushr 2).toInt()
        // 0x94000000 超出 Int 正数范围，用有符号写法保证是 Int
        val w = -0x6C000000 or (imm and 0x03FFFFFF)
        image[fileOff] = (w and 0xFF).toByte()
        image[fileOff + 1] = ((w ushr 8) and 0xFF).toByte()
        image[fileOff + 2] = ((w ushr 16) and 0xFF).toByte()
        image[fileOff + 3] = ((w ushr 24) and 0xFF).toByte()
    }

    /** 裸 arm64 Image 布局：_text 在文件偏移 0x1000。 */
    @Test
    fun `裸 arm64 Image 布局下解析出分配调用点`() {
        val textOff = 0x1000
        val fnVa = base + textOff
        val allocVa = base + textOff + 0x2000
        val image = ByteArray(0x4000)
        putBl(image, textOff + 0x20, fnVa + 0x20, allocVa)

        val symbols = mapOf(
            "do_timer_create" to fnVa,
            "kmem_cache_alloc" to allocVa,
            "zzz_end" to base + textOff + 0x1800,
        )
        val sites = AllocCallSiteResolver.resolve(image, symbols, base)

        assertEquals(
            fnVa + 0x24,
            sites[AllocCallSiteResolver.KEY_TIMER],
        )
    }

    /** PE/COFF 布局：_text 就在文件偏移 0（creek 5.15 GKI 就是这种）。 */
    @Test
    fun `PE 容器布局下解析出分配调用点`() {
        val fnVa = base
        val allocVa = base + 0x2000
        val image = ByteArray(0x4000)
        putBl(image, 0x20, fnVa + 0x20, allocVa)

        val symbols = mapOf(
            "do_timer_create" to fnVa,
            "kmem_cache_alloc" to allocVa,
            "zzz_end" to base + 0x1800,
        )
        val sites = AllocCallSiteResolver.resolve(image, symbols, base)

        assertEquals(
            fnVa + 0x24,
            sites[AllocCallSiteResolver.KEY_TIMER],
        )
    }

    /** task_struct 的分配点：dup_task_struct 里找，找不到再退到 copy_process。 */
    @Test
    fun `task_struct 分配点优先取 dup_task_struct`() {
        val textOff = 0x1000
        val dupVa = base + textOff
        val allocVa = base + textOff + 0x2000
        val image = ByteArray(0x4000)
        putBl(image, textOff + 0x30, dupVa + 0x30, allocVa)

        val symbols = mapOf(
            "dup_task_struct" to dupVa,
            "kmem_cache_alloc" to allocVa,
            "zzz_end" to base + textOff + 0x1800,
        )
        val sites = AllocCallSiteResolver.resolve(image, symbols, base)

        assertEquals(dupVa + 0x34, sites[AllocCallSiteResolver.KEY_TASK])
    }

    /** 没有分配器调用时不该硬凑一个值出来。 */
    @Test
    fun `没有分配调用时返回空`() {
        val textOff = 0x1000
        val fnVa = base + textOff
        val image = ByteArray(0x4000)
        val symbols = mapOf(
            "do_timer_create" to fnVa,
            "zzz_end" to base + textOff + 0x1800,
        )
        val sites = AllocCallSiteResolver.resolve(image, symbols, base)

        assertTrue(sites.isEmpty())
        assertNull(sites[AllocCallSiteResolver.KEY_TIMER])
    }
}
