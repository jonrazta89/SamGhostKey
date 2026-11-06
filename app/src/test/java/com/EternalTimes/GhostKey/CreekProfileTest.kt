package com.EternalTimes.GhostKey.data

import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * POCO M7 (creek) / HyperOS 3.0.304.0.WBOMIXM 的内置 profile 回归。
 *
 * 这台机器的内核是 5.15-android13-8 家族里的一颗新构建，三处和 6.6 不同：
 *  - 内核镜像是 PE/COFF 容器，_text 落在**文件偏移 0**（裸 arm64 Image 是 0x1000）；
 *  - do_timer_create 里的 kmem_cache_alloc 调用点在函数内 **+0xa4**（6.6 是 +0xa8）；
 *  - task_struct 的 slab 分配点在 **dup_task_struct+0x38**（6.6 是 copy_process+0x140）。
 *
 * profile 里任何一项写错，trace 过滤都会一条都匹配不上（真机表现为
 * captured=0 / hits=0，KASLR 也解不出来），所以这里把三个调用点
 * 和 5.15 家族的 cred 布局钉死。
 */
class CreekProfileTest {

    private val release = "5.15.194-android13-8-00019-gf4321180a397-ab15212794"

    /** kallsyms 里的链接期符号（由本机 boot.img 实测）。 */
    private val doTimerCreate = u("ffffffc00827ec64")
    private val prepareCreds = u("ffffffc00818b13c")
    private val dupTaskStruct = u("ffffffc008132d08")

    private fun u(hex: String): Long = java.lang.Long.parseUnsignedLong(hex, 16)

    private fun assetFile(name: String): File? =
        listOf(
            "app/src/main/assets/kernel_profiles/$name",
            "src/main/assets/kernel_profiles/$name",
        ).firstNotNullOfOrNull { p -> File(p).takeIf { it.isFile } }

    private fun creekProfile(): ProfileDocument {
        val f = assetFile("$release.conf")
        assertTrue("找不到内置 profile: $release.conf", f != null)
        return ProfileDocument.parse(f!!.readText())
    }

    @Test
    fun `内置 profile 字段齐全且 release 精确匹配`() {
        val doc = creekProfile()
        assertEquals(release, doc.release)
        assertTrue("缺字段: ${doc.missingRequiredFields()}", doc.missingRequiredFields().isEmpty())

        val p = doc.toKernelProfile()
        assertEquals(release, p.release)
        // PAGE_OFFSET(0xffffff8000000000) − DRAM 起始(0x80000000)
        assertEquals(-551903297536L, p.pageOffset)
        // 5.15 家族的 cred 布局（176 字节，整体比 6.6 前移 8）
        assertEquals(176, p.credSize)
        assertEquals(4, p.credUid)
        assertEquals(40, p.credCapInheritable)
        assertEquals(72, p.credCapAmbient)
        assertEquals(120, p.credSecurity)
        assertEquals(136, p.credUserNs)
        assertEquals(152, p.credGroups)
        // task_struct / k_itimer
        assertEquals(1944, p.taskCred)
        assertEquals(4608, p.taskStructSize)
        assertEquals(264L, p.kitimerSize)
        assertEquals(120, p.kitimerNode)
    }

    @Test
    fun `分配调用点写的是返回地址而不是函数基址`() {
        val p = creekProfile().toKernelProfile()
        assertEquals(doTimerCreate + 0xa4, p.timerLink)
        assertEquals(prepareCreds + 0x24, p.credLink)
        assertEquals(dupTaskStruct + 0x38, p.taskAllocLink)
    }

    @Test
    fun `落进 308 字节 v4 blob 且字段偏移对齐 kernel_table_c`() {
        val blob = com.EternalTimes.GhostKey.native.KernelProfileSerializer.serialize(
            creekProfile().toKernelProfile(),
        )
        assertEquals(308, blob.size)
        assertEquals("C982", String(blob, 0, 4, Charsets.US_ASCII))

        val buf = ByteBuffer.wrap(blob).order(ByteOrder.LITTLE_ENDIAN)
        assertEquals(4, buf.getShort(4).toInt())
        assertEquals(doTimerCreate + 0xa4, buf.getLong(16))   // timer_link
        assertEquals(prepareCreds + 0x24, buf.getLong(24))     // cred_link
        assertEquals(264L, buf.getLong(248))                   // kitimer_size
        assertEquals(dupTaskStruct + 0x38, buf.getLong(256))   // task_alloc_link
        assertEquals(176, buf.getInt(264))                     // cred_size
        assertEquals(152, buf.getInt(304))                     // cred_groups
    }

    @Test
    fun `index_conf 收录 creek 且引用的文件存在`() {
        val idx = assetFile("index.conf")
        assertTrue("找不到 index.conf", idx != null)
        val line = idx!!.readLines()
            .map { it.substringBefore('#').trim() }
            .firstOrNull { it.startsWith("$release ") }
        assertTrue("index.conf 未收录 $release", line != null)

        val parts = line!!.split(Regex("\\s+"))
        assertEquals("$release.conf", parts[1])
        assertEquals("1", parts[2])
        assertTrue("index 指向的文件不存在: ${parts[1]}", assetFile(parts[1]) != null)
    }
}
