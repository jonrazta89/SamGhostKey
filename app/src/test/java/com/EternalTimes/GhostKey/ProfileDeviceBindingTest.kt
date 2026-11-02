package com.EternalTimes.GhostKey.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * 内核 profile 的 **机型声明**（`device`）解析与往返单测。
 *
 * 为什么需要它：内核 profile 按 `uname -r` 精确匹配，但**内核字符串相同不等于
 * 内核镜像相同**。`task_cred`（offsetof(task_struct, cred)）、`cred_size`、
 * `kitimer_node` 这些结构体偏移来自 BTF，随 vendor config 片段变化，**无法在
 * 运行期验证**。套用别的机型的偏移 → 往 task_struct 的错误字段写值 → 踩坏内核
 * 内存 → kernel panic → 设备重启。
 *
 * 所以 profile 可以声明它实测的机型（`device = "product-device"`），由注入前的
 * 一致性校验拦下「别的机型套用」。
 *
 * 这里锁死三件事：
 *  1. 声明了 `device` 就能解析出来；
 *  2. 没声明就是 null（**不做**机型校验 —— 既有 profile 行为不变）；
 *  3. KernelProfile → HOCON → KernelProfile 往返不丢 `device`。
 */
class ProfileDeviceBindingTest {

    /** 一份最小可用的内核 profile（字段集与 pkj110.conf 等价）。 */
    private val BASE = """
        release = "6.18.21-android17-5-g284297031c53-abogki555938958-4k"
        vuln_type = "cve-2026-98260"
        recommend_shizuku = 1
        page_offset = 0xffffff8000000000
        offset {
            timer_link = 0xffffffc08021104c
            cred_link = 0xffffffc080133160
            selinux_link = 0xffffffc082918630
            user_ns = 0xffffffc0826d1e48
            root_user = 0xffffffc0826d2098
            groups = 0xffffffc0826d2a08
            ucounts = 0xffffffc0826d2b60
            task_cred = 0x908
            task_struct_size = 0x1280
            cred_uid = 0x8
            kitimer_node = 0xe0
        }
    """.trimIndent()

    @Test
    fun `声明了 device 就能解析出来`() {
        val doc = ProfileDocument.parse(
            """
            $BASE
            device = "madrid-madrid"
            """.trimIndent()
        )
        assertEquals("madrid-madrid", doc.toKernelProfile().device)
    }

    @Test
    fun `没声明 device 就是 null 表示不做机型校验`() {
        val doc = ProfileDocument.parse(BASE)
        assertNull(doc.toKernelProfile().device)
    }

    @Test
    fun `空串与纯空白视为未声明`() {
        val doc = ProfileDocument.parse(
            """
            $BASE
            device = "   "
            """.trimIndent()
        )
        assertNull(doc.toKernelProfile().device)
    }

    @Test
    fun `往返不丢 device`() {
        val original = ProfileDocument.parse(
            """
            $BASE
            device = "madrid-madrid"
            """.trimIndent()
        ).toKernelProfile()

        val round = ProfileDocument.fromKernelProfile(original)
            .let { ProfileDocument.parse(it.toHocon()) }
            .toKernelProfile()

        assertEquals("madrid-madrid", round.device)
        assertEquals(original.release, round.release)
        assertEquals(original.taskCred, round.taskCred)
        assertEquals(original.credSize, round.credSize)
        assertEquals(original.kitimerNode, round.kitimerNode)
    }
}
