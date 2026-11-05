package com.EternalTimes.GhostKey

import com.EternalTimes.GhostKey.ksu.KsudStage
import com.EternalTimes.GhostKey.ksu.KsudStage.Outcome
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** KSUD_STAGE（管理器提取 ksud）脚本与输出解析测试。 */
class KsudStageTest {

    @Test
    fun `解析成功标记`() {
        val out = "KSUD_STAGE_OK md5=abc123 size=6402736\n"
        val r = KsudStage.parse(out)
        assertEquals(Outcome.Ok("abc123", 6402736L), r)
    }

    @Test
    fun `解析失败标记`() {
        assertEquals(
            Outcome.Fail("manager_not_installed"),
            KsudStage.parse("KSUD_STAGE_FAIL manager_not_installed\n"),
        )
        assertEquals(
            Outcome.Fail("no_source apk=/data/app/xx/base.apk"),
            KsudStage.parse("KSUD_STAGE_FAIL no_source apk=/data/app/xx/base.apk"),
        )
    }

    @Test
    fun `无输出视为执行异常`() {
        assertEquals(Outcome.Fail("no_output"), KsudStage.parse(""))
        assertEquals(Outcome.Fail("no_output"), KsudStage.parse("sh: pm: not found\n"))
    }

    @Test
    fun `取最后一个标记行`() {
        val out = "KSUD_STAGE_FAIL no_source apk=a\nKSUD_STAGE_OK md5=ff size=10\n"
        val r = KsudStage.parse(out)
        assertTrue(r is Outcome.Ok)
    }

    @Test
    fun `脚本是合法的最小 shell 形状`() {
        val s = KsudStage.SCRIPT
        // 关键元素：候选包名、pm path、两路提取、KSUD_STAGE 标记
        assertTrue(s.contains("me.weishu.kernelsu"))
        // SuKiSu Ultra 家族（复用设备已装管理器，不内置产物）
        assertTrue(s.contains("com.sukisu.ultra"))
        assertTrue(s.contains("pm path"))
        assertTrue(s.contains("lib/arm64/libksud.so"))
        assertTrue(s.contains("lib/arm64-v8a/libksud.so"))
        assertTrue(s.contains("KSUD_STAGE_OK"))
        assertTrue(s.contains("KSUD_STAGE_FAIL"))
        // 目标路径与常量一致
        assertTrue(s.contains("T=${KsudStage.TARGET}"))
    }

    @Test
    fun `脚本覆盖混淆改名 fork`() {
        val s = KsudStage.SCRIPT
        // SukiSU Ultra 在候选包名里，且脚本按内容签名兜底挑随机改名的 ksud
        assertTrue(s.contains("com.sukisu.ultra"))
        assertTrue(s.contains("late-load"))
        assertTrue(s.contains("kernelsu"))
    }

    @Test
    fun `ksud 签名识别`() {
        // 造一个大 ELF 头 + late-load / kernelsu 语义串（模拟 SukiSU 随机改名产物）
        val ksud = ByteArray(600 * 1024)
        ksud[0] = 0x7f
        ksud[1] = 'E'.code.toByte()
        ksud[2] = 'L'.code.toByte()
        ksud[3] = 'F'.code.toByte()
        "late-load".toByteArray().copyInto(ksud, 64)
        "kernelsu".toByteArray().copyInto(ksud, 128)
        assertTrue(KsudStage.containsKsudSignature(ksud))
    }

    @Test
    fun `ksud 签名拒绝非 ksud`() {
        val big = ByteArray(600 * 1024)
        big[0] = 0x7f
        big[1] = 'E'.code.toByte()
        big[2] = 'L'.code.toByte()
        big[3] = 'F'.code.toByte()
        // ELF 但没有 ksud 语义串
        assertFalse(KsudStage.containsKsudSignature(big))
        // 有语义串但不是 ELF
        val notElf = ByteArray(600 * 1024)
        "late-load".toByteArray().copyInto(notElf, 64)
        "kernelsu".toByteArray().copyInto(notElf, 128)
        assertFalse(KsudStage.containsKsudSignature(notElf))
        // 体积不足下限
        assertFalse(KsudStage.containsKsudSignature(ByteArray(1024)))
    }
}
