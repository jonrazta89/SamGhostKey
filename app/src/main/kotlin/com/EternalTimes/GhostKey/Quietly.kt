package com.EternalTimes.GhostKey

/**
 * 运行 [block] 并吞掉其中的任何异常，不关心结果。
 *
 * 用于替换那些**故意丢弃 Result** 的 `runCatching { ... }`（清理 / IO / IPC 尽力而为调用）：
 * 语义等价（同样 catch Throwable），但明确表达"不为结果而来"，消除 Kotlin 2.5 对
 * runCatching 返回值未使用的告警。需要消费成功/失败时仍应直接用 runCatching + Result API。
 */
internal fun tryQuietly(block: () -> Unit) {
    try {
        block()
    } catch (_: Throwable) {
        // 尽力而为：按设计忽略失败
    }
}
