#ifndef MEMGUARD_H
#define MEMGUARD_H

#include <stdint.h>

/*
 * memguard.h - trace 环形缓冲的内存预算（纯计算，可宿主单测）
 *
 * 背景：uaf_plant.c 会把 tracefs 的 per-CPU 环形缓冲
 * (tracefs/buffer_size_kb) 调大来装事件：
 *
 *   采集阶段  16384 KB/CPU  —— 要装下 k_itimer 的分配记录（体积大）
 *   喷洒阶段  65536 KB/CPU  —— 装 mm_page_alloc / mm_page_free
 *
 * 关键事实：**buffer_size_kb 是内核全局设置，进程退出不会还原**。
 * 8 核 × 64 MiB = 512 MiB 内核内存；如果一次运行死在「缓冲已调大、还原没跑到」
 * 的路径上，这 512 MiB 就一直占着，设备可用内存被永久扣掉一块。反复重试 →
 * 越来越接近 OOM → 卡死 → watchdog 重启。这正是「跑一次就卡死重启、反复重试
 * 反复卡」的主要来源。
 *
 * 而旧代码从头到尾**不看设备有多少内存**（全仓没有任何 /proc/meminfo 读取），
 * 一律按 64 MiB/CPU 分配。对 8G 机器来说这一步就是灾难。
 *
 * 所以这里做两件事：
 *   1) 纯函数 memguard_trace_buf_kb()：按设备内存算每 CPU 上限（可宿主单测）；
 *   2) 纯函数 memguard_parse_memtotal_kb()：从 /proc/meminfo 文本取 MemTotal。
 *
 * 不碰 tracefs、不碰 Android，纯计算 → 宿主单测。
 */

/* 每 CPU 环形缓冲的硬上限（KB）。64 MiB/CPU × 8 核 = 512 MiB。 */
#define MEMGUARD_BUF_KB_MAX 65536

/* 下限（KB）。4 MiB 足够装 mm_page_* 这类稀疏事件。 */
#define MEMGUARD_BUF_KB_MIN 4096

/* 采集阶段的固定值（KB/CPU）：要装下 k_itimer 的分配记录，体积大，不能压。 */
#define MEMGUARD_BUF_KB_COLLECT 16384

/* 喷洒阶段的原始值（KB/CPU）：装 mm_page_alloc/free，实际用不到这么多。 */
#define MEMGUARD_BUF_KB_RECLAIM 65536

/*
 * 从 /proc/meminfo 的文本里取 MemTotal（单位 KB）。
 * 文本格式固定为一行 "MemTotal:        123456 kB"。
 * 取不到（没有该行 / 没有数字）返回 0，表示「未知」。
 */
uint64_t memguard_parse_memtotal_kb(const char *text);

/*
 * 按设备内存算出「每 CPU 环形缓冲上限（KB）」。
 *
 * 规则：每 CPU 上限 = 总内存(KB) / 64 / ncpu，再夹到 [4 MiB, 64 MiB]，
 * 并且不超过调用方想要的 want（want 是「这个阶段本来需要多少」）。
 * want 本身 <4 MiB 时不反向撑大（结果永远 ≤ want）。
 *
 * total_kb == 0（读不到内存）或 ncpu <= 0 时返回 want —— 即保持原有行为，
 * 不在信息缺失时擅自改变一条已经跑通过（哪怕只是跑通过失败路径）的路径。
 *
 * 算例：
 *   16 GiB / 8 核 → 每 CPU 32 MiB → 采集 16 MiB 不变、喷洒 64→32 MiB
 *   12 GiB / 8 核 → 每 CPU 24 MiB → 采集 16 MiB 不变、喷洒 64→24 MiB
 *    8 GiB / 8 核 → 每 CPU 16 MiB → 采集 16 MiB 不变、喷洒 64→16 MiB
 *    6 GiB / 8 核 → 每 CPU 12 MiB → 采集 16→12 MiB、喷洒 64→12 MiB
 */
unsigned memguard_trace_buf_kb(uint64_t total_kb, int ncpu, unsigned want);

#endif /* MEMGUARD_H */
