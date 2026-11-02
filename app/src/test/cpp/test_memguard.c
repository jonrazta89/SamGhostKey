/*
 * T5 - memguard.c 的宿主单测
 *
 * 被测对象是 trace 环形缓冲的内存预算（memguard.c）。它决定 uaf_plant.c 往
 * tracefs/buffer_size_kb 写多大的 per-CPU 环形缓冲。
 *
 * 为什么它值得单独测：buffer_size_kb 是**内核全局设置，进程退出不会还原**。
 * 写大了 → 8 核 × 64 MiB = 512 MiB 内核内存被永久扣住 → 反复重试 → OOM →
 * 卡死 → watchdog 重启。这条链在设备上的表现是「跑一次就重启」，但设备上
 * 没有断点可打，只能靠宿主单测把预算算式钉死。
 *
 * 重点验证的性质：
 *   1) /proc/meminfo 文本解析：正常行、缺行、脏值都要有确定结果；
 *   2) 预算算式：信息缺失时**保持原行为**（不改已跑过的路径）；
 *   3) 结果永远不超过调用方要的 want（不能反向撑大）；
 *   4) 夹取上下限的行为符合预期。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "memguard.h"

static int g_checks;
static int g_failures;

static void check(int ok, const char *expr, int line)
{
	g_checks++;
	if (!ok) {
		g_failures++;
		printf("  FAIL  line %d: %s\n", line, expr);
	}
}

#define CHECK(cond) check((cond) != 0, #cond, __LINE__)

#define MIB 1024ULL
#define GIB (1024ULL * MIB)

/* 一段典型的 /proc/meminfo 头部。 */
static const char *MEMINFO =
	"MemTotal:       12082696 kB\n"
	"MemFree:         1234567 kB\n"
	"MemAvailable:    7654321 kB\n"
	"Buffers:          123456 kB\n"
	"Cached:          2345678 kB\n";

static void test_parse(void)
{
	/* 正常：取第一行的数值。 */
	CHECK(memguard_parse_memtotal_kb(MEMINFO) == 12082696ULL);

	/* 只有一行也能取。 */
	CHECK(memguard_parse_memtotal_kb("MemTotal:  123456 kB\n") == 123456ULL);

	/* 行尾无换行。 */
	CHECK(memguard_parse_memtotal_kb("MemTotal:  123456 kB") == 123456ULL);

	/* 前缀不在行首也没关系（strstr）。 */
	CHECK(memguard_parse_memtotal_kb("garbage MemTotal:  77 kB\n") == 77ULL);

	/* 缺 MemTotal → 0（未知）。 */
	CHECK(memguard_parse_memtotal_kb("MemFree:  123456 kB\n") == 0ULL);

	/* 空文本 / NULL → 0。 */
	CHECK(memguard_parse_memtotal_kb("") == 0ULL);
	CHECK(memguard_parse_memtotal_kb(NULL) == 0ULL);

	/* 脏值：不是数字 → 0，不能瞎猜。 */
	CHECK(memguard_parse_memtotal_kb("MemTotal:  unknown kB\n") == 0ULL);
	CHECK(memguard_parse_memtotal_kb("MemTotal:\n") == 0ULL);

	/* 只有 MemTotal 行缺失但别的行有数字，也不能误取别人的数。 */
	CHECK(memguard_parse_memtotal_kb("SwapTotal:  999 kB\n") == 0ULL);
}

static void test_budget(void)
{
	/* 信息缺失 → 保持原行为。 */
	CHECK(memguard_trace_buf_kb(0, 8, 65536) == 65536);
	CHECK(memguard_trace_buf_kb(0, 8, 16384) == 16384);
	CHECK(memguard_trace_buf_kb(12082696ULL, 0, 65536) == 65536);
	CHECK(memguard_trace_buf_kb(12082696ULL, -1, 65536) == 65536);

	/* 16 GiB / 8 核 → 每 CPU 32 MiB。采集不动，喷洒 64→32。 */
	CHECK(memguard_trace_buf_kb(16 * GIB, 8, 16384) == 16384);
	CHECK(memguard_trace_buf_kb(16 * GIB, 8, 65536) == 32768);

	/* 12 GiB / 8 核 → 每 CPU 24 MiB。 */
	CHECK(memguard_trace_buf_kb(12 * GIB, 8, 16384) == 16384);
	CHECK(memguard_trace_buf_kb(12 * GIB, 8, 65536) == 24576);

	/* 8 GiB / 8 核 → 每 CPU 16 MiB。 */
	CHECK(memguard_trace_buf_kb(8 * GIB, 8, 16384) == 16384);
	CHECK(memguard_trace_buf_kb(8 * GIB, 8, 65536) == 16384);

	/* 6 GiB / 8 核 → 每 CPU 12 MiB，采集也会被压。 */
	CHECK(memguard_trace_buf_kb(6 * GIB, 8, 16384) == 12288);
	CHECK(memguard_trace_buf_kb(6 * GIB, 8, 65536) == 12288);

	/* 4 GiB / 8 核 → 每 CPU 8 MiB。 */
	CHECK(memguard_trace_buf_kb(4 * GIB, 8, 65536) == 8192);

	/* 超大内存也封顶在 64 MiB（= want 的上限）。 */
	CHECK(memguard_trace_buf_kb(512 * GIB, 8, 65536) == 65536);

	/* 极小内存 → 抬到下限 4 MiB（但仍不超过 want）。 */
	CHECK(memguard_trace_buf_kb(256 * MIB, 8, 65536) == MEMGUARD_BUF_KB_MIN);

	/* want 本身小于下限时不得反向撑大。 */
	CHECK(memguard_trace_buf_kb(16 * GIB, 8, 1024) == 1024);
	/* 内存极小 + want 很小时：结果取内存份额，且仍 ≤ want。 */
	CHECK(memguard_trace_buf_kb(1024, 8, 1024) <= 1024);
	CHECK(memguard_trace_buf_kb(1024, 8, 1024) > 0);

	/* 结果永远 ≤ want。 */
	CHECK(memguard_trace_buf_kb(16 * GIB, 8, 16384) <= 16384);
	CHECK(memguard_trace_buf_kb(6 * GIB, 8, 65536) <= 65536);
}

int main(void)
{
	test_parse();
	test_budget();
	printf("%s memguard: %d checks, %d failures\n",
	       g_failures ? "FAIL" : "ok", g_checks, g_failures);
	return g_failures ? 1 : 0;
}
