/*
 * memguard.c - trace 环形缓冲的内存预算（纯计算，可宿主单测）
 *
 * 详见 memguard.h 的说明。这里只有两个纯函数：不读文件、不碰 tracefs，
 * 因此可以在宿主机上直接单测（见 app/src/test/cpp/test_memguard.c）。
 */

#include <stdlib.h>
#include <string.h>

#include "memguard.h"

uint64_t memguard_parse_memtotal_kb(const char *text)
{
	const char *p;
	unsigned long long kb = 0;

	if (!text)
		return 0;
	p = strstr(text, "MemTotal:");
	if (!p)
		return 0;
	p += sizeof("MemTotal:") - 1;
	while (*p == ' ' || *p == '\t')
		p++;
	/* strtoull 会跳过前导空白；这里再确认一次首字符是数字，避免把
	 * "MemTotal:  unknown kB" 这类行解析成 0 之外的怪值。 */
	if (*p < '0' || *p > '9')
		return 0;
	kb = strtoull(p, NULL, 10);
	return (uint64_t)kb;
}

unsigned memguard_trace_buf_kb(uint64_t total_kb, int ncpu, unsigned want)
{
	uint64_t per_cpu, cap;

	/* 信息缺失 → 保持原行为，不擅自改变已跑过的路径。 */
	if (total_kb == 0 || ncpu <= 0)
		return want;

	/* 每 CPU 上限：总内存的 1/64 再除以 CPU 数。 */
	per_cpu = total_kb / 64u / (uint64_t)ncpu;
	if (per_cpu == 0)
		per_cpu = 1;

	/* 先取「想要的」与「内存允许的」里小的那个。 */
	cap = (uint64_t)want;
	if (per_cpu < cap)
		cap = per_cpu;

	/*
	 * 下限只在调用方本来就要 ≥4 MiB 时才抬：结果永远不超过 want。
	 * want 本来就 <4 MiB 的场合（没有）保持原样，不反向撑大。
	 */
	if (want >= MEMGUARD_BUF_KB_MIN && cap < MEMGUARD_BUF_KB_MIN)
		cap = MEMGUARD_BUF_KB_MIN;
	if (cap > MEMGUARD_BUF_KB_MAX)
		cap = MEMGUARD_BUF_KB_MAX;
	return (unsigned)cap;
}
