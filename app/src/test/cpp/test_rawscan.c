/*
 * T4 - rawscan.c 的宿主单测
 *
 * 被测对象是 raw trace 记录的增量扫描器（rawscan.c）。它是 uaf_plant.c 里
 * collect_nth() 的核心：从 per-CPU 的 trace_pipe_raw 里挑出 k_itimer 分配记录。
 *
 * 为什么它值得单独测：这条路径直接决定「拿哪个 k_itimer 当 UAF 受害者」。
 * 它在设备上的失败表现是「注入了但 uid 没变成 0」，而设备上根本没有断点可打，
 * 只能靠宿主单测把逻辑钉死。
 *
 * 重点验证的性质：
 *   1) **分块喂与整块喂的结果必须逐条一致** —— 这是把「读完再扫」改成
 *      「边读边扫」的前提。记录是按字节逐位试探匹配的，候选可能跨块。
 *   2) 过滤条件与旧实现逐字一致（call_site / bytes_req / 内核地址 / 8 字节对齐）。
 *   3) out[] 容量小于命中数时：只截断数组，命中总数照常计数。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rawscan.h"

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

#define SITE 0xffffffd2f4211134ULL
#define REQ  0x180ULL
#define NPTR 0xffffff8be3c18a80ULL

#define BUF_SZ 4096

/* 往 buf 的 off 处摆一条 kmem_cache_alloc 记录（6.18 布局）。 */
static void put_rec(uint8_t *buf, size_t off, uint64_t site, uint64_t ptr, uint64_t req)
{
	uint64_t pad = 0;
	memcpy(buf + off, &site, 8);
	memcpy(buf + off + 8, &ptr, 8);
	memcpy(buf + off + 16, &pad, 8);	/* 6.18: name_desc */
	memcpy(buf + off + 24, &req, 8);	/* bytes_req */
	memcpy(buf + off + 32, &pad, 8);	/* bytes_alloc */
}

/* 造一条缓冲区：填充 0xAA（保证不会误命中），在指定偏移摆记录。 */
static size_t build(uint8_t *buf, const size_t *offs, const uint64_t *ptrs, size_t n)
{
	size_t i;
	memset(buf, 0xAA, BUF_SZ);
	for (i = 0; i < n; i++)
		put_rec(buf, offs[i], SITE, ptrs[i], REQ);
	return BUF_SZ;
}

int main(void)
{
	uint8_t buf[BUF_SZ];
	uint64_t whole_out[64], chunk_out[64];
	struct rawscan_state s;
	uint64_t site64 = SITE;

	/* ---- 用例数据：5 条正常记录 ---- */
	size_t offs[] = { 100, 300, 700, 1200, 2000 };
	uint64_t ptrs[] = { 0xffffff8be3c18a80ULL, 0xffffff8be3c18b60ULL,
			    0xffffff8be3c18c40ULL, 0xffffff8b87e3d800ULL,
			    0xffffff8bd20bfb00ULL };
	size_t n = 5;
	size_t len;

	len = build(buf, offs, ptrs, n);
	/* 干扰项（必须放在 build() 之后：build() 会 memset 整块） */
	put_rec(buf, 400, SITE ^ 0x1ULL, 0xffffff8baaaaaa00ULL, REQ);	/* site 不对 */
	put_rec(buf, 800, SITE, 0xffffff8bbbbbbb00ULL, 0x108ULL);		/* req 不对 */
	put_rec(buf, 1500, SITE, 0xffffff8bcccccc04ULL, REQ);		/* ptr 未对齐 */
	put_rec(buf, 2500, SITE, 0x0000000012345600ULL, REQ);		/* ptr 非内核地址 */

	/* ---- 1) 整块喂 ---- */
	memset(whole_out, 0, sizeof(whole_out));
	rawscan_init(&s, (const uint8_t *)&site64, 1, REQ,
		     whole_out, (int)(sizeof(whole_out) / sizeof(whole_out[0])), 2);
	rawscan_feed(&s, buf, len);
	CHECK(s.out_n == 5);
	CHECK(s.chosen == ptrs[2]);
	CHECK(s.bytes == len);
	CHECK(whole_out[0] == ptrs[0]);
	CHECK(whole_out[4] == ptrs[4]);

	/* ---- 2) 分块喂必须与整块喂完全一致 ---- */
	{
		static const size_t chunks[] = { 1, 3, 7, 31, 32, 33, 64, 97, 1000, 4096 };
		size_t ci;
		for (ci = 0; ci < sizeof(chunks) / sizeof(chunks[0]); ci++) {
			size_t off = 0;
			memset(chunk_out, 0, sizeof(chunk_out));
			rawscan_init(&s, (const uint8_t *)&site64, 1, REQ,
				     chunk_out,
				     (int)(sizeof(chunk_out) / sizeof(chunk_out[0])), 2);
			while (off < len) {
				size_t take = chunks[ci];
				if (off + take > len)
					take = len - off;
				rawscan_feed(&s, buf + off, take);
				off += take;
			}
			CHECK(s.out_n == 5);
			CHECK(s.chosen == ptrs[2]);
			CHECK(memcmp(whole_out, chunk_out,
				     sizeof(whole_out)) == 0);
		}
	}

	/* ---- 3) 记录正好跨块边界时不能漏 ---- */
	{
		/* 记录起点落在第 64 字节块的第 20 字节 → 记录跨 64 字节边界 */
		uint8_t b2[256];
		uint64_t p2[] = { 0xffffff8baaaaaa00ULL, 0xffffff8bbbbbbb00ULL };
		uint64_t out2[8];
		size_t off;
		memset(b2, 0xAA, sizeof(b2));
		put_rec(b2, 20, SITE, p2[0], REQ);
		put_rec(b2, 100, SITE, p2[1], REQ);
		off = 0;
		rawscan_init(&s, (const uint8_t *)&site64, 1, REQ,
			     out2, (int)(sizeof(out2) / sizeof(out2[0])), 0);
		while (off < sizeof(b2)) {
			size_t take = 64;	/* 边界落在 64 / 128 / 192 */
			if (off + take > sizeof(b2))
				take = sizeof(b2) - off;
			rawscan_feed(&s, b2 + off, take);
			off += take;
		}
		CHECK(s.out_n == 2);
		CHECK(out2[0] == p2[0]);
		CHECK(out2[1] == p2[1]);
	}

	/* ---- 4) filter_by_site=0 时忽略 site ---- */
	{
		uint64_t out4[8];
		rawscan_init(&s, NULL, 0, REQ, out4,
			     (int)(sizeof(out4) / sizeof(out4[0])), 0);
		rawscan_feed(&s, buf, len);
		/* 5 条正常 + site 不对那条（site 不过滤了）= 6；req/对齐/地址过滤仍在 */
		CHECK(s.out_n == 6);
		CHECK(out4[0] == ptrs[0]);
	}

	/* ---- 5) out[] 容量不足：数组截断，命中总数照常计数 ---- */
	{
		uint64_t out5[2];
		rawscan_init(&s, (const uint8_t *)&site64, 1, REQ,
			     out5, 2, 3);
		rawscan_feed(&s, buf, len);
		CHECK(s.out_n == 5);
		CHECK(s.chosen == ptrs[3]);
		CHECK(out5[0] == ptrs[0]);
		CHECK(out5[1] == ptrs[1]);
	}

	/* ---- 6) index 超出命中数 → chosen 保持 0 ---- */
	{
		uint64_t out6[8];
		rawscan_init(&s, (const uint8_t *)&site64, 1, REQ,
			     out6, (int)(sizeof(out6) / sizeof(out6[0])), 99);
		rawscan_feed(&s, buf, len);
		CHECK(s.out_n == 5);
		CHECK(s.chosen == 0);
	}

	/* ---- 7) 空数据 ---- */
	{
		uint64_t out7[8];
		rawscan_init(&s, (const uint8_t *)&site64, 1, REQ,
			     out7, (int)(sizeof(out7) / sizeof(out7[0])), 0);
		rawscan_feed(&s, buf, 0);
		CHECK(s.out_n == 0);
		CHECK(s.chosen == 0);
		CHECK(s.bytes == 0);
	}

	printf("[case] rawscan incremental record scanning\n");
	printf("%d checks, %d failure(s): %s\n", g_checks, g_failures,
	       g_failures ? "FAIL" : "OK");
	return g_failures ? 1 : 0;
}
