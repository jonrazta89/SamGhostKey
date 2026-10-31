/*
 * T1 - slide_resolve.c 的宿主单测（不需要 Android NDK，也不触碰 tracefs）
 *
 * 被测对象是 6.18 适配新增的「从运行期 call_site 精确反解 KASLR slide」：
 *
 *   call_site = F + slide + off        (F = 函数未重定位地址, off = 函数内偏移)
 *   slide ≡ 0 (mod 2 MiB)
 *   => off = (call_site - F) mod 2 MiB
 *   => slide = call_site - F - off
 *
 * 这段逻辑一旦漂移就是「slide 算错 → 伪造 cred 里全是错指针」的隐性故障，
 * 真机上只表现为 exploit 静默失败，所以必须在宿主上跑：
 *
 *   sr_find_func           按 VA 二分定位包含某地址的符号
 *   sr_resolve_slide       给定 (函数基址, 函数长度, 运行期 call_site) 解 slide
 *   sr_resolve_slide_named 按函数名解 slide（运行期的真实用法）
 *   sr_resolve_slide_syms  按未重定位 call_site 解 slide
 *
 * 运行：app/src/test/cpp/run_c_tests.sh（需要 clang 或 gcc，任意平台）
 * 退出码：0 全部通过，1 有失败项（便于接 CI）。
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "slide_resolve.h"

_Static_assert(sizeof(uint64_t) == 8, "test assumes 64-bit uint64_t");

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
#define CHECK_EQ_U64(got, want)                                                        \
	do {                                                                           \
		uint64_t g_ = (uint64_t)(got), w_ = (uint64_t)(want);                  \
		if (g_ != w_) {                                                        \
			g_checks++;                                                    \
			g_failures++;                                                  \
			printf("  FAIL  line %d: %s == %s (got 0x%llx, want 0x%llx)\n", \
			       __LINE__, #got, #want,                                     \
			       (unsigned long long)g_, (unsigned long long)w_);          \
		}                                                                      \
	} while (0)

/* 确定性 LCG：单测必须可复现，不能用时间做种子。 */
static uint64_t rng_state = 0x243F6A8885A308D3ULL;

static uint64_t rng_next(void)
{
	rng_state = rng_state * 6364136223846793005ULL + 1442695040888963407ULL;
	return rng_state >> 11;
}

/* ------------------------------------------------------------------ */

/*
 * 造一张按 VA 升序的符号表。
 * 刻意在若干个 VA 上放多个别名（_text/__pi__text…），
 * 因为真实 kallsyms 就是这样，而「下一个符号」若不跳过同 VA 别名
 * 会算出 0 长度的函数，off 校验就永远过不了。
 */
#define MAX_SYMS 64

static void build_syms(sr_sym *syms, size_t *n_out, const char *const *names,
		       const uint64_t *vas, size_t n_names)
{
	size_t i;

	*n_out = 0;
	for (i = 0; i < n_names; i++) {
		syms[*n_out].va = vas[i];
		syms[*n_out].name = names[i];
		(*n_out)++;
	}
}

/* 一个函数在表里的长度：到下一个**不同** VA 的距离。 */
static uint64_t func_len_of(const sr_sym *syms, size_t n, size_t idx)
{
	size_t j;

	if (idx + 1 >= n)
		return SR_FUNC_MAX_LEN;
	for (j = idx + 1; j < n; j++) {
		if (syms[j].va != syms[idx].va)
			return syms[j].va - syms[idx].va;
	}
	return SR_FUNC_MAX_LEN;
}

/* ------------------------------------------------------------------ */

static void test_exact_recovery(void)
{
	/* do_timer_create + 前后各若干符号，末尾带一组同 VA 别名 */
	static const char *const names[] = {
		"_text", "__pi__text", "do_timer_create", "do_timer_create.part",
		"prepare_creds", "prep", "selinux_state",
	};
	static const uint64_t vas[] = {
		0xffffffc080000000ULL, 0xffffffc080000000ULL, 0xffffffc080211040ULL,
		0xffffffc080211040ULL, 0xffffffc080220000ULL, 0xffffffc080220000ULL,
		0xffffffc080300000ULL,
	};
	sr_sym syms[MAX_SYMS];
	size_t n = 0;
	uint64_t slide = 0x1a200000ULL;   /* 2MiB 对齐 */
	uint64_t off = 0x20;              /* 调用点在函数内的偏移 */
	uint64_t func_va = 0xffffffc080211040ULL;
	uint64_t call_site = func_va + slide + off;
	uint64_t got_slide = 0, got_unreloc = 0;

	build_syms(syms, &n, names, vas, sizeof(vas) / sizeof(vas[0]));
	CHECK(n == 7);

	/* 同 VA 别名必须让「函数长度」算成到下一个不同 VA 的距离，而不是 0 */
	CHECK_EQ_U64(func_len_of(syms, n, 2), 0xffffffc080220000ULL - func_va);

	/* 按名字解：应精确还原 slide */
	CHECK(sr_resolve_slide_named(syms, n, "do_timer_create", call_site,
				     &got_slide, &got_unreloc) == 1);
	CHECK_EQ_U64(got_slide, slide);
	CHECK_EQ_U64(got_unreloc, func_va + off);

	/* 同一张表，换另一个别名查，长度也要对 */
	got_slide = 0;
	CHECK(sr_resolve_slide_named(syms, n, "do_timer_create.part", call_site,
				     &got_slide, NULL) == 1);
	CHECK_EQ_U64(got_slide, slide);
}

static void test_low_level_resolve(void)
{
	uint64_t func_va = 0xffffffc080211040ULL;
	uint64_t slide = 0x3c000000ULL;
	uint64_t off = 0x1a4;
	uint64_t call_site = func_va + slide + off;
	uint64_t got_slide = 0, got_off = 0;
	uint64_t len = 0x400;

	CHECK(sr_resolve_slide(func_va, len, call_site, &got_slide, &got_off) == 1);
	CHECK_EQ_U64(got_slide, slide);
	CHECK_EQ_U64(got_off, off);

	/* 函数长度不足以容纳该偏移 -> 不自洽，必须拒绝 */
	got_slide = 0;
	CHECK(sr_resolve_slide(func_va, 0x10, call_site, &got_slide, &got_off) == 0);

	/* call_site 落在函数之前 -> 拒绝 */
	got_slide = 0;
	CHECK(sr_resolve_slide(func_va, len, func_va - 0x100, &got_slide, &got_off) == 0);

	/* 函数长度 >= 2MiB -> off 不唯一，参数错误 */
	CHECK(sr_resolve_slide(func_va, SR_FUNC_MAX_LEN, call_site, &got_slide,
			       &got_off) == -1);

	/* slide 超出合理上界 -> 拒绝 */
	got_slide = 0;
	CHECK(sr_resolve_slide(func_va, len, func_va + (1ULL << 43),
			       &got_slide, &got_off) == 0);
}

static void test_negatives(void)
{
	static const char *const names[] = { "alpha", "beta" };
	static const uint64_t vas[] = { 0xffffffc080100000ULL, 0xffffffc080200000ULL };
	sr_sym syms[MAX_SYMS];
	size_t n = 0;
	uint64_t slide = 0x800000ULL;
	uint64_t got_slide = 0;

	build_syms(syms, &n, names, vas, 2);

	/* 表里没有这个函数名 */
	CHECK(sr_resolve_slide_named(syms, n, "not_there",
				     0xffffffc080100000ULL + slide + 0x10,
				     &got_slide, NULL) == 0);

	/* 空表 */
	CHECK(sr_resolve_slide_named(syms, 0, "alpha", 0x1000, &got_slide, NULL) == 0);

	/* sr_find_func：地址低于第一个符号 -> 0 */
	{
		uint64_t base = 0, len = 0;
		CHECK(sr_find_func(syms, n, 0xffffffc07f000000ULL, &base, &len, NULL) == 0);
	}

	/* sr_find_func：落在 alpha 内 -> 命中 */
	{
		uint64_t base = 0, len = 0;
		const char *name = NULL;
		CHECK(sr_find_func(syms, n, 0xffffffc080100100ULL, &base, &len, &name) == 1);
		CHECK_EQ_U64(base, 0xffffffc080100000ULL);
		CHECK_EQ_U64(len, 0xffffffc080200000ULL - 0xffffffc080100000ULL);
		CHECK(name && strcmp(name, "alpha") == 0);
	}
}

static void test_fuzz(void)
{
	/*
	 * 随机 2000 组 (函数基址, slide, off)：必须 100% 精确还原。
	 * 这正是真机上的用法——off（函数内调用点偏移）在不同内核/不同编译下
	 * 都会漂移，解算器不能对 off 有任何先验假设。
	 */
	int i;
	int hits = 0;

	for (i = 0; i < 2000; i++) {
		uint64_t func_va = 0xffffffc080000000ULL + (rng_next() % 0x1000000ULL) * 0x10ULL;
		uint64_t slide = (rng_next() % 0x1000ULL) * SR_SLIDE_ALIGN;
		uint64_t off = rng_next() % 0x1000ULL;
		uint64_t len = 0x1000 + (rng_next() % 0x1000ULL);
		uint64_t call_site = func_va + slide + off;
		uint64_t got_slide = 0, got_off = 0;

		if (sr_resolve_slide(func_va, len, call_site, &got_slide, &got_off) != 1) {
			continue;
		}
		hits++;
		if (got_slide != slide || got_off != off) {
			g_checks++;
			g_failures++;
			printf("  FAIL  fuzz %d: slide got 0x%llx want 0x%llx, "
			       "off got 0x%llx want 0x%llx\n",
			       i, (unsigned long long)got_slide, (unsigned long long)slide,
			       (unsigned long long)got_off, (unsigned long long)off);
			break;
		}
	}
	g_checks++;
	if (hits != 2000) {
		g_failures++;
		printf("  FAIL  fuzz: only %d/2000 resolved\n", hits);
	}
}

int main(void)
{
	printf("== slide_resolve ==\n");

	printf("- exact recovery (by name)\n");
	test_exact_recovery();

	printf("- low-level resolve + guards\n");
	test_low_level_resolve();

	printf("- negatives\n");
	test_negatives();

	printf("- fuzz (2000 random cases)\n");
	test_fuzz();

	printf("== %d checks, %d failures ==\n", g_checks, g_failures);
	return g_failures ? 1 : 0;
}
