/*
 * calib_core.c - pure-compute part of the calibration algorithm (no platform deps, host unit-testable)
 *
 * Corresponds to the python in the PC reference implementation:
 *   calib_scan_kitimer / calib_top_values  <- tools/slide_from_timers.py scans()
 *   calib_solve_lmap                        <- tools/solve_lmap.py solve loop
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "calib.h"

/* Scan range of solve_lmap.py: PKJ110 DRAM starts at 0x80000000,
 * linear map base = PAGE_OFFSET - 0x80000000, must not start scanning from 0xFFFFFF8000000000 */
#ifndef SCAN_START
#define SCAN_START UINT64_C(0xFFFFFF7E00000000)
#endif
#ifndef LMAP_END
#define LMAP_END   UINT64_C(0xFFFFFF8C00000000)
#endif
#ifndef SCAN_STEP
#define SCAN_STEP  UINT64_C(0x200000)
#endif

static uint64_t rd_u64(const uint8_t *p)
{
	uint64_t v = 0;
	memcpy(&v, p, 8);
	return v;
}

static int cmp_u64(const void *a, const void *b)
{
	uint64_t x = *(const uint64_t *)a;
	uint64_t y = *(const uint64_t *)b;
	return (x > y) - (x < y);
}

static int cmp_run(const void *a, const void *b)
{
	const struct calib_run *x = a;
	const struct calib_run *y = b;
	if (x->count != y->count)
		return (int)((int64_t)y->count - (int64_t)x->count);
	return (x->value > y->value) - (x->value < y->value);
}

/* 高 16 位是 0xFFFF 才算内核地址（arm64 的内核 text 与 linear map 都在这个窗口里） */
static int is_kernel_addr(uint64_t v)
{
	return (v >> 48) == 0xFFFFULL;
}

/*
 * kmem_cache_alloc 的 raw 记录布局随内核版本变化（include/trace/events/kmem.h）：
 *
 *   ≤ 6.6（没有 name 字段）：
 *       site@0  ptr@8  bytes_req@16  bytes_alloc@24  gfp_flags@32  node@40  accounted@41
 *   ≥ 6.18（新增 __string(name, s->name)，在 ptr 与 bytes_req 之间插入 8 字节
 *            动态字符串描述符 = (u32 offset << 32) | u32 len）：
 *       site@0  ptr@8  name_desc@16  bytes_req@24  bytes_alloc@32  gfp_flags@40
 *            node@48  accounted@52
 *
 * 两版里 bytes_req 都与 bytes_alloc 相邻，所以以「bytes_req 的位置 k」为锚点，
 * 向前试两组候选 (site, ptr)：
 *      A：site@k-16, ptr@k-8      —— ≤ 6.6
 *      B：site@k-24, ptr@k-16     —— ≥ 6.18
 * 哪一组的 site 与 ptr **同时**是内核地址就采用哪一组。错配的那组必然被否：
 *      · 6.18 下 A 组的 ptr 读到的是 name_desc（小整数，不在内核地址窗口里）
 *      · 6.6  下 B 组的 site 读到的是 trace 记录头（pid 之类的小整数）
 * 于是同一份代码在 6.6 与 6.18 上都能正确解析，不需要按版本号分支。
 */
struct calib_kmem_rec *calib_scan_kmem_recs(const uint8_t *d, size_t n,
					    const uint64_t *sizes, size_t n_sizes,
					    size_t *out_n)
{
	size_t cap = 4096, cnt = 0, k;
	struct calib_kmem_rec *out;

	*out_n = 0;
	if (!d || !n)
		return NULL;

	/* default candidate k_itimer sizes (non-empty, host unit-testable) */
	static const uint64_t DEFAULT_SIZES[] = {0x108, 0x100, 0x110, 0x118};
	if (!sizes || n_sizes == 0) {
		sizes = DEFAULT_SIZES;
		n_sizes = sizeof(DEFAULT_SIZES) / sizeof(DEFAULT_SIZES[0]);
	}

	out = malloc(cap * sizeof(*out));
	if (!out)
		return NULL;

	/* k+16 <= n：req@k / alloc@k+8 都要读满 8 字节 */
	for (k = 24; k + 16 <= n; k++) {
		uint64_t req = rd_u64(d + k);
		uint64_t alloc = rd_u64(d + k + 8);
		uint64_t site = 0, ptr = 0;
		size_t si;
		int matched = 0;

		for (si = 0; si < n_sizes; si++) {
			if (req == sizes[si]) {
				matched = 1;
				break;
			}
		}
		if (!matched)
			continue;

		/* 布局 A（≤ 6.6） */
		site = rd_u64(d + k - 16);
		ptr = rd_u64(d + k - 8);
		if (!is_kernel_addr(site) || !is_kernel_addr(ptr)) {
			/* 布局 B（≥ 6.18）：ptr/name_desc 再往前挪 8 字节 */
			uint64_t desc;

			site = 0;
			ptr = 0;
			if (k < 24)
				continue;
			site = rd_u64(d + k - 24);
			ptr = rd_u64(d + k - 16);
			desc = rd_u64(d + k - 8);
			/* name 描述符。真机实测（madrid / 6.18.21-android17）：
			 *   0x00000012003d -> offset=0x3d(61), size=0x12(18)   "skbuff_head_cache"
			 *   0x00000007003d -> offset=0x3d(61), size=0x07(7)    "dentry"
			 * 即「u16 offset + u16 size + 4 字节填充」，offset 是 entry 内动态数据的
			 * 起点（61 = 8(hdr)+8(site)+8(ptr)+4(desc)+4(pad)+8(req)+8(alloc)
			 *            +8(gfp)+4(node)+1(accounted)）。
			 * 也有内核把描述符写成两个 u32，所以两种都认：
			 *   变体 A：低 16 位 offset、高 16 位 size（高 32 位必须为 0）
			 *   变体 B：低 32 位 offset、高 32 位 size（高 32 位必须非 0）
			 * 这条约束同时挡住了「恰好撞上 alloc 字段」造成的假阳性：
			 * 那种位置上的 desc 其实是尺寸值（如 248），size=0。 */
			{
				uint64_t off16 = desc & 0xFFFFu;
				uint64_t size16 = (desc >> 16) & 0xFFFFu;
				uint64_t off32 = desc & 0xFFFFFFFFu;
				uint64_t size32 = desc >> 32;
				int ok16 = (size32 == 0) && off16 >= 32u && off16 < 0x10000u &&
					    size16 >= 1u && size16 <= 64u;
				int ok32 = (size32 != 0) && off32 >= 32u && off32 < 0x10000u &&
					    size32 >= 1u && size32 <= 64u;

				if (!is_kernel_addr(site) || !is_kernel_addr(ptr) ||
				    (!ok16 && !ok32))
					continue;
			}
		}
		if ((ptr & 7))
			continue;

		if (cnt == cap) {
			struct calib_kmem_rec *p = realloc(out, (cap * 2) * sizeof(*out));
			if (!p)
				break;
			out = p;
			cap *= 2;
		}
		out[cnt].site = site;
		out[cnt].ptr = ptr;
		out[cnt].req = req;
		out[cnt].alloc = alloc;
		cnt++;
	}
	*out_n = cnt;
	return out;
}

/*
 * Scan raw trace for kmem_cache_alloc records (legacy wrapper).
 *
 * 旧的取值方式（layout A：site@k-16 / ptr@k-8 / req@k / alloc@k+8）在 6.18 上
 * 会整体错位 8 字节（6.18 给 kmem_cache_alloc 加了 name 动态字符串字段），
 * 导致每条记录都被判为「ptr 不是内核地址」而丢弃。
 * 现在底层改用布局自适应的 calib_scan_kmem_recs()，这里保留
 * 「req == alloc」这个老不变式给原有调用方（calib_b / 老单测）。
 */
uint64_t *calib_scan_kitimer(const uint8_t *d, size_t n, uint64_t site_link,
			     int want_site, int filter_site,
			     const uint64_t *sizes, size_t n_sizes, size_t *out_n)
{
	size_t nrec = 0, i, cnt = 0;
	struct calib_kmem_rec *recs;
	uint64_t *out;

	*out_n = 0;
	recs = calib_scan_kmem_recs(d, n, sizes, n_sizes, &nrec);
	if (!recs)
		return NULL;

	out = malloc((nrec ? nrec : 1) * sizeof(*out));
	if (!out) {
		free(recs);
		return NULL;
	}
	for (i = 0; i < nrec; i++) {
		/* 保留原来的 req==alloc 不变式 */
		if (recs[i].req != recs[i].alloc)
			continue;
		if (filter_site && recs[i].site != site_link)
			continue;
		out[cnt++] = want_site ? recs[i].site : recs[i].ptr;
	}
	free(recs);
	*out_n = cnt;
	return out;
}

/*
 * 解析内核 %pS 打印的 call_site 符号串："FUNC+0xOFF/LEN"。
 *
 * 两个坑（都踩过）：
 *   · '+' 后面紧跟 "0x"，所以第一个十六进制数字在 q+3 而不是 q+2；
 *     写成 strtoull(q + 2, ...) 时 "x" 不是合法十六进制字符 → 偏移恒为 0。
 *   · 符号名与偏移必须分开，名字里不能留 "+0x..."。
 */
int calib_parse_psym(const char *text, char *out_sym, size_t sym_cap,
		     uint64_t *out_off)
{
	const char *plus;
	size_t len;

	if (!text || !out_sym || !sym_cap)
		return 0;
	plus = strchr(text, '+');
	if (!plus)
		return 0;
	len = (size_t)(plus - text);
	if (len == 0 || len >= sym_cap)
		return 0;
	memcpy(out_sym, text, len);
	out_sym[len] = 0;

	if (out_off) {
		/* plus[1] 应为 '0'，plus[2] 为 'x'，第一个数字在 plus[3] */
		if (plus[1] != '0' || (plus[2] != 'x' && plus[2] != 'X')) {
			*out_off = 0;
		} else {
			*out_off = strtoull(plus + 3, NULL, 16);
		}
	}
	return 1;
}

/* count the most frequent values (descending), return the number written */
size_t calib_top_values(uint64_t *arr, size_t n, struct calib_run *out,
			size_t out_cap)
{
	size_t i, m = 0;
	if (!n || !arr)
		return 0;
	qsort(arr, n, sizeof(*arr), cmp_u64);
	for (i = 0; i < n;) {
		size_t j = i + 1;
		while (j < n && arr[j] == arr[i])
			j++;
		if (m < out_cap) {
			out[m].value = arr[i];
			out[m].count = (int)(j - i);
			m++;
		}
		i = j;
	}
	qsort(out, m, sizeof(*out), cmp_run);
	return m;
}

/* 候选分配点按 count 降序（同 count 时按 site 升序，保证结果可复现） */
static int cmp_site_cand(const void *a, const void *b)
{
	const struct calib_site_cand *x = a, *y = b;

	if (x->count != y->count)
		return (int)((int64_t)y->count - (int64_t)x->count);
	return (x->site > y->site) - (x->site < y->site);
}

/*
 * 挑出可信的分配点（6.18 适配新增）。
 * 详细判据见 calib.h 的注释。
 */
int calib_pick_trusted_site(const struct calib_site_cand *cands, size_t n,
			    uint64_t slide, uint64_t anchor_base,
			    uint64_t anchor_len, uint64_t *out_site)
{
	struct calib_site_cand *sorted;
	size_t i;

	if (!cands || !out_site)
		return 0;
	*out_site = 0;
	if (!n)
		return 0;

	sorted = malloc(n * sizeof(*sorted));
	if (!sorted)
		return 0;
	memcpy(sorted, cands, n * sizeof(*sorted));
	qsort(sorted, n, sizeof(*sorted), cmp_site_cand);

	for (i = 0; i < n; i++) {
		const struct calib_site_cand *c = &sorted[i];
		uint64_t unreloc;

		if (c->count <= 0)
			continue;
		/* 1) 必须是内核 text 地址 */
		if (!is_kernel_addr(c->site))
			continue;
		if (c->site < slide)
			continue;
		unreloc = c->site - slide;
		/* 2) 必须落在它自称的函数区间里 */
		if (!c->func_base || !c->func_len)
			continue;
		if (unreloc < c->func_base || unreloc >= c->func_base + c->func_len)
			continue;
		/* 3) 语义自证：函数名命中关键字，或与 profile 锚点同函数 */
		if (!c->name_hit) {
			if (!anchor_base || !anchor_len)
				continue;
			if (c->func_base != anchor_base || c->func_len != anchor_len)
				continue;
		}
		*out_site = c->site;
		free(sorted);
		return 1;
	}
	free(sorted);
	return 0;
}

/* binary search over a sorted PFN set (replaces Python's set lookup) */
static int pfn_in(const uint64_t *set, size_t n, uint64_t v)
{
	size_t lo = 0, hi = n;
	while (lo < hi) {
		size_t mid = (lo + hi) / 2;
		if (set[mid] == v)
			return 1;
		if (set[mid] < v)
			lo = mid + 1;
		else
			hi = mid;
	}
	return 0;
}

/*
 * Scan candidate linear map bases L (2MiB steps); the correct L makes every slab page
 * derived PFN land in the order-1 allocation set. Returns the L with the most hits.
 */
uint64_t calib_solve_lmap(const uint64_t *pages, size_t n_pages,
			  const uint64_t *pfns, size_t n_pfns,
			  uint64_t *best_score)
{
	uint64_t L;
	uint64_t best_base = 0;
	uint64_t best = 0;

	*best_score = 0;
	if (!n_pages || !n_pfns)
		return 0;
	for (L = SCAN_START; L < LMAP_END; L += SCAN_STEP) {
		uint64_t score = 0;
		size_t p;
		int bad = 0;
		for (p = 0; p < n_pages; p++) {
			if (pages[p] < L) {
				bad = 1;
				break;
			}
			if (pfn_in(pfns, n_pfns, (pages[p] - L) >> 12))
				score++;
		}
		if (bad)
			continue;
		if (score > best) {
			best = score;
			best_base = L;
		}
	}
	*best_score = best;
	return best_base;
}

/* convert object virtual addresses into deduplicated slab pages (order-1 = 8KB, so 8K aligned) */
size_t calib_pages_from_ptrs(uint64_t *ptrs, size_t n_ptrs, uint64_t *pages)
{
	size_t n = 0, i, j;
	if (!n_ptrs)
		return 0;
	qsort(ptrs, n_ptrs, sizeof(*ptrs), cmp_u64);
	for (i = 0; i < n_ptrs;) {
		size_t k = i + 1;
		while (k < n_ptrs && ptrs[k] == ptrs[i])
			k++;
		pages[n++] = ptrs[i] & ~UINT64_C(0x1fff);
		i = k;
	}
	qsort(pages, n, sizeof(*pages), cmp_u64);
	j = 0;
	for (i = 0; i < n; i++) {
		if (j == 0 || pages[j - 1] != pages[i])
			pages[j++] = pages[i];
	}
	return j;
}
