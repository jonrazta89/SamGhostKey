#ifndef CALIB_H
#define CALIB_H

#include <stddef.h>
#include <stdint.h>

/*
 * calib.h - calib_a / calib_b
 *
 * Corresponds to the PC reference implementation:
 *   calib_a = scripts/capture_site.sh + tools/slide_from_timers.py
 *           -> derives this boot's KASLR slide
 *   calib_b = scripts/calib.sh         + tools/solve_lmap.py
 *           -> derives this boot's linear map base page_offset
 *
 * Results are persisted (read by the host Shizuku UserService):
 *   $CVE98260_HOME/slide.txt          content like 0x1f200000
 *   $CVE98260_HOME/page_offset.txt    content like 0xffffff7f80000000
 *   $CVE98260_HOME/page_offset.score  content like "132/150" or "fallback"
 *
 * calib_core.c holds the platform-independent pure-compute part (host unit-testable),
 * calib.c holds the tracefs capture and flow orchestration.
 */

int calib_a_main(int argc, char **argv);
int calib_b_main(int argc, char **argv);

/* a value and its occurrence count (output of calib_top_values) */
struct calib_run {
	uint64_t value;
	int count;
};

/*
 * linear map base solving (core of solve_lmap.py).
 * Returns the base with the most hits; *best_score is the hit count (0 means no solution).
 * pfns must already be sorted ascending.
 */
uint64_t calib_solve_lmap(const uint64_t *pages, size_t n_pages,
			  const uint64_t *pfns, size_t n_pfns,
			  uint64_t *best_score);

/*
 * raw trace record scanning (core of slide_from_timers.py).
 * Returns a malloc'd array (call sites when want_site=1, else object virtual addresses),
 * count written to *out_n. When filter_site=1 only records with site == site_link are kept.
 *
 * sizes / n_sizes is the candidate set of sizeof(struct k_itimer) values to accept.
 * A record matches when req == alloc == sizes[si] for some si (the original req==alloc
 * invariant is preserved, only widened to the candidate set). Pass NULL/0 to use the
 * built-in default set {0x108,0x100,0x110,0x118} so host unit tests stay runnable.
 */
uint64_t *calib_scan_kitimer(const uint8_t *data, size_t len,
			     uint64_t site_link, int want_site,
			     int filter_site,
			     const uint64_t *sizes, size_t n_sizes,
			     size_t *out_n);

/* 一条 kmem_cache_alloc 记录（从 raw trace 解出来的字段） */
struct calib_kmem_rec {
	uint64_t site;   /* 运行期 call_site（_RET_IP_） */
	uint64_t ptr;    /* 分配到的对象地址 */
	uint64_t req;    /* bytes_req  (= slab 的 object_size) */
	uint64_t alloc;  /* bytes_alloc(= slab 的 size) */
};

/*
 * 解析 raw trace 里的 kmem_cache_alloc 记录，**布局自适应**。
 *
 * 布局随内核版本变（include/trace/events/kmem.h）：
 *   ≤ 6.6 ：site@0 ptr@8 bytes_req@16 bytes_alloc@24 ...
 *   ≥ 6.18：site@0 ptr@8 name_desc@16 bytes_req@24 bytes_alloc@32 ...
 *          （6.18 给 kmem_cache_alloc 加了 __string(name, s->name)，
 *            在 ptr 与 bytes_req 之间插了 8 字节动态字符串描述符）
 *
 * 两版里 bytes_req 都与 bytes_alloc 相邻，所以以 bytes_req 的位置 k 为锚点，
 * 向前试两组候选 (site, ptr)，哪一组同时满足「site 与 ptr 都是内核地址」
 * 就用哪一组 —— 错配的那组必然被否（6.18 下读到的是 name_desc 小整数，
 * 6.6 下读到的是 trace 记录头小整数）。
 *
 * 返回 malloc 的数组（调用方 free），条数写入 *out_n。
 * 这里**不**要求 req == alloc：bytes_req 是 slab 的 object_size，
 * bytes_alloc 是 slab 的 size，两者是否相等取决于 slab 实现；
 * 需要该不变式的老调用方请用 calib_scan_kitimer()。
 */
struct calib_kmem_rec *calib_scan_kmem_recs(const uint8_t *data, size_t len,
					    const uint64_t *sizes, size_t n_sizes,
					    size_t *out_n);

/* 一个候选分配点（运行期 call_site 及其在 kallsyms 里的归属） */
struct calib_site_cand {
	uint64_t site;       /* 运行期 call_site（_RET_IP_，含 slide） */
	int      count;      /* 该站点在 raw trace 里出现的次数 */
	uint64_t func_base;  /* 站点所属函数的**未重定位**基址（0 = 未知） */
	uint64_t func_len;   /* 该函数长度 */
	int      name_hit;   /* 该函数名是否命中语义关键字（cred / task 等） */
};

/*
 * 从候选分配点里挑出「可信」的那一个（6.18 适配新增，纯计算，可宿主单测）。
 *
 * 为什么需要这一步：cred / task_struct 的 slab 大小可能被别的专用缓存共享，
 * 光按「尺寸最频」挑站点会挑到别人的分配点，于是 exploit 阶段按站点过滤
 * trace 时过滤不到真正的 cred 对象（表现为「注入了但 uid 没变成 0」）。
 *
 * 可信判据（全部满足）：
 *   1. site 必须是内核 text 地址（高 16 位为 0xFFFF）；
 *   2. 反算出的未重定位地址 site-slide 必须落在 func_base..func_base+func_len；
 *   3. 语义自证满足其一：
 *        · 函数名命中关键字（name_hit），
 *        · 或站点所属函数与 profile 锚点（anchor_base..anchor_base+anchor_len）
 *          是同一个函数 —— 这条允许 LTO 把 prepare_creds 内联进别的函数。
 *
 * 候选按 count 降序考察，返回第一个可信者。
 * 返回 1 成功（*out_site = 运行期 call_site），0 表示没有可信候选
 * （调用方应退回「只按尺寸匹配」的旧行为，不写结果文件）。
 */
int calib_pick_trusted_site(const struct calib_site_cand *cands, size_t n,
			    uint64_t slide, uint64_t anchor_base,
			    uint64_t anchor_len, uint64_t *out_site);

/*
 * 解析内核 %pS 打印的 call_site 符号串（纯计算，可宿主单测）。
 *
 * 输入形如 "do_timer_create+0xe8/0x508"（符号名 + 函数内偏移 / 符号大小）。
 * 输出：out_sym = "do_timer_create"，out_off = 0xe8。
 *
 * 这里单独立一个函数，是因为两个非常隐蔽的坑都出在这一行解析上：
 *   1. '+' 后面紧跟的是 "0x"，所以第一个十六进制数字在 **q+3** 而不是 q+2。
 *      写成 strtoull(q + 2, ...) 时 "x" 不是合法十六进制字符，偏移恒为 0。
 *   2. 符号名与偏移必须分开存，不能把 "+0x..." 留在名字里。
 *
 * 返回 1 成功，0 表示格式不认识（没有 '+'，或偏移不是 0x 形式）。
 */
int calib_parse_psym(const char *text, char *out_sym, size_t sym_cap,
		     uint64_t *out_off);

/* count the most frequent values (descending), return the number written */
size_t calib_top_values(uint64_t *arr, size_t n, struct calib_run *out,
			size_t out_cap);

/*
 * convert object virtual addresses into deduplicated slab pages (order-1 = 8KB, 8K aligned).
 * pages must be caller-allocated with at least n_ptrs uint64_t. Returns the page count.
 */
size_t calib_pages_from_ptrs(uint64_t *ptrs, size_t n_ptrs, uint64_t *pages);

#endif /* CALIB_H */
