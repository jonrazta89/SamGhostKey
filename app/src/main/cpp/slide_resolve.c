/*
 * slide_resolve.c — 见 slide_resolve.h 的说明。
 */
#include "slide_resolve.h"

#include <string.h>

int sr_find_func(const sr_sym *syms, size_t n, uint64_t addr,
                 uint64_t *out_base, uint64_t *out_len, const char **out_name)
{
    size_t lo = 0, hi = n, idx;

    if (!syms || n == 0)
        return 0;

    /* 二分找最后一个 va <= addr */
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (syms[mid].va <= addr)
            lo = mid + 1;
        else
            hi = mid;
    }
    if (lo == 0)
        return 0;
    idx = lo - 1;

    if (out_base)
        *out_base = syms[idx].va;
    if (out_len) {
        uint64_t end = (idx + 1 < n) ? syms[idx + 1].va : (syms[idx].va + SR_FUNC_MAX_LEN);
        uint64_t len = end - syms[idx].va;
        *out_len = len;
    }
    if (out_name)
        *out_name = syms[idx].name;
    return 1;
}

int sr_resolve_slide(uint64_t func_va, uint64_t func_len, uint64_t call_site,
                     uint64_t *out_slide, uint64_t *out_off)
{
    uint64_t delta, off, slide;

    if (func_len == 0 || func_len >= SR_FUNC_MAX_LEN)
        return -1;
    if (call_site < func_va)
        return 0;

    delta = call_site - func_va;
    off = delta % SR_SLIDE_ALIGN;
    if (off >= func_len)
        return 0;                       /* 与「调用点落在该函数内」不自洽 */

    slide = delta - off;
    if (slide >= SR_SLIDE_MAX)
        return 0;

    if (out_slide)
        *out_slide = slide;
    if (out_off)
        *out_off = off;
    return 1;
}

int sr_resolve_slide_syms(const sr_sym *syms, size_t n, uint64_t call_site,
                          uint64_t *out_slide, uint64_t *out_unreloc_site)
{
    uint64_t base = 0, len = 0, slide = 0, off = 0;

    if (!sr_find_func(syms, n, call_site, &base, &len, NULL))
        return 0;
    if (!sr_resolve_slide(base, len, call_site, &slide, &off))
        return 0;
    if (out_slide)
        *out_slide = slide;
    if (out_unreloc_site)
        *out_unreloc_site = base + off;
    return 1;
}

int sr_resolve_slide_named(const sr_sym *syms, size_t n, const char *func_name,
                           uint64_t call_site, uint64_t *out_slide,
                           uint64_t *out_unreloc_site)
{
    size_t i;
    uint64_t base = 0, len = 0, slide = 0, off = 0;

    if (!syms || n == 0 || !func_name)
        return 0;

    for (i = 0; i < n; i++) {
        if (syms[i].name && strcmp(syms[i].name, func_name) == 0) {
            size_t j;
            base = syms[i].va;
            /* 函数长度 = 到**下一个不同 VA** 的距离。
             * kallsyms 里同一地址常有多个别名（_text/__pi__text…），
             * 直接取下一个符号会算出 0 长度。 */
            len = SR_FUNC_MAX_LEN;
            for (j = i + 1; j < n; j++) {
                if (syms[j].va != base) {
                    len = syms[j].va - base;
                    break;
                }
            }
            break;
        }
    }
    if (i == n)
        return 0;                       /* 表里没有这个函数 */

    if (!sr_resolve_slide(base, len, call_site, &slide, &off))
        return 0;
    if (out_slide)
        *out_slide = slide;
    if (out_unreloc_site)
        *out_unreloc_site = base + off;
    return 1;
}
