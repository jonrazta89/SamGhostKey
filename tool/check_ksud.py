#!/usr/bin/env python3
"""校验内置 assets/ksu/ksud 是否与 assets/ksu/ksud.manifest 记录一致。

纯标准库，无第三方依赖。三种用法：

    python3 tool/check_ksud.py            # 校验；不一致退出码非 0
    python3 tool/check_ksud.py --emit      # 打印当前二进制的 sha256/size（供更新清单）
    python3 tool/check_ksud.py --update     # 用当前二进制的实测值就地改写清单的 sha256/size
    python3 tool/check_ksud.py --file /path/to/ksud   # 对指定二进制校验/取值

换 ksud 二进制后：先跑 `--update`（或 `--emit` 手动核对），并同步清单里的
version / version_code / provenance 等人工字段。
"""

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
ASSET = REPO / "app/src/main/assets/ksu/ksud"
MANIFEST = REPO / "app/src/main/assets/ksu/ksud.manifest"


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_manifest(path: Path) -> dict:
    if not path.is_file():
        sys.exit(f"manifest not found: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def check(binary: Path, manifest: dict) -> int:
    if not binary.is_file():
        print(f"[FAIL] 二进制缺失: {binary}")
        return 1
    actual_size = binary.stat().st_size
    actual_sha = sha256_of(binary)
    exp_size = manifest.get("size_bytes")
    exp_sha = (manifest.get("sha256") or "").lower()

    ok = True
    if exp_size is None or int(exp_size) != actual_size:
        print(f"[FAIL] size 不符: 期望 {exp_size}, 实际 {actual_size}")
        ok = False
    if exp_sha != actual_sha:
        print(f"[FAIL] sha256 不符:\n        期望 {exp_sha}\n        实际 {actual_sha}")
        ok = False
    if ok:
        print(
            f"[OK] ksud {manifest.get('fork')} {manifest.get('version')}"
            f" (code {manifest.get('version_code')}) — "
            f"size={actual_size} sha256={actual_sha}"
        )
    return 0 if ok else 1


def update_manifest(manifest_path: Path, binary: Path) -> int:
    if not binary.is_file():
        sys.exit(f"binary not found: {binary}")
    text = manifest_path.read_text(encoding="utf-8")
    sha = sha256_of(binary)
    size = binary.stat().st_size
    new = re.sub(r'("sha256"\s*:\s*")[0-9a-fA-F]+(")', rf"\g<1>{sha}\g<2>", text)
    new = re.sub(r'("size_bytes"\s*:\s*)\d+', rf"\g<1>{size}", new)
    if new == text:
        sys.exit("清单里没有可改写的 sha256/size 字段，请手动编辑")
    manifest_path.write_text(new, encoding="utf-8")
    print(f"[UPDATED] 已写入 sha256={sha} size={size}（记得同步 version/provenance）")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="校验/更新内置 ksud 版本清单")
    ap.add_argument("--file", type=Path, default=ASSET, help="ksud 二进制路径（默认内置 asset）")
    ap.add_argument("--manifest", type=Path, default=MANIFEST, help="清单路径")
    ap.add_argument("--emit", action="store_true", help="仅打印实测 sha256/size")
    ap.add_argument("--update", action="store_true", help="用实测值就地改写清单")
    args = ap.parse_args()

    if args.emit:
        print(f"sha256={sha256_of(args.file)}")
        print(f"size_bytes={args.file.stat().st_size}")
        return 0
    if args.update:
        return update_manifest(args.manifest, args.file)
    return check(args.file, load_manifest(args.manifest))


if __name__ == "__main__":
    sys.exit(main())
