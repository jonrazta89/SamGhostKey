#!/usr/bin/env bash
#
# T1: 在宿主机（不是 Android 设备）上编译并运行 calib_core 的纯计算单测。
#
# 为什么要单独跑：calib_core.c 里的四个函数决定 KASLR slide / page_offset 的
# 解算结果，逻辑漂移在真机上只表现为「exploit 静默失败」，很难定位。它们不依赖
# tracefs / Android，任何有 C 编译器的机器都能验证。
#
# 用法：
#   app/src/test/cpp/run_c_tests.sh          # 自动选择 clang / gcc
#   CC=clang app/src/test/cpp/run_c_tests.sh # 指定编译器
#
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../../.." && pwd)"
CPP_DIR="$ROOT/app/src/main/cpp"
TEST_DIR="$ROOT/app/src/test/cpp"

if [ -z "${CC:-}" ]; then
    for c in clang gcc cc; do
        if command -v "$c" >/dev/null 2>&1; then
            CC="$c"
            break
        fi
    done
fi
if [ -z "${CC:-}" ]; then
    echo "error: 找不到 C 编译器（clang / gcc / cc），请先安装或设置 CC=" >&2
    exit 2
fi

OUT_DIR="$TEST_DIR/.build"
mkdir -p "$OUT_DIR"

case "$(uname -s 2>/dev/null || echo unknown)" in
    MINGW*|MSYS*|CYGWIN*) BIN_SUFFIX=".exe" ;;
    *) BIN_SUFFIX="" ;;
esac

echo "== 编译测试 =="
echo "   CC = $CC"

# T1-a：calib_core 的纯计算单测（slide_from_timers.py / solve_lmap.py 的核心）
"$CC" -std=c11 -O1 -g -Wall -Wextra \
    -I "$CPP_DIR" \
    "$CPP_DIR/calib_core.c" \
    "$TEST_DIR/test_calib_core.c" \
    -o "$OUT_DIR/test_calib_core$BIN_SUFFIX"

# T1-b：slide_resolve 的 KASLR slide 精确解算单测（6.18 适配新增）
"$CC" -std=c11 -O1 -g -Wall -Wextra \
    -I "$CPP_DIR" \
    "$CPP_DIR/slide_resolve.c" \
    "$TEST_DIR/test_slide_resolve.c" \
    -o "$OUT_DIR/test_slide_resolve$BIN_SUFFIX"

# T1-c：ksu_script 的接管脚本生成单测（KSU 候选阶梯）
"$CC" -std=c11 -O1 -g -Wall -Wextra \
    -I "$CPP_DIR" \
    "$CPP_DIR/ksu_script.c" \
    "$TEST_DIR/test_ksu_script.c" \
    -o "$OUT_DIR/test_ksu_script$BIN_SUFFIX"

# T1-d：rawscan 的增量记录扫描单测（uaf 受害者选取）
"$CC" -std=c11 -O1 -g -Wall -Wextra \
    -I "$CPP_DIR" \
    "$CPP_DIR/rawscan.c" \
    "$TEST_DIR/test_rawscan.c" \
    -o "$OUT_DIR/test_rawscan$BIN_SUFFIX"

# T1-e：memguard 的 trace 环形缓冲内存预算单测（重启风险防护）
"$CC" -std=c11 -O1 -g -Wall -Wextra \
    -I "$CPP_DIR" \
    "$CPP_DIR/memguard.c" \
    "$TEST_DIR/test_memguard.c" \
    -o "$OUT_DIR/test_memguard$BIN_SUFFIX"

echo "== 运行测试 =="
"$OUT_DIR/test_calib_core$BIN_SUFFIX"
"$OUT_DIR/test_slide_resolve$BIN_SUFFIX"
"$OUT_DIR/test_rawscan$BIN_SUFFIX"
"$OUT_DIR/test_memguard$BIN_SUFFIX"
(cd "$OUT_DIR" && "$OUT_DIR/test_ksu_script$BIN_SUFFIX")

# 生成的接管脚本做一次 shell 语法检查（脚本在设备上由 rootd 以 uid=0 执行，
# 语法错误只会在设备上表现为「没 su」，这里提前拦一道）
if command -v sh >/dev/null 2>&1; then
    if sh -n "$OUT_DIR/ksu_takeover_test.sh"; then
        echo "  ok    ksu_takeover_test.sh: shell syntax valid"
    else
        echo "  FAIL  ksu_takeover_test.sh: shell syntax error" >&2
        exit 1
    fi
fi
