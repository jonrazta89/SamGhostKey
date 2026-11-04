#!/system/bin/sh
# 取证脚本：抓「自动重启 / 内核崩溃」到底是谁干的。
#
# 用法（三选一，按权限从高到低）：
#   adb shell su -c sh /data/local/tmp/collect_reboot_evidence.sh   # 有 root 时最佳
#   adb shell sh /data/local/tmp/collect_reboot_evidence.sh          # 无 root：仍能拿 dmesg/logcat
#   设备上直接：su -c sh collect_reboot_evidence.sh
#
# 输出：/data/local/tmp/cve98260-app/reboot_evidence.txt
#
# ⚠️ 运行时机：
#   · pstore(ramoops) 存的是**上一次**崩溃的内核日志，再下次开机会被覆盖。
#   · 证据要能回答：
#       1) 是不是真内核 oops？   -> pstore 有没有 "Unable to handle kernel" / "BUG:"
#       2) 是不是 userspace 崩？   -> dropbox 的 system_server_crash / ANR
#       3) 页回收被抢还是自伤？   -> app 运行日志的 [stream_backfill] hit=0/1
#       4) 是不是 SELinux AVC 洪水？-> dmesg 里 avc: denied 的频率 + audit_lost

OUT=/data/local/tmp/cve98260-app/reboot_evidence.txt
mkdir -p "$(dirname "$OUT")"
: > "$OUT"

say() { echo "===== $* =====" >> "$OUT"; }

say "meta"
{
  echo "date: $(date 2>/dev/null)"
  echo "whoami: $(id 2>/dev/null)"
  echo "uptime: $(cat /proc/uptime 2>/dev/null)"
  echo "kernel: $(uname -a 2>/dev/null)"
  echo "modules:"; grep -iE 'kernelsu|ksu' /proc/modules 2>/dev/null
} >> "$OUT" 2>&1

# ---------------------------------------------------------------- A) 内核 panic
say "pstore (ramoops = 上一次内核崩溃日志)"
ls -l /sys/fs/pstore/ 2>&1 >> "$OUT"
for f in /sys/fs/pstore/*; do
  [ -f "$f" ] || continue
  say "pstore file: $f"
  cat "$f" 2>&1 | tail -600 >> "$OUT"
done

say "avc 洪水：全量统计（最早 40 条 + 总条数）"
# audit_lost 每次内核启动清零。若开机后不久就很大，说明**开机后到本次运行之间**
# 已经有一轮 AVC 洪水 —— 这是当前唯一未解的问题，必须抓最早的记录而不是尾部。
dmesg 2>&1 | grep 'avc:  denied' | head -40 >> "\$OUT" 2>&1
echo "--- avc total:" >> "\$OUT"
dmesg 2>&1 | grep -c 'avc:  denied' >> "\$OUT" 2>&1
echo "--- audit_lost all (first 20):" >> "\$OUT"
dmesg 2>&1 | grep 'audit_lost' | head -20 >> "\$OUT" 2>&1
echo "--- boot_id / uptime:" >> "\$OUT"
cat /proc/sys/kernel/random/boot_id 2>&1 >> "\$OUT"
cat /proc/uptime 2>&1 >> "\$OUT"

say "dmesg tail"
dmesg 2>&1 | tail -400 >> "$OUT"

# SELinux AVC 洪水检测（残留 rootd 每 200ms 触发一次 -> audit 队列溢出）
say "SELinux avc / audit 洪水统计"
dmesg 2>&1 | grep -c 'avc:  denied' >> "$OUT" 2>&1
dmesg 2>&1 | grep 'audit_lost' | tail -5 >> "$OUT" 2>&1
dmesg 2>&1 | grep 'avc:  denied' | tail -20 >> "$OUT" 2>&1

# ---------------------------------------------------------------- B) userspace 崩溃
# 注意：dropbox 文件名带时间戳（system_server_crash@1793635261267.txt），
# 必须用 glob 匹配，否则永远匹配不到。
say "dropbox list"
ls -lt /data/system/dropbox/ 2>&1 | head -80 >> "$OUT"

say "dropbox contents"
for k in system_server_crash system_app_crash SYSTEM_TOMBSTONE data_app_crash \
         system_server_anr SYSTEM_BOOT SYSTEM_RESTART; do
  for f in /data/system/dropbox/${k}@*.txt; do
    [ -f "$f" ] || continue
    say "dropbox: $f"
    cat "$f" 2>&1 | head -120 >> "$OUT"
  done
done

say "logcat crash buffer"
logcat -b crash -d -v threadtime 2>&1 | tail -400 >> "$OUT"

say "logcat main buffer (last 300)"
logcat -b main -d -v threadtime 2>&1 | tail -300 >> "$OUT"

say "logcat events (watchdog / reboot / boot)"
logcat -b events -d -v threadtime 2>&1 | tail -300 >> "$OUT"

# ---------------------------------------------------------------- C) 利用侧日志
# 分辨「页回收被抢」和「UAF 原语自伤」的关键：
#   hit=0  -> 回收/抢页失败   -> 偏向「页被系统活动抢走」
#   hit=1  -> 回收成功仍崩     -> 偏向「UAF 竞态自伤」
say "app run logs (run_logs)"
for pkg in com.EternalTimes.GhostKey com.EternalTimes.GhostKey.test; do
  for base in /data/user/0 /data/data; do
    d="$base/$pkg/files/run_logs"
    [ -d "$d" ] || continue
    say "run_logs dir: $d"
    ls -lt "$d" 2>&1 | head -20 >> "$OUT"
    for f in $(ls -t "$d"/*.log 2>/dev/null | head -4); do
      say "run log: $f"
      cat "$f" 2>&1 | tail -500 >> "$OUT"
    done
  done
done

# ---------------------------------------------------------------- D) 残留状态
say "reboot / boot reason"
for p in /sys/kernel/power/last_reboot /sys/power/last_reboot \
         /proc/sys/kernel/random/boot_id; do
  [ -e "$p" ] && { echo "--- $p"; cat "$p" 2>&1; } >> "$OUT"
done
getprop 2>/dev/null | grep -iE 'sys.boot.reason|ro.boot.bootreason|sys.powerctl|ro.boot.hardware' >> "$OUT" 2>&1

say "KSU userspace"
ls -l /data/adb/ksud /data/adb/ksu/bin/ksud 2>&1 >> "$OUT"
pidof ksud 2>&1 >> "$OUT"
ls -l /data/adb/modules 2>&1 >> "$OUT"

say "residual exploit processes"
ps -A -o PID,PPID,USER,NAME 2>&1 | grep -iE 'uaf_plant|ksud|cve98260|libcve' >> "$OUT" 2>&1

say "residual processes: SELinux context"
for p in $(pidof libcve98260.so 2>/dev/null); do
  echo "--- pid $p"; cat /proc/$p/attr/current 2>&1
done

say "tracefs buffer (内核全局，进程退出不还原)"
cat /sys/kernel/tracing/buffer_size_kb 2>&1 >> "$OUT"

say "done"
echo "written: $OUT"
