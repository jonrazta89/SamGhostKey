#!/system/bin/sh
# 取证脚本：抓「自动重启」到底是谁干的。
#
# 用法（在设备上，或 `adb shell sh collect_reboot_evidence.sh`）：
#   su -c sh collect_reboot_evidence.sh
# 输出写到 /data/local/tmp/cve98260-app/reboot_evidence.txt
#
# 为什么需要它：「注入完成后软重启、几秒后又自动重启」有两种完全不同的成因，
# 现象一样，取证才能分开：
#   A) 内核 panic  → pstore 里有 ramoops 日志（最硬 的证据）
#   B) userspace 反复崩溃 → dropbox / crash log 里有 system_server 的 tombstone
# 两者都抓，缺一不可。

OUT=/data/local/tmp/cve98260-app/reboot_evidence.txt
mkdir -p "$(dirname "$OUT")"
: > "$OUT"

say() { echo "===== $* =====" >> "$OUT"; }

say "meta"
{
  echo "date: $(date 2>/dev/null)"
  echo "uptime: $(cat /proc/uptime 2>/dev/null)"
  echo "kernel: $(uname -a 2>/dev/null)"
  echo "modules:"; grep -iE 'kernelsu|ksu' /proc/modules 2>/dev/null
} >> "$OUT" 2>&1

# ---- A) 内核 panic：pstore 的 ramoops 保留了上一次崩溃的内核日志 ----
say "pstore"
ls -l /sys/fs/pstore/ 2>&1 >> "$OUT"
for f in /sys/fs/pstore/*; do
  [ -f "$f" ] || continue
  say "pstore file: $f"
  # ramoops 是 root-only，能读就读；读不到也把失败原因留下
  cat "$f" 2>&1 | tail -400 >> "$OUT"
done

say "last_kmsg"
cat /proc/last_kmsg 2>&1 | tail -300 >> "$OUT"

say "dmesg tail"
dmesg 2>&1 | tail -300 >> "$OUT"

# ---- B) userspace 反复崩溃：dropbox 里的 tombstone / crash ----
say "dropbox list"
ls -lt /data/system/dropbox/ 2>&1 | head -60 >> "$OUT"

say "dropbox system_server / system_app crash"
for k in system_server_crash system_app_crash SYSTEM_TOMBSTONE data_app_crash \
         system_server_anr SYSTEM_BOOT; do
  [ -e "/data/system/dropbox/$k" ] || continue
  say "dropbox: $k"
  dumpsys dropbox --print "$k" 2>&1 | head -200 >> "$OUT"
done

say "logcat crash buffer"
logcat -b crash -d -v threadtime 2>&1 | tail -300 >> "$OUT"

say "logcat main buffer (last 200)"
logcat -b main -d -v threadtime 2>&1 | tail -200 >> "$OUT"

say "reboot / shutdown history"
for p in /sys/kernel/power/last_reboot /sys/power/last_reboot \
         /proc/sys/kernel/random/boot_id; do
  [ -e "$p" ] && { echo "--- $p"; cat "$p" 2>&1; } >> "$OUT"
done
# 有些 ROM 把重启原因留在这里
getprop 2>/dev/null | grep -iE 'sys.boot.reason|ro.boot.bootreason|sys.powerctl' >> "$OUT" 2>&1

say "KSU userspace"
ls -l /data/adb/ksud /data/adb/ksu/bin/ksud 2>&1 >> "$OUT"
pidof ksud 2>&1 >> "$OUT"

say "done"
echo "written: $OUT"
