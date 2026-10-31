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
				 const char *kmi, const char *log, int allow_shell)
{
	FILE *f = fopen(path, "w");
	int i;

	if (!f)
		return -1;
	fprintf(f, "#!/system/bin/sh\n");
	fprintf(f, "# CVE-2026-98260 KSU takeover: this script is executed only by rootd (uid=0)\n");
	fprintf(f, "#\n");
	fprintf(f, "# 2026-10-31 real-device corrections, all traced back to upstream\n");
	fprintf(f, "# KernelSU v3.3.1 sources:\n");
	fprintf(f, "#\n");
	fprintf(f, "# 1) `ksud late-load` calls daemonize() FIRST (late_load.rs:39), so the\n");
	fprintf(f, "#    command returns immediately and the module is registered later by\n");
	fprintf(f, "#    the forked child. Sampling /proc/modules once after 1s raced that\n");
	fprintf(f, "#    and reported 'not loaded', sending the ladder on to the next\n");
	fprintf(f, "#    candidate. -> poll until the module shows up.\n");
	fprintf(f, "#\n");
	fprintf(f, "# 2) late-load itself calls utils::install() (late_load.rs:82), which\n");
	fprintf(f, "#    installs ksud at /data/adb/ksud and symlinks /data/adb/ksu/bin/ksud.\n");
	fprintf(f, "#    That ksud is what the kernel substitutes for 'su'. KernelSU has\n");
	fprintf(f, "#    NO long-lived 'ksud daemon' to start: the old host-side\n");
	fprintf(f, "#    'nohup ksud &' used the stale manager build (only -h/-V) and\n");
	fprintf(f, "#    always reported 'ksud daemon not visible in /proc'.\n");
	fprintf(f, "#\n");
	fprintf(f, "# 3) KernelSU's su is not a file in PATH: the kernel replaces the\n");
	fprintf(f, "#    execve target with ksud and only for AUTHORIZED uids (cli.rs:501).\n");
	fprintf(f, "#    So 'is there su' is a question about the CALLER's uid, not about\n");
	fprintf(f, "#    a file existing somewhere.\n");
	for (i = 0; i < n_ksuds; i++)
		fprintf(f, "KSUD%d='%s'\n", i, ksuds[i]);
	fprintf(f, "KMI='%s'\n", kmi);
	fprintf(f, "LOG='%s'\n", log);
	fprintf(f, "ALLOW_SHELL=%d\n", allow_shell ? 1 : 0);
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
	 * poll_live(): late-load registers the module asynchronously AND after it
	 * has forked (upstream late_load.rs daemonizes before load_module), so a
	 * single "sleep 1 && grep" sample races that and reports live=no for a
	 * load that is about to succeed. Poll until the module shows up.
	 * Case-insensitive, like the reference's `grep -qi`.
	 */
	fprintf(f, "POLL_TRIES=6\n");
	fprintf(f, "poll_live() {\n");
	fprintf(f, "  i=0\n");
	fprintf(f, "  while [ $i -lt $POLL_TRIES ]; do\n");
	fprintf(f, "    sleep 1\n");
	fprintf(f, "    if grep -qi kernelsu /proc/modules 2>/dev/null; then echo yes; return; fi\n");
	fprintf(f, "    i=$((i+1))\n");
	fprintf(f, "  done\n");
	fprintf(f, "  echo no\n");
	fprintf(f, "}\n");
	fprintf(f, "\n");
	fprintf(f, "LIVE=no\n");
	fprintf(f, "KSUD_USED=''\n");
	fprintf(f, "for K in");
	for (i = 0; i < n_ksuds; i++)
		fprintf(f, " \"$KSUD%d\"", i);
	fprintf(f, "; do\n");
	fprintf(f, "  [ -x \"$K\" ] || { echo \"[ksu] skip (not executable): $K\" >> \"$LOG\"; continue; }\n");
	fprintf(f, "  if [ \"$LIVE\" != yes ]; then\n");
	fprintf(f, "    if [ \"$ALLOW_SHELL\" = 1 ]; then\n");
	fprintf(f, "      echo \"[ksu] try: $K late-load --kmi $KMI --allow-shell\" >> \"$LOG\"\n");
	fprintf(f, "      \"$K\" late-load --kmi \"$KMI\" --allow-shell >> \"$LOG\" 2>&1\n");
	fprintf(f, "    else\n");
	fprintf(f, "      echo \"[ksu] try: $K late-load --kmi $KMI\" >> \"$LOG\"\n");
	fprintf(f, "      \"$K\" late-load --kmi \"$KMI\" >> \"$LOG\" 2>&1\n");
	fprintf(f, "    fi\n");
	fprintf(f, "    echo \"[ksu] rc=$? ksud=$K\" >> \"$LOG\"\n");
	fprintf(f, "    sync\n");
	fprintf(f, "    LIVE=$(poll_live)\n");
	fprintf(f, "    echo \"[ksu] live=$LIVE ksud=$K\" >> \"$LOG\"\n");
	fprintf(f, "    if [ \"$LIVE\" != yes ]; then\n");
	fprintf(f, "      echo '[ksu] try: $K late-load (no args, ksud picks the embedded KMI)' >> \"$LOG\"\n");
	fprintf(f, "      \"$K\" late-load >> \"$LOG\" 2>&1\n");
	fprintf(f, "      echo \"[ksu] rc=$? ksud=$K\" >> \"$LOG\"\n");
	fprintf(f, "      sync\n");
	fprintf(f, "      LIVE=$(poll_live)\n");
	fprintf(f, "      echo \"[ksu] live=$LIVE ksud=$K\" >> \"$LOG\"\n");
	fprintf(f, "    fi\n");
	fprintf(f, "  fi\n");
	fprintf(f, "  if [ \"$LIVE\" = yes ]; then\n");
	fprintf(f, "    KSUD_USED=$K\n");
	fprintf(f, "    break\n");
	fprintf(f, "  fi\n");
	fprintf(f, "  echo '[ksu] this ksud did not register the module, trying next candidate' >> \"$LOG\"\n");
	fprintf(f, "done\n");
	fprintf(f, "\n");
	/*
	 * Report the userspace component the kernel substitutes for 'su'.
	 *
	 * late-load's utils::install() creates both of these; if they are absent
	 * the su replacement target does not exist and no `su` can work, no matter
	 * which uid is authorized. Reading them here (as uid 0, inside rootd) is
	 * also the only way to see them at all: /data/adb is 0700 root, so the
	 * shell-uid side cannot stat them.
	 *
	 * WAIT for them: `late-load` daemonizes BEFORE it does the install, so
	 * the install runs in the background child and is usually NOT finished
	 * when the late-load command returns. Checking immediately produced a
	 * false "su replacement target missing" (2026-10-31 real device: the
	 * module was already loaded, so late-load went straight to install and
	 * the check ran before it finished).
	 *
	 * Only wait when the module actually registered: if load_module failed,
	 * late-load returns early (late_load.rs:67) and never reaches
	 * utils::install() (late_load.rs:82), so nothing would ever show up and
	 * we would just burn POLL_TRIES seconds for nothing.
	 */
	fprintf(f, "wait_install() {\n");
	fprintf(f, "  i=0\n");
	fprintf(f, "  while [ $i -lt $POLL_TRIES ]; do\n");
	fprintf(f, "    if [ -e /data/adb/ksu/bin/ksud ] || [ -e /data/adb/ksud ]; then return; fi\n");
	fprintf(f, "    sleep 1\n");
	fprintf(f, "    i=$((i+1))\n");
	fprintf(f, "  done\n");
	fprintf(f, "}\n");
	fprintf(f, "if [ \"$LIVE\" = yes ]; then wait_install; fi\n");
	fprintf(f, "for P in /data/adb/ksu/bin/ksud /data/adb/ksud; do\n");
	fprintf(f, "  if [ -e \"$P\" ]; then\n");
	fprintf(f, "    echo \"[ksu] ksud_installed=$P size=$(stat -c %%s \"$P\" 2>/dev/null)\" >> \"$LOG\"\n");
	fprintf(f, "  fi\n");
	fprintf(f, "done\n");
	fprintf(f, "echo \"[ksu] ksud_used=$KSUD_USED\" >> \"$LOG\"\n");
	fprintf(f, "echo '[ksu] note: rc is not a criterion -- ksud returns 0 even on silent failure' >> \"$LOG\"\n");
	fprintf(f, "echo \"[ksu] end live=$LIVE\" >> \"$LOG\"\n");
	fprintf(f, "exit 0\n");
	fclose(f);
	return 0;
}
