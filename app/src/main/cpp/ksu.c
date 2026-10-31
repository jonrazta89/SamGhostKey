/*
 * ksu.c - KernelSU takeover
 *
 * Corresponds to the PC reference reference: tools/ksu_activate.sh (pushed in run.py as
 * REMOTE_KSU_TAKEOVER and executed) and scripts/ksu_takeover.sh.
 *
 * Two on-device measured conclusions (from the reference impl comments):
 *   1) late-load must run as uid=0; when run as shell (uid 2000) rc=0
 *      but the module does not enter the kernel.
 *   2) after a successful load the kernel forces SELinux back to Enforcing, and rootd's unlabeled socket
 *      drops the link, so the script does no final verification; the criterion is moved to the parent, which uses
 *      'whether kernelsu appears in /proc/modules'.
 *
 * Therefore this module does not run ksud directly (this process is shell uid 2000); instead it
 * generates a takeover script and runs it via rootd's unix socket as uid=0 -- equivalent to run.py's
 *   printf 'KSU_EXPECT_SHA256=... sh /data/local/tmp/ksu_takeover.sh\n' | pc98260_su
 */

#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#include "ksu.h"
#include "ksu_script.h"

int pc98260_su_main(int argc, char **argv);

#define ROOT_SOCK_DEFAULT "/data/local/tmp/pc98260-root.sock"

static const char *ksu_home(void)
{
	const char *h = getenv("CVE98260_HOME");
	if (h && *h)
		return h;
	return "/data/local/tmp/cve98260-app";
}

/* bionic's strcasestr is not exported in all NDK versions; implement locally for stability */
static int strcasestr_local(const char *hay, const char *needle)
{
	size_t i, n = strlen(needle);
	if (!n)
		return 1;
	for (i = 0; hay[i]; i++) {
		size_t j;
		for (j = 0; j < n && hay[i + j]; j++) {
			if ((hay[i + j] | 32) != (needle[j] | 32))
				break;
		}
		if (j == n)
			return 1;
	}
	return 0;
}

static int uname_rel(char *out, size_t size)
{
	struct utsname u;
	if (uname(&u))
		return -1;
	snprintf(out, size, "%s", u.release);
	return 0;
}

static void sleep_ms(int ms)
{
	struct timespec ts;
	ts.tv_sec = ms / 1000;
	ts.tv_nsec = (long)(ms % 1000) * 1000000L;
	nanosleep(&ts, NULL);
}

/* derive KMI from uname -r: 6.6.118-android15-8-... -> android15-6.6
 *(equivalent to the sed expression in ksu_activate.sh) */
static void derive_kmi(char *out, size_t out_size)
{
	char rel[256] = { 0 };
	const char *android = NULL;
	char major[32] = { 0 };
	char minor[32] = { 0 };
	size_t i;

	if (uname_rel(rel, sizeof(rel)) != 0)
		rel[0] = 0;
	for (i = 0; rel[i]; i++) {
		if (!strncmp(rel + i, "android", 7)) {
			android = rel + i;
			break;
		}
	}
	if (rel[0]) {
		int part = 0;
		size_t start = 0;
		for (i = 0; rel[i]; i++) {
			if (rel[i] == '.') {
				if (part == 0) {
					size_t n = i - start;
					if (n >= sizeof(major))
						n = sizeof(major) - 1;
					memcpy(major, rel + start, n);
					major[n] = 0;
					start = i + 1;
					part = 1;
				} else if (part == 1) {
					size_t n = i - start;
					if (n >= sizeof(minor))
						n = sizeof(minor) - 1;
					memcpy(minor, rel + start, n);
					minor[n] = 0;
					break;
				}
			}
		}
	}
	if (android && major[0] && minor[0]) {
		char android_short[32] = { 0 };
		size_t k = 0;
		while (android[k] && android[k] != '-' && k + 1 < sizeof(android_short))
			k++;
		memcpy(android_short, android, k);
		android_short[k] = 0;
		snprintf(out, out_size, "%s-%s.%s", android_short, major, minor);
		return;
	}
	snprintf(out, out_size, "android15-6.6");
}

/*
 * 收集**所有**可用的 ksud 候选，按优先级排序（去重）。
 *
 * 2026-10-31 真机教训：设备上同时存在两个不同版本的 ksud ——
 *   · 管理器里的 libksud.so（4990848 B，旧版，只认 -h/-V，不支持
 *     late-load / daemon）；
 *   · APK 自带的 assets/ksu/ksud（6402736 B，sha256 049491e2b4cc0a6c...，
 *     版本串 32680 / 3.3.1 —— 与设备上那个 KSU 管理器 v3.3.1 (32680-5)
 *     **同版本**，所以 late-load 才能加载成功）。
 * 旧实现只取第一个存在的候选（永远是管理器那个），于是接管时
 * `late-load` 只打印一段帮助，最终「模块加载了但没有 su」。
 *
 * 现在的顺序（2026-10-31 修正）：
 *   1. CVE98260_KSUD       —— 宿主显式指定（宿主现在指向内置那个 v3.3.1）
 *   2. $CVE98260_HOME/ksud —— APK 内置资源（与本 APK 的 KMI 集配套）
 *   3. /data/adb/ksu/bin/ksud —— 上一次 late-load 的 utils::install() 产物，
 *      这正是**内核替换 su 时用的那个 ksud**
 *   4. /data/adb/ksud      —— 同上，legacy 路径
 *   5. /data/local/tmp/ksud —— 管理器里那个陈旧构建，**排最后**（兜底）
 *
 * 返回候选个数（0 = 一个都没有）。
 */
static int find_ksud_list(char out[][512], int max)
{
	const char *env = getenv("CVE98260_KSUD");
	const char *candidates[5];
	char built[512];
	size_t i;
	int n = 0;

	if (!out || max <= 0)
		return 0;
	snprintf(built, sizeof(built), "%s/ksud", ksu_home());
	candidates[0] = env;
	candidates[1] = built;
	candidates[2] = "/data/adb/ksu/bin/ksud";
	candidates[3] = "/data/adb/ksud";
	candidates[4] = "/data/local/tmp/ksud";
	for (i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
		struct stat st;
		int dup = 0;
		int j;

		if (!candidates[i] || !*candidates[i])
			continue;
		if (stat(candidates[i], &st))
			continue;
		if (!S_ISREG(st.st_mode))
			continue;
		for (j = 0; j < n; j++)
			if (!strcmp(out[j], candidates[i]))
				dup = 1;
		if (dup)
			continue;
		if (n >= max)
			break;
		snprintf(out[n], 512, "%s", candidates[i]);
		n++;
	}
	return n;
}

/* Size of a file, or -1 when it cannot be stat'ed. Used to tell the bundled
 * ksud (6402736 B) apart from the device build under /data/adb/ksud. */
static long long file_size(const char *path)
{
	struct stat st;
	if (stat(path, &st))
		return -1;
	if (!S_ISREG(st.st_mode))
		return -1;
	return (long long)st.st_size;
}

static int modules_have_kernelsu(void)
{
	char line[512];
	FILE *f = fopen("/proc/modules", "r");
	if (!f)
		return 0;
	while (fgets(line, sizeof(line), f)) {
		if (strcasestr_local(line, "kernelsu")) {
			fclose(f);
			return 1;
		}
	}
	fclose(f);
	return 0;
}

/*
 * Flush the stage log to the block device.
 *
 * A kernel panic does not flush page cache, so on 23:06 the run died inside
 * this step and every diagnostic after the last checkpoint was lost as NUL
 * bytes - leaving no way to tell which attempt killed the kernel. Called only
 * at stage boundaries, never in a timing-sensitive window.
 */
static void ksu_sync(void)
{
	(void)fdatasync(STDOUT_FILENO);
}


int ksu_takeover_main(int argc, char **argv)
{
	char ksuds[5][512], kmi[64], script[512], log[512], cmd[1024];
	char *su_argv[4];
	int i, rc = 1;
	int already = 0;
	int n_ksuds;
	int allow_shell;

	(void)argc;
	(void)argv;

	/*
	 * allow_shell=1 是上游 late-load 的模块加载参数，含义「Always allow
	 * shell to get root permission」—— 放行 shell(uid 2000)，也就是本工具
	 * UserService 的身份。**只在模块首次加载时生效**：late_load::run 开头
	 * 就检查 has_kernelsu()，已加载则跳过 load_module，参数无处可施。
	 * 所以默认关闭，由宿主按需通过 CVE98260_KSU_ALLOW_SHELL=1 打开。
	 */
	{
		const char *as = getenv("CVE98260_KSU_ALLOW_SHELL");
		allow_shell = (as && *as && strcmp(as, "0") != 0) ? 1 : 0;
	}

	n_ksuds = find_ksud_list(ksuds, 5);
	if (n_ksuds <= 0) {
		fprintf(stderr, "[ksu] error: ksud not found (assets/ksu/ksud not bundled?)\n");
		return 1;
	}
	derive_kmi(kmi, sizeof(kmi));
	snprintf(script, sizeof(script), "%s/ksu_takeover.sh", ksu_home());
	snprintf(log, sizeof(log), "%s/ksu_takeover.log", ksu_home());

	fprintf(stdout, "[ksu] kmi=%s uid=%u candidates=%d allow_shell=%d\n", kmi,
		(unsigned)getuid(), n_ksuds, allow_shell);
	/*
	 * Diagnostic: two different ksud builds live on the device -- the bundled
	 * one is 6402736 B (sha256 049491e2b4cc0a6c...) while /data/adb/ksud is a
	 * 4990848 B device build. Both are now tried in turn by the takeover
	 * script, so print the size of every candidate: the one that actually
	 * works is the one that gets a working ksud daemon (and therefore su).
	 */
	for (i = 0; i < n_ksuds; i++)
		fprintf(stdout, "[ksu] candidate[%d]=%s size=%lld\n", i, ksuds[i],
			file_size(ksuds[i]));
	ksu_sync();

	if (modules_have_kernelsu()) {
		fprintf(stdout, "[ksu] kernelsu already in /proc/modules, skip KSU\n");
		ksu_sync();
		already = 1;
		goto done;
	}

	if (ksu_write_takeover_script(script, ksuds, n_ksuds, kmi, log, allow_shell)) {
		fprintf(stderr, "[ksu] error: cannot write %s\n", script);
		ksu_sync();
		return 1;
	}
	chmod(script, 0755);
	/* The script itself is on disk before anything risky runs; make sure the
	 * fact that we got this far is durable too. */
	ksu_sync();

	snprintf(cmd, sizeof(cmd), "sh %s", script);
	fprintf(stdout, "[ksu] executing via rootd as uid=0: %s\n", cmd);
	ksu_sync();

	su_argv[0] = (char *)"su";
	su_argv[1] = (char *)"-c";
	su_argv[2] = cmd;
	su_argv[3] = NULL;
	rc = pc98260_su_main(3, su_argv);
	if (rc != 0)
		fprintf(stdout, "[ksu] warn: rootd channel exit code %d (possible connection failure)\n", rc);
	/* Last durable checkpoint before the poll: if the log stops here, the
	 * late-load itself (init_module) took the kernel down. */
	ksu_sync();

	/* late-load is asynchronous; poll for module registration */
	for (i = 0; i < 15; i++) {
		if (modules_have_kernelsu()) {
			already = 1;
			break;
		}
		sleep_ms(1000);
	}

done:
	if (already) {
		fprintf(stdout, "[ksu] success: kernelsu is in /proc/modules\n");
		fprintf(stdout, "C98260_KSU=loaded\n");
		return 0;
	}
	fprintf(stderr, "[ksu] error: /proc/modules has no kernelsu (see %s)\n", log);
	fprintf(stdout, "C98260_KSU=missing\n");
	return 1;
}
