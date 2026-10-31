/*
 * T2 - ksu_script.c 的宿主单测
 *
 * 被测对象是 KSU 接管脚本生成器。这个脚本由 rootd 以 uid=0 在设备上执行，
 * 是整条接管链路里最脆的一环：2026-10-31 真机就是因为「只用一个 ksud 候选」
 * 导致 late-load 打印一段帮助、daemon 起不来，最终表现为
 * 「模块加载了，但 /system/bin/sh: su: inaccessible or not found」——
 * 而脚本写错了不会在编译期暴露，只会在设备上表现为「没 su」。
 *
 * 这里做两件事：
 *   1) 断言生成出来的脚本包含关键片段（候选阶梯、daemon 用的是**能用的那个**、
 *      ksud_used 记录、pidof 确认……）；
 *   2) 把脚本落盘，供外部用 `sh -n` 做语法检查。
 *
 * 之所以能跑宿主：ksu_script.c 只依赖 stdio/string（chmod 由调用方负责）。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ksu_script.h"

static int g_checks;
static int g_failures;

static void check(int ok, const char *expr, int line)
{
	g_checks++;
	if (!ok) {
		g_failures++;
		printf("  FAIL  line %d: %s\n", line, expr);
	}
}

#define CHECK(cond) check((cond) != 0, #cond, __LINE__)

/*
 * Count occurrences of a substring.
 *
 * Needed because the generated script is written in TEXT mode on Windows, so
 * its line endings are CRLF here but LF on the device. Any assertion that
 * depends on a bare "\n" would therefore pass on device and fail in the host
 * test (or the other way round) — count occurrences instead.
 */
static int count_occurrences(const char *hay, const char *needle)
{
	int n = 0;
	size_t len = strlen(needle);
	const char *p = hay;

	if (!len)
		return 0;
	while ((p = strstr(p, needle)) != NULL) {
		n++;
		p += len;
	}
	return n;
}

int main(void)
{
	char ksuds[3][512];
	const char *path = "ksu_takeover_test.sh";
	const char *log = "ksu_takeover_test.log";
	char buf[65536];
	FILE *f;
	size_t len = 0;

	snprintf(ksuds[0], sizeof(ksuds[0]), "%s", "/data/local/tmp/ksud");
	snprintf(ksuds[1], sizeof(ksuds[1]), "%s", "/data/local/tmp/cve98260-app/ksud");
	snprintf(ksuds[2], sizeof(ksuds[2]), "%s", "/data/adb/ksud");

	/* ---- 生成 ---- */
	CHECK(ksu_write_takeover_script(path, ksuds, 3, "android17-6.18", log, 0) == 0);

	f = fopen(path, "rb");
	CHECK(f != NULL);
	if (!f)
		return 1;
	len = fread(buf, 1, sizeof(buf) - 1, f);
	fclose(f);
	buf[len] = 0;
	CHECK(len > 0);

	/* ---- 候选都在 ---- */
	CHECK(strstr(buf, "KSUD0='/data/local/tmp/ksud'") != NULL);
	CHECK(strstr(buf, "KSUD1='/data/local/tmp/cve98260-app/ksud'") != NULL);
	CHECK(strstr(buf, "KSUD2='/data/adb/ksud'") != NULL);
	CHECK(strstr(buf, "KMI='android17-6.18'") != NULL);
	CHECK(strstr(buf, "LOG='ksu_takeover_test.log'") != NULL);

	/* ---- 阶梯：先 --kmi，再裸 late-load ---- */
	CHECK(strstr(buf, "late-load --kmi") != NULL);
	CHECK(strstr(buf, "\"$K\" late-load >>") != NULL);

	/* ---- late-load 先 daemonize、模块注册是异步的：必须轮询，不能采样一次 ----
	 * 旧实现 sleep 1 采样一次，在 daemonize 竞态里会误判成「没加载」，
	 * 于是白白跳到下一个候选。 */
	CHECK(strstr(buf, "poll_live()") != NULL);
	CHECK(strstr(buf, "LIVE=$(poll_live)") != NULL);
	CHECK(strstr(buf, "while [ $i -lt $POLL_TRIES ]") != NULL);
	/* 旧的单次采样实现必须已经不存在 */
	CHECK(strstr(buf, "live() { sleep 1;") == NULL);

	/* ---- 不再自己起 ksud daemon ----
	 * 上游 KernelSU 没有常驻 ksud daemon：late-load 自带的后台进程跑完 stage
	 * 脚本就退出；旧实现额外 nohup 起来的是管理器里那个只认 -h/-V 的陈旧构建，
	 * 于是永远报 "ksud daemon not visible in /proc"。 */
	CHECK(strstr(buf, "nohup \"$K\"") == NULL);
	CHECK(strstr(buf, "pidof ksud") == NULL);
	CHECK(strstr(buf, "nohup \"$KSUD\"") == NULL);

	/* ---- 记录最终用了哪个候选，以及 late-load 装出来的 userspace 组件
	 * （内核替换 su 用的就是 /data/adb/ksu/bin/ksud） ---- */
	CHECK(strstr(buf, "KSUD_USED=$K") != NULL);
	CHECK(strstr(buf, "ksud_used=$KSUD_USED") != NULL);
	CHECK(strstr(buf, "ksud_installed=$P") != NULL);
	CHECK(strstr(buf, "/data/adb/ksu/bin/ksud") != NULL);
	CHECK(strstr(buf, "/data/adb/ksud") != NULL);
	/* late-load 先 daemonize 再 install —— 安装产物必须等，不能查完就报缺失 */
	CHECK(strstr(buf, "wait_install() {") != NULL);
	/* 定义 + 调用各一次。这里不能断言 "wait_install\n"：宿主上脚本是 TEXT 模式
	 * 写出的，行尾是 \r\n，卡行尾会在宿主上假失败、在设备上真通过。 */
	CHECK(count_occurrences(buf, "wait_install") == 2);
	CHECK(strstr(buf, "[ -e /data/adb/ksu/bin/ksud ]") != NULL);
	/* 模块没起来时 late-load 直接失败、不会 install —— 此时不该空等 6 秒 */
	CHECK(strstr(buf, "if [ \"$LIVE\" = yes ]; then wait_install; fi") != NULL);

	/* ---- allow_shell 默认关闭；打开时给 late-load 传 --allow-shell ---- */
	CHECK(strstr(buf, "ALLOW_SHELL=0") != NULL);
	CHECK(strstr(buf, "late-load --kmi \"$KMI\" --allow-shell") != NULL);

	/* ---- 其它必须保留的行为 ---- */
	CHECK(strstr(buf, "setenforce 0") != NULL);
	CHECK(strstr(buf, "grep -qi kernelsu /proc/modules") != NULL);
	CHECK(strstr(buf, "sync") != NULL);
	CHECK(strstr(buf, "exit 0") != NULL);

	/* ---- 单候选时只生成 KSUD0，不留空壳变量 ---- */
	{
		char one[1][512];
		snprintf(one[0], sizeof(one[0]), "%s", "/data/local/tmp/ksud");
		CHECK(ksu_write_takeover_script(path, one, 1, "android17-6.18", log, 0) == 0);
		f = fopen(path, "rb");
		len = f ? fread(buf, 1, sizeof(buf) - 1, f) : 0;
		if (f)
			fclose(f);
		buf[len] = 0;
		CHECK(strstr(buf, "KSUD0='/data/local/tmp/ksud'") != NULL);
		CHECK(strstr(buf, "KSUD1=") == NULL);
	}

	/* ---- allow_shell 打开时：late-load 必须带上 --allow-shell ---- */
	{
		char one[1][512];
		snprintf(one[0], sizeof(one[0]), "%s", "/data/local/tmp/ksud");
		CHECK(ksu_write_takeover_script(path, one, 1, "android17-6.18", log, 1) == 0);
		f = fopen(path, "rb");
		len = f ? fread(buf, 1, sizeof(buf) - 1, f) : 0;
		if (f)
			fclose(f);
		buf[len] = 0;
		CHECK(strstr(buf, "ALLOW_SHELL=1") != NULL);
		CHECK(strstr(buf, "late-load --kmi \"$KMI\" --allow-shell") != NULL);
	}

	printf("[case] ksu takeover script generation\n");
	printf("%d checks, %d failure(s): %s\n", g_checks, g_failures,
	       g_failures ? "FAIL" : "OK");
	return g_failures ? 1 : 0;
}
