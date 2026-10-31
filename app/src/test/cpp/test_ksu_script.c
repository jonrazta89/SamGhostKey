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
	CHECK(ksu_write_takeover_script(path, ksuds, 3, "android17-6.18", log) == 0);

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

	/* ---- daemon 必须用「真正能 late-load 的那个」候选 ---- */
	CHECK(strstr(buf, "nohup \"$K\" >/dev/null 2>&1 &") != NULL);
	/* 旧写法（固定变量）必须已经不存在，否则又回到「只用一个候选」的老路 */
	CHECK(strstr(buf, "nohup \"$KSUD\"") == NULL);

	/* ---- daemon 起没起来要用 pidof 确认，并记录最终用了谁 ---- */
	CHECK(strstr(buf, "if pidof ksud >/dev/null 2>&1; then") != NULL);
	CHECK(strstr(buf, "KSUD_USED=$K") != NULL);
	CHECK(strstr(buf, "ksud_used=$KSUD_USED") != NULL);

	/* ---- 其它必须保留的行为 ---- */
	CHECK(strstr(buf, "setenforce 0") != NULL);
	CHECK(strstr(buf, "grep -qi kernelsu /proc/modules") != NULL);
	CHECK(strstr(buf, "sync") != NULL);
	CHECK(strstr(buf, "exit 0") != NULL);

	/* ---- 单候选时只生成 KSUD0，不留空壳变量 ---- */
	{
		char one[1][512];
		snprintf(one[0], sizeof(one[0]), "%s", "/data/local/tmp/ksud");
		CHECK(ksu_write_takeover_script(path, one, 1, "android17-6.18", log) == 0);
		f = fopen(path, "rb");
		len = f ? fread(buf, 1, sizeof(buf) - 1, f) : 0;
		if (f)
			fclose(f);
		buf[len] = 0;
		CHECK(strstr(buf, "KSUD0='/data/local/tmp/ksud'") != NULL);
		CHECK(strstr(buf, "KSUD1=") == NULL);
	}

	printf("[case] ksu takeover script generation\n");
	printf("%d checks, %d failure(s): %s\n", g_checks, g_failures,
	       g_failures ? "FAIL" : "OK");
	return g_failures ? 1 : 0;
}
