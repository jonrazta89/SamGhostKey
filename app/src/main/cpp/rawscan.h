#ifndef RAWSCAN_H
#define RAWSCAN_H

#include <stddef.h>
#include <stdint.h>

/*
 * rawscan.h - raw trace 记录扫描（纯计算，可宿主单测）
 *
 * 背景：uaf_plant.c 的 collect_nth() 要从 per-CPU 的 trace_pipe_raw 里找出
 * 「k_itimer 对象分配」记录。它原来是「把整个 pipe 读完再扫一遍」，而且只读
 * cpu0、还阻塞等满 2 秒（alarm 兜底）—— 那 2 秒发生在 tracing_on=0 之后，
 * 环形缓冲早已冻结、不会再有新记录，所以是纯死等。
 *
 * 现在改成边读边扫（rawscan_feed），于是出现一个跨块的问题：记录是按
 * **字节逐位试探**匹配的（每挪 1 字节试一次 memcmp），所以候选可能从上一块
 * 的最后 31 字节里开始。rawscan 用 tail 把上一块的尾巴接到前面，保证跨块的
 * 候选不漏 —— 这样「增量扫描」的结果与「整块扫描」逐条一致。
 *
 * 这部分不碰 tracefs、不碰 Android，所以放在独立文件里做宿主单测。
 */

/*
 * 跨块衔接要带过去的字节数。
 *
 * 一条记录占 32 字节。若上一块结束于流位置 end，那么**下一个还没被扫过的
 * 起点**是 end-31，它的记录要跨块（头 1 字节在上一块、尾 31 字节在下一块）。
 * 所以衔接必须带 31 字节 —— 带 32 会把「上一轮已经扫过的那个起点」再扫一遍，
 * 命中数就会重复计数。
 */
#define RAWSCAN_CARRY 31
#define RAWSCAN_MAX_CHUNK 16384

struct rawscan_state {
	/* 匹配键 */
	uint8_t needle[8];	/* call_site（运行期地址，含 slide） */
	int filter_by_site;	/* 0 = 只按 req 匹配 */
	uint64_t req;		/* bytes_req（= slab 的 object_size） */

	/* 输出 */
	uint64_t *out;		/* 命中指针数组（调用方提供） */
	int out_cap;		/* out 的容量 */
	int out_n;		/* 命中总数（可能 > out_cap） */
	int index;		/* 取第几条当 victim（0 基） */
	uint64_t chosen;	/* 第 index 条（不够则为 0） */

	/* 跨块衔接 */
	uint8_t tail[RAWSCAN_CARRY];
	int tail_n;
	size_t bytes;		/* 累计喂进来的字节数 */

	/* 扫描工作区（衔接字节 + 一块数据） */
	uint8_t scratch[RAWSCAN_MAX_CHUNK + RAWSCAN_CARRY];
};

/*
 * 初始化扫描状态。
 *   needle        8 字节 call_site；filter_by_site=0 时可以传 NULL
 *   req           目标 slab 的 object_size（k_itimer 大小）
 *   out / out_cap 命中指针数组与容量（数组可以小于命中数，超出部分只计数）
 *   index         取第几条当 victim（0 基）
 */
void rawscan_init(struct rawscan_state *s, const uint8_t *needle, int filter_by_site,
		  uint64_t req, uint64_t *out, int out_cap, int index);

/*
 * 喂一块 raw 数据（len ≤ RAWSCAN_MAX_CHUNK），把命中的指针累加进 s->out。
 * 可以反复调用；分块喂与一次性喂的结果必须完全一致。
 */
void rawscan_feed(struct rawscan_state *s, const uint8_t *data, size_t len);

#endif /* RAWSCAN_H */
