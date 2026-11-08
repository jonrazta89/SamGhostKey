package com.EternalTimes.GhostKey.data.ota

/**
 * 内核内「分配调用点」解析器。
 *
 * kmem_cache_alloc tracepoint 记的 `call_site` 是 **调用方的返回地址**
 * （BL 的下一条指令），不是函数入口。GhostKey profile 里的
 * `timer_link` / `cred_link` / `task_alloc_link` 必须写这个地址：
 * 写成函数基址的话，trace 过滤一条都匹配不上（见 uaf_plant.c collect_nth）。
 *
 * 这个函数内偏移**每个内核构建都不同**（6.6 是 do_timer_create+0xa8、
 * 5.15 是 +0xa4、6.18 开 LTO 后漂到 +0xe8），只能从镜像实测：
 *   1. 找出函数体内所有 BL 指令；
 *   2. 取目标是 slab 分配器（kmem_cache_alloc / kmem_cache_alloc_node）的那些；
 *   3. 调用点 = BL 的下一条指令地址。
 *
 * 与 PC 端 tool/mkprofile.py 的 candidate_sites() 同算法。
 */
internal object AllocCallSiteResolver {

    /** k_itimer（posix_timers_cache）的分配调用点。 */
    const val KEY_TIMER = "timer"

    /** cred（cred_jar_cache）的分配调用点。 */
    const val KEY_CRED = "cred"

    /** task_struct（task_struct_cachep）的分配调用点。 */
    const val KEY_TASK = "task"

    /** slab 分配器符号：这些函数里的 BL 才是我们关心的分配调用点。 */
    private val ALLOC_SYMBOLS = setOf(
        "kmem_cache_alloc", "kmem_cache_alloc_node",
        "kmem_cache_alloc_trace", "kmem_cache_alloc_bulk",
    )

    /**
     * 「_text 落在镜像哪个文件偏移」的候选。
     *
     * PE/COFF 容器（高通/Xiaomi 5.15 GKI 常见）里 _text 就在文件偏移 0；
     * 裸 arm64 Image 里 _text 在头部页之后（0x1000）。写死任何一个都会让
     * BL 目标整体偏移同量，所以现场实测。
     */
    private val TEXT_OFFSET_CANDIDATES = intArrayOf(0x0, 0x1000, 0x40)

    /** 判定 text offset 时最多采样多少条 BL。 */
    private const val MAX_SAMPLE_BLS = 40000

    /** 判定 text offset 时只看镜像开头这么多字节。 */
    private const val SAMPLE_PREFIX = 0x400000

    /**
     * @param image 内核镜像字节
     * @param symbols 去歧义后的符号表（名字 → 链接期地址）
     * @param imageBase 镜像虚拟基址（链接期）
     * @return "timer"/"cred"/"task" → 调用点地址（链接期，未加 slide）
     */
    fun resolve(image: ByteArray, symbols: Map<String, Long>, imageBase: Long): Map<String, Long> {
        if (symbols.isEmpty()) return emptyMap()
        val textOffset = detectTextOffset(image, symbols, imageBase) ?: return emptyMap()
        val vas = symbols.values.sorted()
        val byVa = HashMap<Long, String>(vas.size * 2)
        for ((name, va) in symbols) byVa.putIfAbsent(va, name)

        val out = LinkedHashMap<String, Long>()
        allocSitesIn(image, symbols["do_timer_create"], vas, byVa, textOffset, imageBase)
            .singleOrNull()?.let { out[KEY_TIMER] = it }
        allocSitesIn(image, symbols["prepare_creds"], vas, byVa, textOffset, imageBase)
            .singleOrNull()?.let { out[KEY_CRED] = it }
        // task_struct 的 slab 分配点：5.15 在 dup_task_struct 里；
        // 6.6 把 dup_task_struct 内联进了 copy_process，两个都要试。
        val task = allocSitesIn(image, symbols["dup_task_struct"], vas, byVa, textOffset, imageBase)
            .singleOrNull()
            ?: allocSitesIn(image, symbols["copy_process"], vas, byVa, textOffset, imageBase)
                .singleOrNull()
        task?.let { out[KEY_TASK] = it }
        return out
    }

    /**
     * 实测「_text 位于镜像的哪个文件偏移」。
     *
     * BL 是 PC 相对指令：把候选偏移代入后，统计有多少条 BL 的目标恰好落在
     * 符号地址上，命中率最高的即正解（实测 PE 容器上 0x0 是 99.99%，
     * 0x1000 只有 0.7%）。
     */
    private fun detectTextOffset(
        image: ByteArray,
        symbols: Map<String, Long>,
        imageBase: Long,
    ): Int? {
        val vas = HashSet(symbols.values)
        var best: Int? = null
        var bestHit = -1
        val limit = minOf(SAMPLE_PREFIX, image.size - 3)
        for (cand in TEXT_OFFSET_CANDIDATES) {
            var hit = 0
            var total = 0
            var off = 0
            while (off + 4 <= limit) {
                val w = u32(image, off)
                if ((w and BL_MASK) == BL_OPCODE) {
                    total++
                    if (total > MAX_SAMPLE_BLS) break
                    val target = imageBase + (off - cand).toLong() + (blImm(w).toLong() shl 2)
                    if (target in vas) hit++
                }
                off += 4
            }
            if (hit > bestHit) {
                bestHit = hit
                best = cand
            }
        }
        return best
    }

    /**
     * 函数体内所有「调用 slab 分配器」的调用点（BL 的下一条指令地址）。
     *
     * 函数长度用下一个符号地址估（kallsyms 不带 size）：只要覆盖函数体即可。
     */
    private fun allocSitesIn(
        image: ByteArray,
        funcVa: Long?,
        vas: List<Long>,
        byVa: Map<Long, String>,
        textOffset: Int,
        imageBase: Long,
    ): List<Long> {
        if (funcVa == null) return emptyList()
        val end = vas.firstOrNull { it > funcVa } ?: (funcVa + 0x600)
        val start = (funcVa - imageBase + textOffset).toInt()
        val stop = (end - imageBase + textOffset).toInt()
        if (start < 0 || stop <= start || stop > image.size) return emptyList()
        val sites = ArrayList<Long>()
        var off = start and 3.inv()
        while (off + 4 <= stop) {
            val w = u32(image, off)
            if ((w and BL_MASK) == BL_OPCODE) {
                val va = imageBase + (off - textOffset).toLong()
                val target = va + (blImm(w).toLong() shl 2)
                val name = byVa[target]
                if (name != null && name in ALLOC_SYMBOLS) sites.add(va + 4)
            }
            off += 4
        }
        return sites
    }

    /**
     * BL 指令编码（arm64）：bits[31:26] = 100101。
     * 用有符号字面量写，保证常量类型是 Int（const 不接受 .toInt() 这类转换）。
     */
    private const val BL_MASK = -0x04000000
    private const val BL_OPCODE = -0x6C000000

    /** 取 BL 的 26 位有符号立即数（单位是 4 字节）。 */
    private fun blImm(w: Int): Int {
        var imm = w and 0x03FFFFFF
        if (imm and 0x02000000 != 0) imm -= 0x04000000
        return imm
    }

    private fun u32(d: ByteArray, o: Int): Int =
        (d[o].toInt() and 0xFF) or
            ((d[o + 1].toInt() and 0xFF) shl 8) or
            ((d[o + 2].toInt() and 0xFF) shl 16) or
            ((d[o + 3].toInt() and 0xFF) shl 24)
}
