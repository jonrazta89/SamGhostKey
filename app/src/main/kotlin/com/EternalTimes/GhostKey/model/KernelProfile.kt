package com.EternalTimes.GhostKey.model

/**
 * 内核偏移表（对应 NEW - 副本 的 offsets.h，按 uname -r 区分）。
 * 字段与原生 kernel_table.h 的 struct kernel_offsets 一一对应。
 */
data class KernelProfile(
    val release: String,
    val vulnType: String = "cve-2026-98260",
    val recommendShizuku: Boolean = true,
    val pageOffset: Long,
    val timerLink: Long,
    val credLink: Long,
    val selinuxLink: Long,
    val userNs: Long,
    val rootUser: Long,
    val groups: Long,
    val ucounts: Long,
    val taskCred: Int,
    val taskStructSize: Int,
    val credUid: Int,
    val kitimerNode: Int,
    val kitimerSize: Long = 0x108L,
    /**
     * `copy_process` 里 `kmem_cache_alloc_node(task_struct_cachep, …)` 的返回地址
     * （BL 的下一条指令），未加 slide。
     *
     * kmem_cache_alloc tracepoint 记录的 `call_site` 就是 `_RET_IP_`，因此用它可以
     * 精确定位 fork 的 task_struct 分配，**与 slab 对象尺寸无关** —— 这正是
     * `leak_task()` 在尺寸匹配失败时的兜底键。0 表示未知（老 profile），此时只按尺寸匹配。
     */
    val taskAllocLink: Long = 0L,
    /**
     * 伪造 cred 页涉及的 `struct cred` 布局（blob v4）。
     *
     * 跨 KMI 会平移：android15-8 起（6.6/6.12/6.18）cred 为 184 字节、
     * uid@8、caps 48..80、security@128、user@136；android13-8/14-11
     * （5.15/6.1）为 176 字节、整体前移 8。默认值即 android15-8 布局，
     * 保证老 profile（无这些字段）行为不变。
     */
    val credSize: Int = 184,
    val credCapInheritable: Int = 48,
    val credCapPermitted: Int = 56,
    val credCapEffective: Int = 64,
    val credCapBset: Int = 72,
    val credCapAmbient: Int = 80,
    val credSecurity: Int = 128,
    val credUser: Int = 136,
    val credUserNs: Int = 144,
    val credUcounts: Int = 152,
    val credGroups: Int = 160,
    /**
     * 该 profile **实测机型**（`ro.product.product-ro.product.device`，如 `madrid-madrid`）。
     *
     * 为什么需要它：内核 profile 是按 `uname -r` 精确匹配的，但**内核字符串相同
     * 不等于内核镜像相同**。`task_cred`（offsetof(task_struct, cred)）、
     * `cred_size`、`kitimer_node` 这些**结构体偏移来自 BTF**，而 BTF 随 vendor
     * config 片段变化 —— 这些量**无法在运行期验证**，套错机型的偏移就会往
     * task_struct 的错误字段写值，直接踩坏内核内存。
     *
     * 所以：声明了这个字段的 profile 只能用于该机型；别的机型命中同一个
     * `uname -r` 时会被**拦下**，提示导入本机 boot.img，而不是拿命去试。
     *
     * null = 不做机型校验（保持既有 profile 的行为不变；只有人工确认过的
     * profile 才应该填）。
     */
    val device: String? = null,
    /**
     * profile 的来源（`_source`），例如 `img:boot.img`。
     *
     * 只作日志线索：同一份 boot.img 会被同家族多个机型共用，所以它说明的是
     * 「这份内核镜像从哪来」，不是「只适用于哪台机器」。
     */
    val source: String? = null,
    /**
     * 生成该 profile 时所用 boot.img 的 sha256（`_image_sha256`）。
     *
     * 与设备实际固件的 boot.img 哈希逐字相同 ⇒ 内核镜像相同 ⇒ BTF 派生的
     * 结构体偏移（task_cred / cred_size / kitimer_node）适用。这是判断
     * 「这个 profile 能不能给别的机器用」最可靠的依据。
     */
    val imageSha256: String? = null,
)
