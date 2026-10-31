#ifndef KSU_SCRIPT_H
#define KSU_SCRIPT_H

/*
 * 生成 KSU 接管脚本（ksud 候选阶梯）。
 *
 * ksuds / n_ksuds：按优先级排列的 ksud 候选路径（已存在的文件）。
 * kmi：KMI（如 android17-6.18）。
 * log：脚本日志落盘路径。
 * allow_shell：非 0 时给 late-load 传 --allow-shell。
 *
 *   上游 v3.3.1 userspace/ksud/src/late_load.rs：allow_shell 会变成模块加载
 *   参数 allow_shell=1，含义是「Always allow shell to get root permission」。
 *   **只在模块首次加载时生效** —— late_load::run 开头就检查 has_kernelsu()，
 *   已加载就直接跳过 load_module，参数无处可施。所以默认关闭。
 *
 * 返回 0 成功，-1 打不开文件。
 */
int ksu_write_takeover_script(const char *path, char ksuds[][512], int n_ksuds,
			      const char *kmi, const char *log, int allow_shell);

#endif /* KSU_SCRIPT_H */
