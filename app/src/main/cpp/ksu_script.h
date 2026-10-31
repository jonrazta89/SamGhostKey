#ifndef KSU_SCRIPT_H
#define KSU_SCRIPT_H

/*
 * 生成 KSU 接管脚本（ksud 候选阶梯）。
 *
 * ksuds / n_ksuds：按优先级排列的 ksud 候选路径（已存在的文件）。
 * 返回 0 成功，-1 打不开文件。
 */
int ksu_write_takeover_script(const char *path, char ksuds[][512], int n_ksuds,
			      const char *kmi, const char *log);

#endif /* KSU_SCRIPT_H */
