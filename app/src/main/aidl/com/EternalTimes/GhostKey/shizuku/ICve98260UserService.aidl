// ICve98260UserService.aidl
package com.EternalTimes.GhostKey.shizuku;

import com.EternalTimes.GhostKey.shizuku.ICve98260Callback;

interface ICve98260UserService {
    void executeExploit(in byte[] profileBlob, in ICve98260Callback callback);
    // 多管理器：在 executeExploit 前告知本服务用户选定的 Root 管理器包名（null/空=自动）。
    void setManagerPackage(in String pkg);
    // 枚举设备上所有携带 ksud 的 Root 管理器。
    // 必须由服务侧（shell uid）执行：管理器的 ksud 在别的应用的 nativeLibraryDir 里，
    // App 进程（untrusted_app）读它会被 SELinux 拒绝，内容签名扫描恒为空。
    // 返回每行 "pkg\tversion\tlibPath"；budgetMs<=0 只查已知包名（毫秒级），
    // >0 时额外做一次全量兜底扫描（能认出随机改名的混淆 fork）。
    String listManagerPackages(long budgetMs);
    String getKernelRelease();
    boolean isShizukuReady();
    void destroy();
}
