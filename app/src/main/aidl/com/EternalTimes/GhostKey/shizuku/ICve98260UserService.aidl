// ICve98260UserService.aidl
package com.EternalTimes.GhostKey.shizuku;

import com.EternalTimes.GhostKey.shizuku.ICve98260Callback;

interface ICve98260UserService {
    void executeExploit(in byte[] profileBlob, in ICve98260Callback callback);
    // 多管理器：在 executeExploit 前告知本服务用户选定的 Root 管理器包名（null/空=自动）。
    void setManagerPackage(in String pkg);
    String getKernelRelease();
    boolean isShizukuReady();
    void destroy();
}
