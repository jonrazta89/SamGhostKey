// ICve98260UserService.aidl
package com.EternalTimes.GhostKey.shizuku;

import com.EternalTimes.GhostKey.shizuku.ICve98260Callback;

interface ICve98260UserService {
    void executeExploit(in byte[] profileBlob, in ICve98260Callback callback);
    String getKernelRelease();
    boolean isShizukuReady();
    void destroy();
}
