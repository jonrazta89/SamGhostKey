// ICve98260Callback.aidl
package com.EternalTimes.GhostKey.shizuku;

interface ICve98260Callback {
    void onLog(String message);
    void onProgress(int stage, String status);
    void onComplete(int exitCode);

    // 以 **App 自身 uid** 执行 `su -c id`，返回原始输出（空串 = 失败）。
    //
    // 为什么要回调到 App：Shizuku UserService 跑在 shell（uid 2000）身份，
    // 而 KernelSU 的 superuser 授权是**按 uid** 管的 —— 用户在管理器里授权
    // 的是本 App 的 uid，对 uid 2000 不生效。所以 KSU 的 su 只能在 App 进程里试。
    //
    // 机制依据（上游 KernelSU v3.3.1 userspace/ksud/src/cli.rs:501）：
    //   "the kernel executes su with argv[0] = 'su' and replace it with us"
    // 内核在 execve 阶段把 su 替换成 ksud，且只对**已授权 uid** 替换；未授权时
    // execve 返回 ENOENT，shell 就报 "su: inaccessible or not found"。
    // 因此**不需要** /system/bin/su 真实存在。
    String probeSu();
}
