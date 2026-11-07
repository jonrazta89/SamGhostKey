# GhostKey — CVE-2026-98260 一键提权工具

> 主分支 **`main`** 为正式版线：包名 `com.EternalTimes.GhostKey`，当前以预发布工具链（AGP 9.6.0-alpha02 / Kotlin 2.5.0-Beta2）构建正式版 **2.0.0**。

面向 **已授权安全研究 / 自用设备** 的 Android 一键提权工具。基于 **Shizuku + NDK Native**，把 exploit、内核偏移表与 OTA boot 镜像解析打包进单个 APK，手机上点击即可触发，无需 PC / 命令行。

> ⚠️ **安全与法律责任**：仅用于授权环境下的安全研究与本人持有设备的合法测试。未经授权对他人设备提权、获取 root 或突破系统限制，可能违反所在地法律与平台条款；使用者自行承担一切风险，作者不对滥用行为负责。

---

## 下载

| 版本线 | 最新版本 | 快捷跳转 | 直接下载 APK |
|---|---|---|---|
| 正式版（`main`） | **2.0.0** | [Releases · Latest](https://github.com/EternalTimes/CVE-2026-98260-GhostKey/releases/latest) | [GhostKey-2.0.0-arm64-v8a-release.apk](https://github.com/EternalTimes/CVE-2026-98260-GhostKey/releases/download/v2.0.0/GhostKey-2.0.0-arm64-v8a-release.apk) |
| 测试线（`test`，预发布 `.test` 包） | **2.2.0-alpha06** | [v2.2.0-alpha06](https://github.com/EternalTimes/CVE-2026-98260-GhostKey/releases/tag/v2.2.0-alpha06) | [GhostKey-2.2.0-alpha06-arm64-v8a-release.apk](https://github.com/EternalTimes/CVE-2026-98260-GhostKey/releases/download/v2.2.0-alpha06/GhostKey-2.2.0-alpha06-arm64-v8a-release.apk) |

> 测试线为 `.test` 包名（`com.EternalTimes.GhostKey.test`），可与正式版共存。全部历史版本见 [Releases 页面](https://github.com/EternalTimes/CVE-2026-98260-GhostKey/releases)。

---

## 反馈与适配请求

遇到问题（提权失败、崩溃、异常重启等）或希望适配新的内核 / 机型，请到 [GitHub Issues](https://github.com/EternalTimes/CVE-2026-98260-GhostKey/issues) 提交，并**优先附上内核信息**——profile 以内核 `uname -r` 精确匹配，这是定位问题的第一依据。

请尽量包含：

1. **内核版本 `uname -r`**（最优先，如 `6.18.21-android17-...`）。
2. **运行日志**：设置页「查看运行记录」导出，或设备上 `/data/local/tmp/cve98260-app/` 下的日志文件。
3. 机型与 Android 版本、复现步骤、所用 App 版本（界面底部 `v<版本> · <commit>`）。
4. 涉及崩溃 / 异常重启时，可运行 `tool/collect_reboot_evidence.sh` 采集 pstore / dropbox / crash buffer / avc 等证据一并附上，便于定位。

---

## 功能特性

- **一键 ROOT**：手机端点击完成提权，无需连接电脑、无需 adb 命令。
- **Shizuku 入口**：经 Shizuku 取得 `adb shell` 上下文作为提权入口。
- **纯 APK + NDK Native**：exploit 的 C 源码经 NDK/CMake 编入 `libcve98260.so`。
- **内置内核偏移表**：按 `uname -r` 精确匹配多版本 profile；无匹配时引导导入 `boot.img` 自动解析。
- **KASLR slide 精确反解**：从 trace `call_site` + kallsyms 未重定位地址反解，不依赖写死的内核锚点。
- **OTA boot 镜像解析** + **KernelSU 衔接**：从 boot 镜像反推内核符号/偏移，并与 KernelSU 集成。
- **运行日志分档 + 失败诊断**（`FailureDiagnoser`），配实时终端面板。

---

## 技术栈与构建环境

| 项目 | 版本 |
|---|---|
| Gradle / AGP | Gradle 9.8.2 / AGP 9.6.0-alpha02（预览） |
| `compileSdk` / `targetSdk` / `minSdk` | 37（minor 2）/ 37 / 31 |
| Kotlin | 2.5.0-Beta2（预发布） |
| Java 字节码 | source/target 27，jvmTarget 27（构建需 JDK 27；`java`/`lint` toolchain 均锁 27） |
| NDK / CMake | CMake 3.22.1，`ANDROID_STL=none` |
| Shizuku | 13.1.5 |
| Jetpack Compose | BOM 2024.10.00（Material3） |
| 目标 ABI | `arm64-v8a`（仅 64 位） |

当前版本：**2.0.0**（versionCode 24，包名 `com.EternalTimes.GhostKey`）。

> Kotlin 2.5.0-Beta2 为预发布版，插件与 stdlib 走 JetBrains bootstrap 仓库（见 `settings.gradle.kts`）。

---

## 构建

采用 **release** 构建（minify + shrinkResources，产物约 5.5 MB）。勿用 `assembleDebug`——debug 与 release 密钥不同，覆盖安装需先卸载。

签名密钥位于 `app/keystore/release.keystore`（已 `.gitignore`，不进版本库）。密码二选一注入，**勿写回源码**：

- `local.properties`：`CVE98260_STORE_PASSWORD` / `CVE98260_KEY_PASSWORD`
- 或同名环境变量

```bash
./gradlew assembleRelease
# 产物：app/build/outputs/apk/release/GhostKey-2.0.0-arm64-v8a-release.apk
```

---

## 使用流程

1. 设备安装并激活 **Shizuku**，对本应用授权。
2. 安装 KernelSU 管理器（用于接收提权结果）。
3. 打开 GhostKey，自动探测内核版本并匹配内置偏移表；无匹配时导出 `boot.img` 导入自动解析。
4. **6.18 机型需先推送 kallsyms**（未重定位符号地址；原生体以 shell 身份运行，需手动推）：
   ```bash
   adb push kallsyms.txt /data/local/tmp/cve98260-app/kallsyms.txt
   adb shell chmod 644 /data/local/tmp/cve98260-app/kallsyms.txt
   ```
   未推送时 `calib_a` 回退旧解法，6.18 上 slide 带固定偏差 → 提权失败。
5. 点击提权，实时查看终端日志与阶段状态；失败按诊断提示排查。
6. 提权为 **临时 root**，设备重启后失效。

> 默认只跑到 `verify` 阶段。`ksu-takeover` 通过 `late-load` 把 KernelSU 模块动态加载进当前运行的内核，**不写任何分区**（boot 分区不被改写），重启后失效，无变砖风险。

---

## 支持设备

内置 profile 覆盖 5.15 / 6.1 / 6.6 / 6.12 / 6.18 系列内核。已验证机型：OPPO Find X8 Ultra（`6.6.118-android15-...`）、小米 18 Pro Max（代号 **madrid** / SM8975 / `6.18.21-android17-...`）。以内核 `uname -r` **精确**匹配为准；机型配置（`app/src/main/assets/device_profiles/`）只是加速层，缺失不影响能否跑通。

给新设备生成 profile（离线、纯标准库、不需 root）：

```bash
python3 tool/mkprofile.py boot.img -o <release>.conf \
    --profile-json <release>.json --kallsyms kallsyms.txt \
    --page-offset -549755813888
```

---

## 关键运行须知

- **SELinux**：利用链会临时把 SELinux 由 Enforcing 改为 Permissive。只跑到 `verify` 时结束后保持 Permissive；`ksu-takeover` 成功后内核会切回 Enforcing。需要时 `adb reboot` 恢复。
- **KernelSU 的 su**：KSU 没有 `/system/bin/su` 文件，内核在 `execve` 阶段按调用方 uid 替换 `su`，只有被授权的 uid 才探测得到。本工具走 App 自身 uid 通道探测。
- **内置 ksud 与维护**：`ksu-takeover` 阶段用 `ksud late-load` 加载 KernelSU 模块（默认只到 `verify` 不触发）。APK 内置一份 `assets/ksu/ksud`（KernelSU v3.3.1，内嵌多套 KMI 的 `.ko`，KMI 集**冻结在打包时刻**）作为首选候选；接管时也会优先复用**设备已装管理器**里的 `libksud.so`（版本随管理器走、无需更新本应用）。内置产物由 `assets/ksu/ksud.manifest` 记录版本与 `sha256`，构建时（`preBuild`）自动校验；换二进制后运行 `python3 tool/check_ksud.py --update` 同步清单。
- **SuKiSu 支持**：SukiSU / SukiSU Ultra（`com.sukisu.ultra`）、ReSukiSU、KernelSU-Next 等 KernelSU fork 的管理器仍携带 `libksud.so`、late-load 语义一致、模块仍注册为 `kernelsu`，因此**直接复用设备已装的 SuKiSu** 完成接管，无需为本应用单独打包 SuKiSu 产物。
- **allow_shell**（默认关闭）：如需 shell（uid 2000）也能用 su，设备侧写开关文件后**必须重新加载模块**才生效：`adb shell 'echo 1 > /data/local/tmp/cve98260-app/allow_shell'`。

---

## 版本约定

正式版产物命名 `GhostKey-<ver>-arm64-v8a-release.apk`，构建后复制到仓库根 `release/`（已被 `.gitignore` 忽略，不进版本库），并以 **GitHub Release 附件**形式发布。

---

## 许可证

仅供授权安全研究与自用设备测试。任何超出授权范围的用途均不在许可范围内。
