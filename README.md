# GhostKey — CVE-2026-98260 一键提权工具

GhostKey 是一款面向 **已授权安全研究 / 自用设备** 的 Android 一键提权（privilege escalation）工具。它基于 **Shizuku + NDK Native** 实现，把提权所需的 Native exploit、内核偏移表与 OTA boot 镜像解析能力打包进一个独立 APK，用户在手机上点击即可触发，无需 PC、无需命令行。

> ⚠️ **安全与法律责任**
> 本仓库仅用于 **授权环境下的安全研究** 与 **本人持有设备的合法测试**。
> 未经设备所有者明确授权，对他人设备执行提权、获取 root 或突破系统限制，可能违反所在地法律法规与平台服务条款。
> 使用本工具即表示你理解并自行承担由此产生的一切法律风险。作者不对任何滥用行为负责。
> 本仓库编译出来的文件有概率在注入阶段重启
---

## 功能特性

- **一键 ROOT**：手机端点击即完成提权流程，无需连接电脑、无需 adb 命令。
- **Shizuku 衔接**：通过 Shizuku 获取 `adb shell` 上下文，作为提权入口。
- **纯 APK + NDK Native**：exploit 的 C 源码随 APK 通过 NDK/CMake 编译进 `libcve98260.so`。
- **内置内核偏移表**：随 APK 分发多版本内核 profile，按 `uname -r` 精确匹配；无匹配时引导用户导入对应 `boot.img` 自动解析。
- **KASLR slide 精确反解**：从 trace 的 `call_site` + kallsyms 未重定位地址反解 slide，不依赖写死的内核内调用点锚点（6.18 开 LTO 后锚点已漂移）。
- **OTA boot 镜像解析**：内置 `BootImageParser` / `ImgToProfile` / `KallsymsExtractor`，支持从 boot 镜像反推内核符号与偏移。
- **KernelSU 衔接**：`KsuResolver` / `KsudStage` 负责与 KernelSU 集成。
- **运行日志分档**：每次提权运行按 `runId` 分组展示，失败诊断（`FailureDiagnoser`）对 `exit` 码（如 KASLR 解算失败 `exit=2`）给出专项引导。
- **终端面板**：实时回显 exploit 执行日志与阶段状态。

---

## 技术栈与构建环境

| 项目 | 版本 |
|---|---|
| `compileSdk` / `targetSdk` | 35 |
| `minSdk` | 31 |
| Kotlin | 1.9+（JVM target 17） |
| NDK / CMake | CMake 3.22.1，`ANDROID_STL=none` |
| Shizuku | 13.1.5 |
| Jetpack Compose | BOM 2024.10.00（Material3） |
| 目标 ABI | `arm64-v8a`（仅 64 位） |
| 产物命名 | `GhostKey-<版本>-arm64-v8a-release.apk` |

当前版本：**1.1.4**（versionCode 17，包名 `com.EternalTimes.GhostKey`）。

---

## 构建

> 本仓库采用 **release** 构建（开启 minify + shrinkResources，产物约 5.8 MB）。请勿使用 `assembleDebug`——旧 debug 密钥与 release 不同，覆盖安装需先卸载。

### 1. 准备签名密码

签名密钥位于 `app/keystore/release.keystore`（已被 `.gitignore` 忽略，**不会**进入版本库）。密码通过以下两种方式之一注入，**不要**写回源码：

- 方式 A：`local.properties` 追加（推荐，该文件已被忽略）
  ```properties
  CVE98260_STORE_PASSWORD=你的密码
  CVE98260_KEY_PASSWORD=你的密码
  ```
- 方式 B：环境变量
  ```bash
  export CVE98260_STORE_PASSWORD=你的密码
  export CVE98260_KEY_PASSWORD=你的密码
  ```

### 2. 编译 release APK

```bash
./gradlew assembleRelease
```

产物路径：`app/build/outputs/apk/release/GhostKey-1.1.4-arm64-v8a-release.apk`

---

## 目录结构（核心模块）

```
app/src/main/
├── kotlin/com/EternalTimes/GhostKey/
│   ├── Cve98260Application.kt        # Application 入口
│   ├── data/                       # 内核 profile 加载/解析/存储
│   │   ├── Profile.kt              # 内核 profile 数据模型
│   │   ├── BuiltinProfileCatalog.kt# 内置偏移表
│   │   ├── ProfileRepository.kt    # 精确 release 匹配（无回退）
│   │   ├── AssetConfigLoader.kt    # assets 配置加载
│   │   ├── LegacyProfileConverter.kt
│   │   ├── ProfileImportManager.kt # 用户导入 boot.img
│   │   ├── RunLogStore.kt         # 运行日志分档存储
│   │   ├── UserProfileStore.kt
│   │   └── ota/                   # BootImageParser / ImgToProfile / KallsymsExtractor
│   ├── device/                    # DeviceBinding / KernelProbe / PrivilegeGate
│   ├── engine/                    # ExploitEngine / FailureDiagnoser
│   ├── ksu/                       # KsuResolver / KsudStage
│   ├── model/                     # KernelProfile / ShizukuStatus / StageTracker ...
│   ├── native/                    # KernelProfileSerializer / NativeContract
│   ├── shizuku/                   # Cve98260UserService / ShizukuPermissionManager
│   ├── ui/                        # Compose 界面（MainScreen / LogViewerScreen / SettingsScreen）
│   └── viewmodel/                 # ExploitViewModel
├── aidl/com/EternalTimes/GhostKey/shizuku/ # Shizuku 跨进程接口
├── cpp/                           # Native exploit（CMake 构建为 libcve98260.so）
└── assets/ksu/                    # ksud 二进制
tool/
└── mkprofile.py                   # 离线生成器：boot.img → profile / kallsyms（纯标准库）
app/src/test/cpp/
├── run_c_tests.sh                 # 宿主 C 单测入口（自动选 clang / gcc）
├── test_calib_core.c              # calib_core 纯计算单测
└── test_slide_resolve.c           # slide 精确解算单测（6.18 适配新增）
```

---

## 使用流程（概览）

1. 在设备上安装并激活 **Shizuku**，对本应用授权。
2. 安装 KernelSU 管理器（用于接收提权结果）。
3. 打开 GhostKey，应用会探测内核版本并匹配内置偏移表；若无匹配，从设备导出 `boot.img` 导入以自动解析。
   - 6.18 机型**还需先推送 `kallsyms.txt`**，见 [6.18 内核适配](#618-内核适配小米-18-pro-max)。
4. 点击提权，实时查看终端日志与阶段状态；失败时根据 `FailureDiagnoser` 的专项诊断（校准 A/B、profile 匹配、tracefs 采样等）排查。
5. 提权为**临时 root**，设备重启后失效。

---

## 支持设备

内置内核 profile 覆盖多个 5.15 / 6.1 / 6.6 / 6.12 / 6.18 系列内核。已验证机型示例：

- OPPO Find X8 Ultra（PKJ110）— 内核 `6.6.118-android15-...`
- 小米 18 Pro Max（设备代号 **madrid**，Snapdragon 8 Elite Extreme Gen 6 / SM8975 / Art v2，Android 17，4K 页）— 内核 `6.18.21-android17-5-g284297031c53-abogki555938958-4k`

具体内核画像以 `app/src/main/kotlin/com/EternalTimes/GhostKey/data/BuiltinProfileCatalog.kt` 与 `app/src/main/assets/kernel_profiles/*.conf` 为准。

---

## 6.18 内核适配（小米 18 Pro Max）

原版 GhostKey 是在 **6.6.118** 上标定的，把三个 6.6 时代的内核布局常量写死了。
在 6.18.21 上这三个值全部失效，其中最致命的一个会让整条 trace 匹配链**永远匹配不到任何记录**。
本仓库已把它们改成 **BTF / 运行时实测驱动**，并新增精确解 KASLR slide 的算法，去掉了「写死内核内锚点」这个根本性缺陷。

> ⚠️ 内置的那条 OPPO 6.18.21 profile 是用**同一段有 bug 的导入代码**生成的 ——
> 「表里有 6.18」不等于「6.18 跑通过」。6.18 机型请以本节为准。

### 6.18 修正了什么

| # | 原版写法 | 6.6 的值 | 小米 18 Pro Max 真值 | 后果 |
|---|---|---|---|---|
| ① | `uaf_plant.c` trace 过滤 `req != 0x108` | 0x108 (264) | **0x180 (384)** | k_itimer 分配记录全被丢弃 → 任务地址泄露空转，第一步就死 |
| ② | `ImgToProfile.kt` `kitimer_node = 0x78` | 0x78 (120) | **0xe0 (224)** | 伪造的 timer 节点放错位置 → 摘链写坏内存 |
| ③ | `timer_link = do_timer_create+0xa8`、`cred_link = prepare_creds+0x24` | 6.6.118 标定 | **已漂移**（`+0xa8` 处是一条 `LDAR` 指令，不是调用点） | slide 带固定偏差 → 伪造 cred 里的 `root_user`/`init_user_ns` 全是错指针，卡在 `leak_cred` |
| ④ | `page_offset` 假设 DRAM 基址 `0x80000000` | SM8750 | **SM8975 = `0x0`** | 物理→虚拟换算整体偏 2 GB（`calib_b` 运行时扫描优先，profile 里只是兜底） |

对应代码改动：

| 文件 | 改动 |
|---|---|
| `app/src/main/cpp/slide_resolve.c` / `.h`（新增） | 精确解 KASLR slide：`call_site = F + slide + off` 且 `slide ≡ 0 (mod 2MiB)` ⇒ `off = (call_site - F) mod 2MiB` 唯一确定 ⇒ `slide = call_site - F - off`。零硬编码锚点、零盲扫、零歧义 |
| `app/src/main/cpp/calib.c` | 新增 `load_kallsyms_map()` / `trace_kmem_call_site()` / `calib_a_resolve_via_kallsyms()`；优先走新解法、失败回退旧法；把运行期 call_site 落盘到 `sites.kitimer` / `sites.cred` / `sites.task` |
| `app/src/main/cpp/uaf_plant.c` | 新增 `KITIMER_SIZE` / `CRED_SIZE`（profile 驱动）与 `SITE_*_RT`（运行期实测调用点）；写死锚点只在 6.6 系（`sizeof(k_itimer)==0x108`）可信，其余内核自动降级为「只按 req 匹配」 |
| `app/src/main/kotlin/.../ota/BootImageParser.kt` | BTF 解析新增 `kItimerLayout` / `cpuTimerLayout` |
| `app/src/main/kotlin/.../ota/ImgToProfile.kt` | `kitimer_node` 改为 BTF 实测（`k_itimer.it` + `cpu_timer.node`），BTF 取不到才回退 `0x78` |
| `app/src/main/assets/kernel_profiles/6.18.21-…-4k.conf` | 小米 18 Pro Max 专用 profile（`kitimer_size=384`、`kitimer_node=224`、`page_offset=-549755813888`） |
| `app/src/test/cpp/test_slide_resolve.c`（新增） | slide 解算宿主单测（精确恢复 / 负例 / 2000 组随机模糊测试） |

### 上机前必做：推送 kallsyms.txt

新解法要读 `$CVE98260_HOME/kallsyms.txt`（默认 `/data/local/tmp/cve98260-app/kallsyms.txt`），
内容是**未重定位**的符号地址（形如 `0xffffffc08021104c do_timer_create`）。
原生体以 shell 身份运行，这一步需要手动推：

```bash
adb push kallsyms.txt /data/local/tmp/cve98260-app/kallsyms.txt
adb shell chmod 644 /data/local/tmp/cve98260-app/kallsyms.txt
adb shell ls -l /data/local/tmp/cve98260-app/kallsyms.txt
```

> 没推的话 `calib_a` 会打印 `[calib_a] kallsyms map not found` 并**回退旧解法**；
> 6.18 上旧解法的 slide 带固定偏差，后续提权会失败。

### 跑起来盯这几行日志

| 阶段 | 期望日志 | 不出现意味着 |
|---|---|---|
| calibrate-a（新解法） | `[calib_a] trace: call_site=0x… func=do_timer_create req=0x180`<br>`[calib_a] resolved slide=0x…` | 文本 trace 里没有 `req=0x180` 的记录（probe 没造出定时器，或 trace 缓冲不够） |
| calibrate-a（兜底） | `[calib_a] slide = 0x…` | 走了兜底 → slide 可能带偏差，后续 cred 泄露会失败 |
| calibrate-b | `[calib_b] page_offset = 0x… (score=N/M)` | `score=fallback` → 线性映射基址用的默认值，物理换算可能偏 2 GB |
| exploit | `[uaf] captured=N chosen=0x…` | `captured=0` → req 过滤或调用点匹配仍有问题 |
| leak_cred | `[cred] ptrs=N` / `[cred] object=0x…` | `ptrs=0` → cred 分配点没匹配上 |
| verify | `uid=0(root)` | 前面对但没 root → 伪造 cred 的字段偏移不对 |

> 建议**先只跑到 `verify`**。`ksu-takeover` 会改写 boot 分区，bootloader 未解锁的设备可能变砖。

### 给别的设备生成 profile

`tool/mkprofile.py` 是离线生成器（纯标准库，不需要 root）：

```bash
python3 tool/mkprofile.py boot.img \
    -o profile/<release>.conf \
    --profile-json profile/<release>.json \
    --kallsyms profile/kallsyms.txt \
    --page-offset -549755813888
```

导入时在设置页选 **JSON 文件**即可（HOCON 是 JSON 的超集，标准 JSON 能被原样解析）；
若 App 版本只认 `.conf` 后缀，把 `.json` 改名成 `.conf` 也能读。

---

## 版本约定

- 产物统一命名 `GhostKey-<ver>-release.apk` 后交付 `dist/`（该目录已被 `.gitignore` 忽略，不进版本库）。

---

## 许可证

仅供授权安全研究与自用设备测试。任何超出授权范围的用途均不在许可范围内。
