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

当前版本：**1.1.8**（versionCode 21，包名 `com.EternalTimes.GhostKey`）。

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

产物路径：`app/build/outputs/apk/release/GhostKey-1.1.4-arm64-v8a-release.apk`，
交付副本放在仓库根的 `release/`（`release/GhostKey-1.1.8-arm64-v8a-release.apk`）。

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
│   ├── device/                    # DeviceBinding / KernelProbe / PrivilegeGate / DeviceProfile
│   ├── engine/                    # ExploitEngine / FailureDiagnoser
│   ├── ksu/                       # KsuResolver / KsudStage
│   ├── model/                     # KernelProfile / ShizukuStatus / StageTracker ...
│   ├── native/                    # KernelProfileSerializer / NativeContract
│   ├── shizuku/                   # Cve98260UserService / ShizukuPermissionManager
│   ├── ui/                        # Compose 界面（MainScreen / LogViewerScreen / SettingsScreen）
│   └── viewmodel/                 # ExploitViewModel
├── aidl/com/EternalTimes/GhostKey/shizuku/ # Shizuku 跨进程接口
├── cpp/                           # Native exploit（CMake 构建为 libcve98260.so）
├── assets/
│   ├── kernel_profiles/           # 内核 profile（按 uname -r 精确匹配）→ 决定正确性
│   ├── device_profiles/           # 机型配置（按 product-device 匹配）→ 决定快慢
│   └── ksu/                       # ksud 二进制
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

具体内核画像以 `app/src/main/kotlin/com/EternalTimes/GhostKey/data/BuiltinProfileCatalog.kt` 与 `app/src/main/assets/kernel_profiles/*.conf` 为准；
机型级加速配置在 `app/src/main/assets/device_profiles/`（见「机型配置」一节），**缺失不影响能否跑通**。

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
| ⑤ | raw trace 记录按 `site@0 ptr@8 bytes_req@16` 定长解析 | ≤ 6.6 的布局 | **6.18 在 `ptr` 与 `bytes_req` 之间插了 8 字节 `__string(name, s->name)` 描述符** → `bytes_req` 移到 `@24` | 整体偏 8 字节，每条记录都被「ptr 不是内核地址」判掉 → 「no k_itimer records found」 |
| ⑥ | `task_struct_size` 直接取 BTF 的 `sizeof(struct task_struct)` | — | **slab 实际 `object_size` = sizeof + THREAD_SIZE**（`CONFIG_THREAD_SIZE_IN_TSK` 内嵌栈），真机 6.18 实测 `0x1680 (5760)` vs BTF `4736` | 尺寸窗口差一截 → `task_struct` 分配点匹配不到 → 拿不到子进程的 task 地址 |

真机实测值（小米 18 Pro Max / madrid / `6.18.21-android17-5-g284297031c53-abogki555938958-4k`）：

| 量 | 实测值 |
|---|---|
| `sizeof(struct k_itimer)` | `0x180` (384) |
| k_itimer 分配调用点 | `do_timer_create+0xe8`（6.6 profile 写死的是 `+0xa8`，**正好差 0x40**） |
| cred 分配调用点 | `prepare_creds+0x30`，slab cache 名 `cred`，`bytes_req=184` |
| task_struct 分配调用点 | `dup_task_struct+0x54`，slab cache 名 `task_struct`，`bytes_req=0x1680 (5760)` |
| `sizeof(struct cred)` | `184`（与 BTF 一致，`cred` cache 的 `object_size` 就是它） |

对应代码改动：

| 文件 | 改动 |
|---|---|
| `app/src/main/cpp/slide_resolve.c` / `.h`（新增） | 精确解 KASLR slide：`call_site = F + slide + off` 且 `slide ≡ 0 (mod 2MiB)` ⇒ `off = (call_site - F) mod 2MiB` 唯一确定 ⇒ `slide = call_site - F - off`。零硬编码锚点、零盲扫、零歧义 |
| `app/src/main/cpp/calib.c` | 新增 `load_kallsyms_map()` / `text_trace_collect_sites()` / `calib_a_resolve_via_kallsyms()` / `calib_a_probe_alloc_sites()`；优先走新解法、失败回退旧法；把运行期 call_site 落盘到 `sites.kitimer` / `sites.cred` / `sites.task`，把运行期 slab 尺寸落盘到 `task_size.txt` |
| `app/src/main/cpp/calib_core.c` | 新增 `calib_scan_kmem_recs()`（**布局自适应**的 raw 记录解析）、`calib_pick_trusted_site()`（分配点语义自证）、`calib_parse_psym()`（解析 `%pS` 符号串） |
| `app/src/main/cpp/uaf_plant.c` | 新增 `KITIMER_SIZE` / `CRED_SIZE`（profile 驱动）与 `SITE_*_RT`（运行期实测调用点）、`TASK_SIZE_RT`（运行期实测 task_struct 尺寸）；写死锚点只在 6.6 系（`sizeof(k_itimer)==0x108`）可信，其余内核自动降级为「只按 req 匹配」 |
| `app/src/main/kotlin/.../ota/BootImageParser.kt` | BTF 解析新增 `kItimerLayout` / `cpuTimerLayout` |
| `app/src/main/kotlin/.../ota/ImgToProfile.kt` | `kitimer_node` 改为 BTF 实测（`k_itimer.it` + `cpu_timer.node`），BTF 取不到才回退 `0x78` |
| `app/src/main/assets/kernel_profiles/6.18.21-…-4k.conf` | 小米 18 Pro Max 专用 profile（`kitimer_size=384`、`kitimer_node=224`、`page_offset=-549755813888`） |
| `app/src/test/cpp/test_calib_core.c` | 新增 `calib_pick_trusted_site` / `calib_parse_psym` 单测（75 checks） |
| `app/src/test/cpp/test_slide_resolve.c`（新增） | slide 解算宿主单测（精确恢复 / 负例 / 2000 组随机模糊测试） |

### 运行期调用点解析：cred / task_struct

trace 匹配需要知道「cred 对象是从哪个调用点分配的」「task_struct 对象是从哪个调用点
分配的」。这两个值随内核版本漂移（6.18 开 LTO 后 `prepare_creds+0x24` 之类的写死锚点
已失效），所以只能**运行期实测**。

`calib_a` 因此分成两段探针：

1. **第一段（k_itimer）**：造 2048 个定时器，拿到 `do_timer_create` 的运行期 call_site，
   据此解 KASLR slide。文本 trace 给「符号名 + 函数内偏移」，raw trace 给「数值地址」，
   两条路径独立算出同一个 slide，互为交叉验证。
2. **第二段（cred / task_struct）**：`fork()` 一次同时触发
   `copy_process → dup_task_struct`（task_struct slab）与 `copy_creds → prepare_creds`
   （cred slab），于是一个窗口里两个尺寸的分配点都有了。

第二段的关键是**按 cache 名定位**，而不是按尺寸猜。6.18 的 `kmem_cache_alloc` 文本记录
带 `name=<cache>`，于是能直接认准 `cred` 与 `task_struct` 两个 cache。

> **task_struct 的 slab 尺寸 ≠ BTF 的 `sizeof(struct task_struct)`**
> `CONFIG_THREAD_SIZE_IN_TSK` 把栈内嵌进 `task_struct`，真机 6.18 实测
> `bytes_req = 0x1680 (5760)`，而 BTF 推出来的是 `4736`（差一个 `THREAD_SIZE=1024`）。
> 所以这个尺寸只能运行期实测，落盘到 `task_size.txt`，`exploit` 阶段用它做尺寸窗口；
> profile 里的 BTF 值退化为兜底。

### 两个静默失效的解析 bug（都曾让「文本 trace 交叉验证」整条路径是死的）

这两处都不报错、只是**恒定解析不出正确值**，排查时极具迷惑性：

| 位置 | 错误写法 | 正确写法 | 后果 |
|---|---|---|---|
| `%pS` 符号串解析 | `strtoull(q + 2, ...)`（`q` 指向 `+`） | `strtoull(q + 3, ...)` | `q+2` 落在 `'x'` 上，不是合法十六进制字符 → 函数内偏移恒为 `0` → slide 算成 `site - F`，不是 2 MiB 对齐 → 交叉验证永远判定不自洽 |
| kallsyms 符号名指针 | `nstart = p + strspn(p, " \t")` | 先跳过 VA token 再跳空白 | 行首是 VA（`0xffffffc08021104c do_timer_create`），`strspn` 匹配 0 个字符 → `name` 变成整行文本 → 按名字查表从未命中 |

修掉之后，真机上两条独立路径（文本符号+偏移法 / 2 MiB 对齐法）算出**同一个 slide**，
cred / task 调用点也从 `cred=0 task=0` 变成可用的运行期地址。

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
| calibrate-a（主路径） | `[calib_a] text trace: call_site=do_timer_create+0xe8 -> slide=0x…` | 文本 trace 里没有 `bytes_req=0x180` 的记录（probe 没造出定时器，或 trace 缓冲不够）；会退回 2 MiB 对齐法 |
| calibrate-a（交叉验证） | `[calib_a] 2MiB method: … off=0xe8 -> slide=0x…` | 两条独立路径算出的 slide 必须一致；不一致说明 kallsyms 与运行内核不是同一份 |
| calibrate-a（调用点） | `[calib_a] cred alloc site=0x… (func=prepare_creds)`<br>`[calib_a] task alloc site=0x… (func=dup_task_struct)`<br>`[calib_a] task_struct object_size=0x…` | 缺这几行 → cred / task 调用点没解析出来，exploit 只能按尺寸兜底匹配 |
| calibrate-a（raw 采集） | `[calib_a] raw capture: N bytes in M ms (idle window 400 ms)` | 耗时接近 8000 ms → 空闲早停没生效（缓冲一直在产生新数据），采集会拖慢整条链路 |
| calibrate-b | `[calib_b] page_offset = 0x… (score=N/M)` | `score=fallback` → 线性映射基址用的默认值，物理换算可能偏 2 GB |
| 机型配置 | `<s> device profile madrid-madrid: trusted by device profile …`<br>`<b> linear map base = 0x… (…; skipping calibrate-b)` | 没有这行 → 没命中机型配置，`calibrate-b` 照常跑（慢 9 秒，但结果一样对） |
| exploit | `[config] runtime call sites: kitimer=0x… cred=0x… task=0x…`<br>`[uaf] captured=N chosen=0x…` | `cred=0` / `task=0` → 调用点没落盘；`captured=0` → req 过滤或调用点匹配仍有问题 |
| exploit（提权） | `[cred] answer uid=0 euid=0 gid=0 egid=0` | 出现的是 `uid=2000` → 伪造 cred 的字段偏移或 task 地址不对 |
| exploit（收尾） | `[cred] child ack: daemon`<br>`[cred] main process exiting, child becomes daemon`<br>`[rootd] listening at … pid=…`<br>`C98260_ROOTD_READY=1` | 主进程要带 `--daemon-exit` 才会走这条路径；否则会驻留等待子进程（见下） |
| verify | `uid=0(root)` | 前面对但没 root → 临时 root 通道没建立 |
| KSU 接管 | `[ksu] kmi=… candidates=N allow_shell=0`<br>`[ksu] live=yes ksud=…`<br>`[ksu] ksud_installed=/data/adb/ksu/bin/ksud size=…` | `live=no` → late-load 没把模块注册起来；`ksud_installed` 缺失 → 内核替换 `su` 用的用户态组件还没装好（v1.1.8 起会等 6 秒） |
| KSU 的 su | `independent su (app uid NNNNN) => uid=0(root) … context=u:r:ksu:s0` | 报 `su: inaccessible or not found` → **该 uid 没被授权**，去 KSU 管理器「超级用户」里授权本 App |

> **`--daemon-exit` 是宿主模型**：不带这个参数时主进程会一直驻留等待 cred 子进程退出
> （子进程要一直持有被伪造的 cred 页），这是参考实现的语义，不是卡死。App 侧的
> `Cve98260UserService` 固定会带上它。

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

## 机型配置（device profile）

> **机型配置是加速层，不是准入闸门。**
> 漏洞能否跑通取决于**内核参数**，与商用机型无关 —— 同 SoC 同 KMI 的不同机型用同一份
> 内核 profile 就够了。所以机型**不参与放行判断**（见 `device/DeviceBinding.kt`
> 里「v1.0.6 起移除机型锁」的说明：机型锁会误伤同 SoC 同 KMI 的设备）。
> 机型配置只回答另一个问题：**这台机器上，有哪些量是每次启动都不变的？**

### 为什么需要它

有几个量是**编译期常量**，每次启动都一样，却要靠运行时扫描确认一遍：

| 量 | 为什么是常量 | 运行时扫描的代价 |
|---|---|---|
| `page_offset`（线性映射基址） | 由 VA bits 与页大小决定，**不随 KASLR 变** | `calibrate-b` 造 4096 个定时器 + 扫 8 个 CPU 的 raw trace，实测 **9 秒** |
| `task_struct` 的 slab `object_size` | `CONFIG_THREAD_SIZE_IN_TSK` 内嵌栈，内核构建时定死 | 只能运行期实测（BTF 的 `sizeof` 少一个 `THREAD_SIZE=1024`） |

真机 2026-10-31 的一次完整链路耗时 **39 秒**，`calibrate-b` 就占 9 秒；
把 `page_offset` 记进机型配置后这一步可以直接跳过。

### 目录与格式

```
app/src/main/assets/device_profiles/
├── madrid-madrid.conf      # 小米 18 Pro Max（product=device=madrid）
└── <product>-<device>.conf # 其它机型
```

查找顺序：`<product>-<device>.conf` → `<product>.conf` → 都没有就用全量运行时扫描
（**永远有退路**：机型配置缺失只是慢一点，不会跑不了）。

```hocon
{
  product = "madrid"
  device = "madrid"
  model = "Xiaomi M154FF"
  soc = "SM8975"

  page_size = 4096                       # 必须与运行时一致（4K/16K/64K 的 PAGE_OFFSET 不同）
  page_offset = 0xffffff8000000000      # 线性映射基址（编译期常量）
  page_offset_trusted = 1               # 人工确认过 → 允许跳过 calibrate-b

  task_struct_object_size = 5760        # slab object_size 实测（含内嵌内核栈）

  flow = {
    calib_a = { probe = 2048, hold = 2 } # 探针参数
  }
}
```

### 三条硬规则

1. **KASLR slide 绝不能进机型配置** —— 它每次启动都变，必须运行时解；写死会直接让
   注入失败（伪造的 cred 里全是错指针）。这是唯一必须运行时才知道的量。
2. **`page_offset_trusted = 1` 之前必须先确认** —— 页大小与运行时对不上时，
   物理→虚拟换算整体偏移，表现为「注入成功但偏移全错」。宿主在运行时比对页大小
   （`Os.sysconf(_SC_PAGESIZE)`），对不上就自动放弃这份配置、退回 `calibrate-b` 扫描。
3. **机型配置不改变放行判断** —— 内核 profile 仍然按 `uname -r` **精确**匹配，
   没有精确匹配就是没有，不会因为「这台机型我配过」而放行。

### 给别的设备生成机型配置

1. 在该设备上跑通一次完整链路，从日志里取 `page_offset` 与 `task_struct object_size`；
2. 照着 `madrid-madrid.conf` 复制一份，改 `product` / `device` / `page_size` /
   `page_offset`；
3. `page_offset_trusted` 先写 `0`，确认过一次再改成 `1`（改成 1 之前会照常跑
   `calibrate-b`，日志里的 `score` 就是对照依据）。

---

## 越狱流程与耗时优化

2026-10-31 真机全链路首次跑通耗时 **39 秒**（`15:03:37 → 15:04:16`），
v1.1.6 优化后实测 **20 秒**（`16:06:00 → 16:06:20`），逐段拆开：

| 阶段 | 首次耗时 | v1.1.6 实测 |
|---|---|---|
| `calib_a` 第一段（k_itimer 探针 + 解 slide） | 11 s | **3 s** |
| `calib_b`（`page_offset` 扫描） | 9 s | **0 s**（命中机型配置时跳过） |
| `exploit` 注入（SELinux 翻转 + 伪造 cred） | 15 s | 12 s |
| KSU 接管 | 4 s | 4 s |
| **合计** | **39 s** | **20 s** |

> **为什么同一版会有 20 s / 30 s 的波动？** 不是版本回退，是**伪造 cred 第一次没打中**。
> 落点 `off` 是随机偏移（伪造的 cred 必须正好落在 child 的 `task->cred` 那个
> 8 KiB slab 页里的相同偏移上），命中概率不是 100%。第一轮失败会重跑一轮，
> 每轮约 9–10 秒 —— 所以「20 s → 30 s」通常就是**多了一轮重试**。
> 日志里看 `[cred] plant attempt 1/12` 与 `[cred] plant attempt 2/12` 就能确认。
> 跑之前先 `adb reboot` 可以清掉残留的 rootd / cred holder，减少这一轮翻车。

### ① raw 采集不再空转到超时（`calib.c`）

`trace_pipe_raw` 是**活管道**：per-CPU 环形缓冲排空后不会 EOF，只能靠超时收尾。
旧实现一直 poll 到 8 秒超时，实测「text trace 抓到」到「captured raw=…」之间
整整隔了 7 秒 —— 那 7 秒全在空转。

现在改成**空闲早停**：连续 400 ms 没有新数据就认为读完了（采集前 `tracing_on`
已关，缓冲里的数据是冻结的，排空即结束）。`seconds` 仍作为硬上限保留。
一条都没读到时仍按老行为等到超时 —— 避免把「没抓到」误判成「抓完了」。

> `cred` / `task_struct` 的调用点**本来就是从文本 trace 解析的**
> （`resolve_alloc_site_by_name()` → `text_trace_collect_sites()`），
> 14 MB 的 raw 只用于 slide 的**交叉验证**与文本路径失效时的兜底。

### ② `calibrate-b` 在命中机型配置时跳过

见上文「机型配置」。

### ③ KSU 接管：ksud 候选阶梯（`ksu.c` / `ksu_script.c`）

设备上同时存在两个不同版本的 ksud：

| 来源 | 大小 | 能力 |
|---|---|---|
| KernelSU 管理器里的 `libksud.so` | 4 990 848 B | 旧版，只认 `-h` / `-V`，**不支持 `late-load`** |
| APK 自带的 `assets/ksu/ksud` | 6 402 736 B（sha256 `049491e2b4cc0a6c…`，版本串 `32680` / `3.3.1`） | 与本 APK 的 KMI 集配套；与设备上的 KSU 管理器 v3.3.1 (32680-5) **同版本** |

内置那个是**首选候选**（2026-10-31 真机：只有它 `late-load` 成功、模块注册成功）；
管理器里那个仍会被暂存到 `/data/local/tmp/ksud`，作为阶梯里的**兜底**。

候选顺序：`CVE98260_KSUD` → `$CVE98260_HOME/ksud` → `/data/adb/ksu/bin/ksud`
→ `/data/adb/ksud` → `/data/local/tmp/ksud`。

脚本对每个候选先 `late-load --kmi <KMI>`、再裸 `late-load`，直到模块真的出现在
`/proc/modules` 里，日志记 `ksud_used=`。

> **模块注册是异步的，必须轮询。** 上游 `late_load.rs:39` 里 `ksud late-load`
> **第一件事就是 `daemonize()`** —— 命令立刻返回，真正的 `load_module` 在后台
> 子进程里做。旧实现 `sleep 1` 采样一次就下结论，正好撞在这个竞态上，会误判成
> 「没加载」并白跑下一个候选。现在改成最多轮询 6 秒。

### ④ KernelSU 的 su 是怎么来的（这一条最容易误判）

**KernelSU 根本没有 `/system/bin/su` 这个文件。** 内核模块在 `execve` 阶段把
`su` 替换成 ksud —— 上游 v3.3.1 `userspace/ksud/src/cli.rs:501` 原文：

> the kernel executes su with argv[0] = "su" and replace it with us

而且**只对被授权的 uid 替换**。没被授权时 `execve` 返回 `ENOENT`，shell 就报
`su: inaccessible or not found`。

两个直接后果：

1. **「有没有 su」取决于调用方的 uid，而不是某个文件存在与否。** 本工具的
   Shizuku UserService 跑在 **uid 2000（shell）** 身份，而你在 KSU 管理器里
   授权的是 **App 自己的 uid** —— 对 uid 2000 无效。于是「模块明明加载了、
   管理器明明显示工作中」，探测却一直说没有 su。
2. su 探测必须**走两条通道**：
   - **App 通道**：由 App 进程用**自己的 uid** 执行 `su -c id`（AIDL 回调
     `ICve98260Callback.probeSu()`）—— 这是用户在 KSU 管理器里授权的那条。
   - **shell 通道**：UserService 以 uid 2000 执行 —— 只有在模块带
     `allow_shell=1` 加载（上游 `late-load --allow-shell`）时才有效。

> `allow_shell` 是**模块加载参数**，只在模块**首次加载**时生效 ——
> `late_load::run` 开头就检查 `has_kernelsu()`，已加载则跳过 `load_module`，
> 参数无处可施。所以**默认关闭**。
>
> **打开方式（v1.1.8 起）**：在设备上写一个开关文件：
>
> ```bash
> adb shell 'echo 1 > /data/local/tmp/cve98260-app/allow_shell'
> ```
>
> 关掉就删掉该文件（或写入 `0`）。开关放在设备侧而不是 App 的 SharedPreferences，
> 是因为 UserService 跑在 **Shizuku 进程（uid 2000）**，读不到 App 私有目录。
>
> ⚠️ **已加载的模块不会因为这个开关而改变参数。** 要让它真正生效，必须让模块
> 重新加载（先卸载/重启，再走一次 late-load）。本工具在 `allow_shell=1` 时会
> 明确打一行提示，避免「开关开了却不生效」的困惑。

另外：**KernelSU 没有 Magisk 那种常驻 daemon。** `late-load` 自带的后台进程跑完
stage 脚本、重启管理器之后就退出了；用户态组件由 `late_load::run` 内部的
`utils::install()` 装到 `/data/adb/ksud`（并建 `/data/adb/ksu/bin/ksud` 软链），
**内核替换 su 用的就是它**。旧实现额外 `nohup ksud &` 起的那一套用的是管理器里
那个陈旧构建（只认 `-h`/`-V`），于是永远报
`ksud daemon not visible in /proc; ksud said: Options: -h, --help`。

> `utils::install()` 是在 `daemonize()` **之后**的子进程里跑的（上游
> `late_load.rs:82`），所以 `late-load` 命令**返回时安装往往还没完成**。
> v1.1.7 直接查 `/data/adb/ksu/bin/ksud` 会假报
> `su replacement target missing`；v1.1.8 改成轮询等待（最多 6 秒），
> 并且只在模块确实注册了（`LIVE=yes`）时才等 —— 模块没起来时 `late-load`
> 会提前 return，根本不会去装，空等毫无意义。

### ⚠️ 关于提权后的 SELinux 状态

`uaf_plant.c` 在伪造 cred 之前会**主动把内核的 `selinux_state` 改写掉**，
把 SELinux 从 Enforcing 切成 Permissive（最多重试 12 次，日志里能看到
`[selinux] attempt N/12` / `[selinux] already permissive`）。

这是利用链路的一环。**跑完之后是什么状态，取决于跑到哪一步**：

| 跑到哪 | 结束时的 SELinux | 说明 |
|---|---|---|
| 只到 `verify`（默认） | **Permissive** | 工具不自动恢复 |
| 到 `ksu-takeover` 且 KernelSU 接管成功 | **Enforcing** | 内核把 SELinux 收回去了 |

2026-10-31 真机实测（v1.1.6 跑完后）：KSU 管理器显示「SELinux 状态：强制执行」，
也就是**接管成功后 SELinux 回到了 Enforcing** —— 这正是 KernelSU 正常工作时的状态。

想强制恢复 Permissive（需要 root）：

```bash
adb shell setenforce 0      # 直接切
adb reboot                  # 最干净：内核启动即 Enforcing
```

> `ksu-takeover` 会改写 boot 分区、bootloader 未解锁的设备可能变砖，
> 所以**默认只跑到 `verify` 阶段** —— 只跑默认流程的话 SELinux 会留在 Permissive。

---

## 版本约定

- 产物统一命名 `GhostKey-<ver>-release.apk`，构建后复制到仓库根的 `release/`（该目录已被 `.gitignore` 忽略，不进版本库），并以 **GitHub Release 附件**的形式发布。

---

## 许可证

仅供授权安全研究与自用设备测试。任何超出授权范围的用途均不在许可范围内。
