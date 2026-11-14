# 设备端全链路验证（v1 + 隔离配置根）

在**真实 Android 设备**上以 v1（逐应用挂载）方式验证 Fuse-Proxy 模块的功能是否可用：
FTP / SFTP 后端、REDIRECT 重定向、SANDBOX 隔离、HIDE、配置热重载，以及**真实存储是否出现侧漏**。
探针 APK 在应用启动早期（`Application.onCreate`）创建/读取文件，结果以结构化 logcat 行回传；
宿主脚本同时核对设备真实存储与宿主后端目录，做双向断言。

## 安全模型（为什么风险可控）

1. **挂载方式固定 v1**：验证配置只点名 6 个探针包（`nsp.probe.*`），生产应用完全不在注入范围。
2. **配置根隔离**：验证二进制由独立构建产出，编译期 `NSP_CONFIG_DIR=/data/local/tmp/nsp_verify/config`；
   生产配置 `/data/Namespace-Proxy` 全程只读，流程前后比对 `injector.conf` 的 sha256。
3. **宿主服务隔离**：FTP / SFTP 服务器都跑在**临时目录 + 127.0.0.1 + 临时密钥**，经
   `adb reverse` 映射到设备回环——不暴露局域网，也不碰宿主已有的 vsftpd / sshd。
4. **设备写操作收敛**：一切写入只经 `device/verify-device.sh`（固定 `/data/local/tmp/nsp_verify`
   与受控夹具 `/data/media/0/nsp_verify`、`/data/media/0/{ftp_probe,sftp_probe}`、
   Download/Pictures 的两个探针文件名）；宿主只做只读查询、`adb install/reverse/logcat` 与脚本调用。
5. **异常自动恢复**：`finally` 中停验证实例 → 清理验证目录与夹具 → 重启生产服务；随后断言
   生产配置 sha256 未变、生产 injector 已恢复。

## 目录

```
device-verify/
├── build/build-verify-binaries.sh   # 交叉构建「隔离配置根」验证版二进制 → dist/bin/
├── probes/                          # 探针 APK 源码 + 离线构建/自检脚本 → dist/apks/
├── device/verify-device.sh          # 设备侧执行器（root；唯一允许的设备写入口）
└── host/run-verify.py               # 宿主编排 + 断言 + 清理（Python 3，仅标准库）
```

构建产物（不入库）：`device-verify/dist/{bin,apks,keys}/`、`device-verify/build/.gen/`。

## 前置

- 设备：Android 12+（API 31+）、已安装模块（Magisk / KernelSU + Zygisk 可用）、`su` 可用、已连 adb。
- 宿主：Android SDK（build-tools 37、platform android-36）、NDK r30、`vsftpd`、`sshd`/`ssh-keygen`、`adb`。
- 宿主端口 `2121`、`2222`、`30200–30209` 空闲（可用参数改）。

## 用法

```bash
# 1) 构建验证版二进制（隔离配置根；不改仓库源码）
device-verify/build/build-verify-binaries.sh

# 2) 构建 6 个探针 APK（离线，无 gradle）
device-verify/probes/build-probes.sh

# 3) 一键验证
python3 device-verify/host/run-verify.py --serial <serial>
```

常用选项：`--skip-build`（复用 dist 产物）、`--keep`（保留宿主临时目录/日志）、
`--keep-apks`（保留探针 APK）、`--dry-run`（只打印配置与计划）、`--self-test`（离线自检）、
`--ftp-port/--sftp-port/--pasv-base`、`--wait`、`--smoke`（只跑 FTP STOR 一条链）、
`--no-fail-fast`（探针未就绪也把其余用例跑完）、`--no-ready-retry`（关掉首次未就绪时的自动重起）、
`--wait-subscriber MS`（起验证实例后等事件通道出现订阅者再跑用例，0=不等）。
退出码：`0` 全过 / `1` 有失败 / `77` 环境不满足（无设备等）。

每次运行结束都会打印各阶段墙钟（构建 / 设备准备 / 停生产+恢复视图+起验证 / 每个探针 /
竞态 / 阶段 B / 断言 / 合计）——提速的对照数据直接取自这里，不靠人肉掐表。

## 探针契约

logcat tag `NSP_PROBE`，每行：

```
case=<ftp|sftp|hide|iso|plain|unlink|race>|step=<name>|ok=<0|1>|detail=<...>
```

| 探针 | 关键步骤 | 语义 |
|---|---|---|
| `nsp.probe.ftp` | sink, ready, write, read, media, list, canary | 写 `/sdcard/ftp_probe/probe_ftp.txt` → FTP 后端；回读比对；再写一张 1×1 JPEG（媒体刷新只认媒体扩展名的落点）；列举；REAL_CANARY 不可见 |
| `nsp.probe.sftp` | 同上 | 写 `/sdcard/sftp_probe/probe_sftp.txt` → SFTP 后端 |
| `nsp.probe.iso` | ready, download, pictures, android_root, android_list, android_skel_data, android_skel_obb, android_skel_media, android_obb_own, android_media_own, android_allow | SANDBOX ON + 整树镜像口径：写 Download/Pictures 与 /Android（含自身 obb/media 私有目录、一条 ALLOW 豁免路径）。Download/Pictures 与 /Android 下的普通条目应落沙盒、真实目录零写入且能在自己的列举里看到；三个容器条目由框架合成，列举里都在且按名 stat 是目录、时间戳非 1970；三处私有目录与 ALLOW 豁免仍落真实目录 |
| `nsp.probe.hide` | ready, phase_a / phase_b+write_denied, list | 阶段 A 真实夹具可见可读；阶段 B（换配置重启）stat/写均 ENOENT、列举不含 hide |
| `nsp.probe.plain` | ready, write, read | 对照组：普通外部目录读写不受影响 |
| `nsp.probe.unlink` | ready, delete, hidden_open, fstat, read, hidden_closed, exists_closed, hidden_legacy | 打开中删除：写文件并保持读句柄 → 删除 → 目录里不得**新增** `.fuse_hidden`；删除后 fstat/读仍可用；关闭后路径消失；宿主预置的历史隐藏名夹具必须**看得见**（不做列举过滤，保留取证能力） |
| `nsp.probe.race` | attempt×N, summary | **不等待就绪**：立即反复写两个判别路径，量出 v1 的未覆盖窗口与侧漏 |

`ready` 步表示探针在 `Application.onCreate` 内轮询到本进程 `/storage/emulated` 的挂载源已变为
`fuse_daemon`（detail 记 `ms=`）；之后才执行 I/O，避免把「尚未注入」误判成模块缺陷。

结果通道：`sink` 是每次运行的第一行，逐个列出候选结果文件的打开结果
（`/data/local/tmp/nsp_verify/probe-logs/<pkg>.log` → 应用私有目录 → 外部私有目录）。
**公共临时目录是主通道**，logcat 只作崩溃/链路证据——logcat 会被别的进程刷掉，也会在
`ENOTCONN` 时一起看不见，而结果文件不受 FUSE 状态影响。公共目录由设备脚本以 root 预建、
`chmod 777` 并 `chcon u:object_r:app_data_file:s0`（默认的 `shell_data_file` 对
`untrusted_app` 只读，实测 `open failed: EACCES`）；宿主在断言前把日志 `adb pull` 回
`<base>/logs/device/`，随后设备侧文件**成功失败一律删除**，宿主留副本。

## 竞态探针：v1 能不能抢在应用首写之前？

`nsp.probe.race` 是唯一**故意不等待就绪**的探针：`Application.onCreate` 一开始就连续写两个
判别路径（每 ~20ms 一次，最多 6s），每次尝试记录相对时间、当时的 FUSE 就绪标志与写入结果。

| 族 | 路径 | 配置 | 判别 |
|---|---|---|---|
| a | `/sdcard/Download/nsp_race_a<i>.txt` | `SANDBOX ON` | 已挂载 ⇒ 落 `Android/data/nsp.probe.race/sandbox/Download`；未挂载 ⇒ 落真实 Download（**侧漏**）或被拒 |
| b | `/sdcard/nsp_race_b/nsp_race_b<i>.txt` | `HIDE /nsp_race_b` | 已挂载 ⇒ 必 `ENOENT`；未挂载 ⇒ 父目录由宿主预置，故非 ENOENT |

宿主交叉判定：`fuse=1` 的写入必须落沙盒、`b=ENOENT`、真实 Download 无文件；`fuse=0` 的写入
不得落沙盒；落到真实 Download 的即侧漏。默认「就绪前侧漏」只 `⚠` 告警，加 `--strict-race`
才计失败（v1 的窗口是已知事实，不是回归）。

### 实测（OPD2404 / Android 16 / KernelSU，2026-10-24）

每次运行 3 轮冷启动；「首次就绪」= 探针首次看到 FUSE 的毫秒数：

| 运行 | 轮次 | 首次就绪 | 未覆盖窗口 | 就绪前尝试 | 侧漏 |
|---|---|---|---|---|---|
| A | 1 | 919ms | [0, 890ms] | 32（28×EACCES、4×ok） | **4 次** |
| A | 2 | 652ms | [0, 626ms] | 23（全 EACCES） | 0 |
| A | 3 | 650ms | [0, 628ms] | 23（全 EACCES） | 0 |
| B | 1 | 803ms | [0, 776ms] | 28（20×EACCES、8×ok） | **8 次** |
| B | 2/3 | 656/683ms | [0, 630/658ms] | 各 23（全 EACCES） | 0 |
| C | 1 | 0ms | 无（首写前已就绪） | 0 | 0 |
| C | 2/3 | 639/610ms | [0, 613/585ms] | 22/21（全 EACCES） | 0 |

**结论：v1 抢不到，是掷硬币。** 观测到的就绪耗时跨 **0–919ms**（典型 600–900ms）：
偶尔同步挂载成功、应用首写前就绪（窗口 0ms）；多数时候 `/storage/emulated` 就绪门控 1s
超时后转重试队列，进程启动后 0.6–0.9s 内仍是系统视图。落在窗口里的写入要么失败
（EACCES，应用侧表现为写文件失败），要么**真的写进真实存储**——多轮运行分别观测到
**4 / 8 / 18 次**侧漏到 `/data/media/0/Download`。
挂载完成后的写入 100% 落沙盒、HIDE 生效、真实目录零写入——**功能正确，缺的是时序保证**。

要强保证需改用 v2/v3（开机早期替换全局视图），或把 v1 补挂载移到 Zygisk `postAppSpecialize`
并同步等待。

### 修复后：两段式补挂载（`pre` 回 DEFER → `post` 发 POST）

v1 的补挂载已从 injector 的异步重试队列搬到 Zygisk：`preAppSpecialize` 收到 `DEFER` 时
模块保留 companion 连接，在 `postAppSpecialize`（仍早于应用 Java 代码）发 `POST`，injector
在应用命名空间内带 1800ms 预算等 `/storage/emulated` 出现、挂完才回 `OK`。复测同一台设备：

| 运行 | 轮次 | 首次就绪 | 未覆盖窗口 | 侧漏 |
|---|---|---|---|---|
| E | 1/2/3 | 2 / 0 / 1 ms | 无（首写前已就绪） | 0 |
| F | 1/2/3 | 1 / 0 / 2 ms | 无（首写前已就绪） | 0 |

**结论：窗口消失。** 三轮冷启动里探针的**第一次**写入就已经看到代理视图（`fuse=1`），
`a` 族全部落沙盒、`b` 族全部 `ENOENT`、真实 Download 零文件；功能断言 99/99 全绿。
设备侧日志可见完整两段式：`Companion: REQ ... → DEFER` → injector「挂载未就绪，交由
zygisk post-specialize 重试」→ `Companion: POST ... → OK`。

代价与边界：目标应用冷启动多等一次挂载（实测 ~0.6–1s，与原先异步重试的时延同量级，
但这次是**阻塞在应用代码之前**）；生产配置无规则时不会产生 `DEFER`（实测生产应用全部
`→ OK`，零 DEFER），v2/v3 与非目标应用同理。

## 断言（57 项功能 + 12 项 open-unlink + 30 项竞态）

- 注入就绪：5 个功能探针 + hide 阶段 B 各一条，耗时 ≤ 12s。
- 结果通道：每个探针的 `sink` 行必须含 `/data/local/tmp/nsp_verify/probe-logs/<pkg>.log=ok`
  （只认公共临时目录，私有目录成功不算）。
- FTP / SFTP：探针 write/read/list/canary 成功；宿主后端文件存在且内容为 `NSP_PROBE:<pkg>:<ts>`；
  **真实存储 `/data/media/0/{ftp_probe,sftp_probe}/` 无同名文件**（写侧漏 = 0）。
- SANDBOX：真实 `Download`/`Pictures` 无探针文件；`/data/media/0/Android/data/nsp.probe.iso/sandbox/`
  下存在且内容正确（`NSP_PROBE_ISO_DOWNLOAD:`）。
- SANDBOX 的 /Android 整树：真实 `/data/media/0/Android/nsp_probe_sandbox.txt` 不存在，
  镜像里 `…/sandbox/Android/nsp_probe_sandbox.txt` 存在且内容为 `NSP_PROBE_ISO_ANDROID:`，
  探针列举 `/sdcard/Android` 时能看到自己刚建的条目；三处私有目录
  （`Android/obb/<pkg>`、`Android/media/<pkg>`）与 `ALLOW /Android/nsp_probe_allow`
  豁免的写入必须落真实目录、镜像里不得出现同名落点。
- HIDE：阶段 A 夹具内容匹配；阶段 B stat 与写均 ENOENT；真实夹具仍在；阶段 A 列举含 `hide`、
  阶段 B 列举不含。
- plain：真实外部目录 `Android/data/nsp.probe.plain/files/plain.txt` 存在。
- unlink（打开中删除）：delete/hidden_open/fstat/read/hidden_closed/exists_closed/hidden_legacy
  七步成功；删除瞬间与关闭后目录里都**没有新增** `.fuse_hidden`；宿主预置的历史隐藏名夹具
  仍物理存在且**列举可见**（本层不做过滤、不自动清理，便于取证），设备侧扫描无新增残留。
- 竞态（每轮 10 项 × 3 轮）：探针收尾、有采样、采到就绪后写入；就绪后写入全部成功/全部落沙盒/
  真实 Download 无文件/HIDE 生效；就绪前写入未落沙盒、未写真实 HIDE 目录；`fuse` 标志单调。
  「就绪前侧漏」默认只告警（`--strict-race` 计失败）。
- 安全：生产配置 sha256 前后一致；生产 injector 已恢复；屏幕常亮设置已还原。

## 本次验收结果（2026-10-24，OPD2404 / Android 16 / KernelSU）

- `python3 device-verify/host/run-verify.py --serial 64a4bad0 --skip-build` → **99/99 通过，退出码 0**
  （57 项功能 + 12 项 open-unlink + 30 项竞态；竞态侧漏为告警，见上节实测表）。
- 两段式补挂载后探针在应用 Java 代码前即就绪（unlink 探针实测 ready=22ms），不再依赖 1s 重试队列。
- FTP/SFTP 后端落盘内容一致；真实存储零侧漏。SANDBOX 真实共享目录零写入、沙盒内容正确。
  HIDE 两阶段 ENOENT 且真实夹具仍在；plain 对照正常；生产配置未变、服务已恢复。

## 已知边界与排障

- **注入时序**：ColorOS/OPD2404 上 vold 在进程启动后 0.6–0.9s 才把 `/storage/emulated` 装配进
  应用命名空间。两段式补挂载修复后，该窗口内的写入已由 Zygisk 在 `postAppSpecialize` 阻塞
  等待（实测首写前即就绪）；`nsp.probe.race` 用于持续回归这一点，`--strict-race` 可把
  「就绪前侧漏」计为失败。
- **屏幕休眠会冻结探针进程**：实测 `mWakefulness=Asleep` 时探针进程 `isFrozen=true`，
  `onCreate` 停在中途既不报错也不继续（现象：只有 `start` 行、之后 25s 无输出）。
  编排器因此会临时设置 `screen_off_timeout`/`stay_on_while_plugged_in` 并在收尾还原，
  每次 `launch` 前还会 `KEYCODE_WAKEUP` + 解锁；探针未收尾时自动重试一次。
- **`/Android/data` 是原生子挂载**（mount_manager 的 preserve 逻辑），HIDE 不作用于该子树；
  HIDE 夹具因此放在真实存储 `/data/media/0/nsp_verify/hide/`（宿主 root 预置、流程结束清理）。
- **SANDBOX 落点**是 `<STORAGE_BASE>/<user_id>/Android/data/<pkg>/sandbox`（`user_id` 为 0，不是应用 uid）。
- **FTP 虚拟前缀必须等于模块配置段名**（如 `FTP /ftp_probe ftp_probe`）：模块按 `/<段名>` 匹配后端。
- **SFTP 认证**：Android 侧 libssh2 以 mbedTLS 为后端，不解析 OpenSSH 私钥、也不从私钥提取公钥，
  需 PEM 私钥 + 同目录 `<key_file>.pub`；模块已自动使用该 .pub，`host_key_check` 保持 on。
- 验证期间生产服务被暂停（v1 注入验证的前提）；已注入的其他应用需重启才能重新获得视图——仅在测试机执行。
- **生产是 v3（全局替换）时，必须先恢复系统存储视图再起验证实例**。v3 在
  `/storage/emulated` 与 `/mnt/{user,installer,androidwritable}/<user>/emulated` 上挂的是
  `fuse_daemon`，四个挂载点共享同一个 peer group；停掉生产进程后这些挂载点在 zygote 命名空间里
  **仍在**、且已无人服务，新起的应用进程会继承它们（`ENOTCONN`），v1 再也挂不上去，
  探针只能等满 15s 就绪预算。设备脚本的 `restore-system-view` 动作先 `umount -l /storage/emulated`
  （peer group 会把另外三个一起带走），再把 `/mnt/pass_through/<user>/emulated` 逐个 bind 回去；
  编排器在 `stop-prod` 之后、`start-verify` 之前调用它，并断言 `SYSTEM_VIEW_READY=1`。
- **首次拉起仍可能抢不到挂载**（注入器的 post 命名空间盯梢有竞态：应用若在盯梢线程起跑前就完成
  了 `unshare`，线程等 1200ms 也「未见命名空间切换」，直接跳过补挂载）。现象是单个探针
  `ready ok=0 detail=timeout_ms=15000`，其余步骤全 `ENOTCONN`。编排器对「首探针未拿到 FUSE 视图」
  自动重起一次（`--no-ready-retry` 可关），实测重起后 `ready=48ms` 正常通过。
  该竞态在 `src/injector/ipc_server.c`（生产代码），验证工具链只做规避、不改它。
- **后端映射不算「活规则」**：`src/injector/mount_manager.c` 里 `app_has_active_rules()` 只数
  重定向/隐藏/只读/沙盒，FTP/SFTP 后端映射不在其中；只配 `FTP /ftp_probe ftp_probe` 的应用会被判
  「无规则冲突，保留原生视图」，于是根本不挂载、后端也就用不上（实测写入 `EACCES`）。
  验证配置因此给 ftp/sftp 段各加一条 `HIDE /nsp_verify/<case>_noop`，把应用拉进挂载范围。
- **FTP 上传的 `media_refresh` 目前发不出来**：`src/daemon/fuse_daemon.c` 的
  `vfs_backend_finish_data()` 用 `(fi->flags & O_ACCMODE) != O_RDONLY` 判「写意图」，而 FUSE 的
  FLUSH/FSYNC 请求不带 open 标志，libfuse 填给回调的 `fi->flags` 是 0 ——实测 FLUSH 到达、
  `backend_flush` 返回 0，但 `write_intent=0`，`fw_events_note_media_refresh()` 从未被调用，
  事件通道侧一行都没有。这属于生产侧缺口（不是验证工具链），本仓库当前不改；
  需要「上传即入相册」时按「open 时记录写意图、FLUSH 用记录值」修，影响面仅后端句柄。
- 排障：`--keep` 保留 `/tmp/nsp_dev_verify.*/`（含 `logs/`、后端目录、`device-dump.txt`）；
  `--keep-apks` 保留探针。**验证实例日志现在先回传再清理**：收尾时设备脚本 `export-logs` 把
  `/data/local/tmp/nsp_verify/config/log/`（`sys.log` / `module_errors.log` / `error.log` /
  `fuse_crash.log` / `verify_injector.out`）连同探针结果文件拷到 `<base>/logs/device/`，
  之后才 `rm -rf` 验证目录——`--keep` 结束就能读到实例日志，不再随清理一起消失。
  若生产服务未自动恢复：`su -c 'sh /data/adb/modules/Namespace-Proxy/service.sh &'`。
