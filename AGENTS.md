# AGENTS.md

Android 13+ 用户态 FUSE 存储代理（root 模块二进制核心），C23 编写，Meson + Ninja 构建。

**本文件只写「不知道就会踩坑」的事**。细节出处：架构 `docs/architecture.md`、模块 ABI `docs/modules.md`、配置语法 `docs/config.md`、测试分层与**逐套件判别性细节** `docs/testing.md`（含 §附录）、流程红线 `CONTRIBUTING.md`。

## 构建

- `target_os` **默认是 `android`**：普通 Linux 上不带 `-Dtarget_os=gnu` 必然失败。
- **一律走仓库脚本，别自己拼命令**：GNU `scripts/build.sh`（`build_gnu/`）；Android `scripts/android-build.sh [目录] [meson 参数…]`（自动找 NDK、导出 PATH、`--reconfigure` 后 `ninja`；符号包目录同脚本传 `build_android_sym`；`ANDROID_API` 默认 35）；打包 `scripts/pack-module.sh`。
- **先 commit 再构建**：`NSP_GIT_HASH` 在 configure 期固化，不 reconfigure 出的包水印/`module.prop` version 仍是旧提交。
- 手工等价：`PATH=<ndk>/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH meson setup --reconfigure build_android && ninja -C build_android`（NDK 不在 PATH 时 configure 直接 `FileNotFoundError: aarch64-linux-android35-clang`）。cross 文件须含 `cmake = 'cmake'`（cmake 子项目交叉必需）与 `host_machine.system = 'android'`（libfuse 的 librt 豁免开关）；`-Dandroid_{libfuse,json_c,curl}=prebuilt` 需配 `-Dfuse3_root=`/`-Dcurl_dir=`。
- **告警纪律**：GNU 完整重建（`ninja -C build_gnu -t clean && ninja -C build_gnu`）应**零代码告警**（只剩 `lto-wrapper` 的 LTRANS 提示）。源文件自带的 `#define _GNU_SOURCE` 必须包在 `#ifndef _GNU_SOURCE` 守卫内（GNU 分支 meson 已定义），否则每个 TU 报一次重定义、淹没真告警。debug/ASan 构建另有 ~36 条既有 `-Wformat-truncation`，判定「新增告警」以 `build_gnu` 为准。
- Zygisk 模块经 `custom_target` 直接调 NDK `clang++` 编双 ABI（`src/zygisk/meson.build`），**不给 `project()` 加 cpp 语言**（否则 GNU 构建也要求 C++ 编译器）；注入 zygote，故禁 STL/RTTI/异常，改动后必须确认 `readelf -d` 无 `libc++_shared.so`。
- libfuse 子模块是自维护 fork（分支 `master-Android`），含 `fuse_invalidate_path_entry()`（`FUSE_3.19` 导出）；系统 pkg-config 库与 prebuilt 没这个接口，故框架侧用**弱引用**（`fuse_daemon.c` 的 `vfs_inval_path`），缺失时退化到 inode 级失效。改动子模块后须 `ninja -C build_sp_patch` 通过。
- SFTP 可选：Android 需先 `scripts/build-libssh2-android.sh` 再 `-Dsftp=enabled -Dlibssh2_dir=<源码树外的根>`（树内路径会被 cmake 子项目忽略，`meson.build` 有前置守卫）；`-Dsftp=disabled` 与历史构建逐字节一致，运行期另有一道 fail-closed 自检。

## 开发流程

1. 先读对应文档（见文首地图）。
2. 按归属写代码：纯 libc 工具进 `src/core/nsp_util.c`；依赖全局（`g_real_root`/日志）进 `src/core/common.c`；跨进程常量进 `include/nsp_constants.h`、日志级别进 `include/nsp_log.h`（各自唯一出处，禁私刻副本）；新跨文件函数带域前缀。
3. 改行为就地补用例：`python3 tests/run.py` 按改动自动选套件。**新套件须同时登记进 `tests/run.py` 的 `SUITE_MAP` 与 `LAYERS`**，否则 `test_docs_sync.py` 失败。
4. 提交前过验收门 `scripts/acceptance.sh`（构建 + 文档一致性 + 全量测试 + 报告）。提交信息中文，规范是可执行的 `scripts/commit_msg.py lint`（`scripts/setup-hooks.sh` 装配后由 `.githooks/commit-msg` 强制）：标题写「做了什么更改」，CJK 按 2 列算，正文行宽 72 显示列。

### 红线（破坏即回滚）

- 同一模块 ABI 版本内不改 fuse_daemon 导出表公共符号签名（已编译模块靠 `b_lundef=false` + `--export-dynamic` 解析）；升 ABI 必须递增 `NSP_MODULE_ABI_VERSION` 让加载器拒载旧模块。
- 不破坏「REDIRECT 虚拟前缀不含 user_id，FUSE 层剥离 `/0/` 后再匹配」。
- 路径合成走 `common_*` 唯一出口（禁裸拼；`MAX_PATH_LEN` 放不下返回 -1 而非截断）。
- 决策强制只在 `fw_route` 单点：新增回调必须 `VFS_SETUP_CORE(path, VFS_OP_READ|VFS_OP_MUTATE)`，不得在回调里手写 hidden/ro 判定（那正是 V3 收敛掉的漂移）。
- **存储根一级条目（`<STORAGE_BASE>/<组件>`，即 /data/media 下的 `0`/`999`/`obb`）不得由 FUSE 视图创建/删除/改名**：父目录补建唯一出口 `common_mkdir_within_storage`（禁直接调 `mkdir_recursive_p`），用户层解析唯一实现 `common_parse_user_layer`（禁 atoi 裸解析）。回归 `test_storage_root_guard.py`。
- YAGNI：不留无调用者的预留实现。

## 测试

```
env -u PYTHONPATH -u BASH_ENV PATH="/usr/local/bin:/usr/bin:/bin:/usr/local/sbin" python3 tests/run.py --all
```

- 自动按「改动文件 + 改动行符号」匹配套件；`--list` 预览、`--all` 全量（不含 `ON_DEMAND`）、`--layer L0|L1|L2`、`--base <ref>`、`--jobs N`（仅 `PARALLEL_SAFE`）、`--strict`（跳过计失败）。
- 退出码：`0` 通过、`1` 失败、`77` 整套跳过、`78` 部分跳过、`127` 套件不存在（计失败）。**跳过不算通过**，验收用 `--strict`。
- 分层：L0 静态/契约（可并行）、L1 GNU 真 FUSE（串行）、L2 Android 拓扑仿真（须核宿主 `mountinfo` 零变化）、L3 真机内核/权限（未做）、L4 设备验收（仅授权后经 `scripts/adb-sh.sh`）。层归属唯一出处是 `tests/run.py` 的 `LAYERS`。
- **环境坑**：宿主 CLI 会注入 `PYTHONPATH`（`sitecustomize` 把 unlink/rmtree 重定向到回收站）与 `BASH_ENV`（safe-bin 垫 PATH），导致 `test_module_circuit`/`test_inject_mount_env` 假失败——必须像上面那样 `env -u` 剥掉。
- 失败处理：残留挂载点用 `fusermount3 -u` 清；测试规则文件在 `/tmp/Namespace-Proxy/injector.conf`。
- **判别性**：新增回归用例必须在旧实现上失败（旧源码副本或 `<X>_SRC=`/`FUSE_DAEMON=<旧二进制>` 复验）。
- 逐套件判别性细节、内存验收（ASan 复跑与已知噪声）、隔离跑（宿主零污染）、按改动→套件映射表：**全部在 `docs/testing.md` §附录**，需要时按需读，不要全量加载。

## 设备操作（生产级隔离）

- 真机视为生产：一切设备命令经 `scripts/adb-sh.sh`（PATH 垫片 + `adb-safe.sh` + `set -u` + 变更/生产路径文本预检）；禁止裸 `adb shell` 做变更。
- 测试 I/O 一律 `su shell` 降权（实测 uid=gid=2000、CapEff=0），root 只建/卸挂载；backing 只用 `SAFE_ROOT` 合成 fixture，生产 backing 永不进测试挂载。
- 设备侧脚本 source harness 后危险命令（rm/umount/mv/cp/dd/chmod/chown/kill…）被影子化，绕过须 `command`/绝对路径（评审可见）；预检有**子串误报**：「arm64」「hidden」「nearme」「watermark」分别命中 rm/dd/rm/rm——换词或拆写，别加 `--unsafe-ok` 了事。
- 全链路功能验证见 `device-verify/README.md`（隔离配置根 + 探针 APK；生产配置只读并前后比对 sha256）。

## 架构要点（只留陷阱型事实）

- **v1 两段式**：pre 通道只裁决、**不挂载**（此刻还在 zygote 的挂载 ns 里，挂载会污染之后所有应用）；应用自己的 ns 到 `postAppSpecialize` 才成立，模块复用 pre 的连接发 `POST`（仍早于 Java 代码），injector 在 POST 上只做**就地快试** `IPC_MOUNT_INLINE_MS`（20ms）→ 拿不到立刻 fail-open ACK（第三态 `NSP_MOUNT_DEFERRED`）并把合并挂载交给后台毫秒快重试。**不要在 POST 上等存储视图**：真机 POST 之后 ~135ms vold 才把 `/storage/emulated` 装进应用 ns，阻塞等待等于给每次冷启动白加 ~140ms（实测 18% 超 250ms 预算后照样 fail-open）。REQ/pre 与旧模块仍用 `IPC_MOUNT_READINESS_MS`（250ms）。预算必须小到不可感知（旧值 1800ms = 每次冷启动多等 1.8s）。`proto` 握手：旧模块走原路径（就地挂载 + 后台重试），v2/v3 与非目标永不产生 `DEFER`/`POST`。
- **后台重试必须收敛**：记账在 `src/injector/retry_queue.c`（纯记账、可直编）。旧实现「派发即出队、失败再入队且次数归零」→ 挂不上的应用 1Hz 永久重试并逐轮刷错误。现在次数随条目保存（**毫秒记账**，`CLOCK_MONOTONIC`）：快档 20ms×10 → 中档 100ms×5 → 1/2/4/8s、上限 20 次、超限 loud 一次后放弃、成功才清账；一次性 `timerfd` 臂到最近到期时刻（1s 周期 tick 等不来 20ms 快档）；后台未就绪用 `NSP_READINESS_QUIET` 只记 DEBUG；入队后 eventfd 唤醒主循环立刻跑一轮（不等 1s tick）。
- **合并挂载三守卫（「某些设备存储全空」的根因）**：① 源预检在**任何卸载之前**（`statfs` == `FUSE_SUPER_MAGIC`，ROM 的 `/mnt` 传播可能只带目录不带 FUSE）；② 动手前 `MS_PRIVATE|MS_REC`（共享挂载组上的卸载会传播到 zygote/其它 ns），否则整机 `/storage/emulated/0` 变空；③ 挂载后 `statfs` 复核 + 失败回滚族根（回滚用调用方传入的 uid，禁在子进程里反查已退出进程）。就绪等待粒度 5ms（100ms 会引入最多 ~100ms 采样滞后，直接是冷启动延迟）。
- **v2/v3 不依赖 zygisk 阻塞**：全局替换后应用自带代理视图，pre 一律立即回 `OK`。v2 非目标应用要还原系统视图——**还原与 ACK 解耦**：pre 回 `DEFER` 的同时派发**后台**还原线程（10ms 步进、1.2s 预算），POST 到达再派发一次（一次命中 4~6ms）；派发按 pid 去重（32 槽），终态「视图始终不是项目 FUSE」= 已隔离，只记 DEBUG。真机实测 POST 会丢（39 次 pre 只 7 次走到 POST），所以正确性不许依赖模块通知。
- **全局替换的源活性守卫**：`do_global_replace` 要求源在本 ns 确实是挂载点（mountinfo 给出 dev），否则按「未就绪」返回 1、族根一点不动（源是普通目录时 bind 会把空目录装进族根 = 整机存储变空）；`ns_global_status` 只认 dev 指纹（`fuse_daemon` fstype 会把 FUSE 崩溃后的死视图误判成「已替换」→ 对账永远跳过），源不在挂载表时返回 UNKNOWN 让对账退避。
- **打开中删除不产生 `.fuse_hidden`**：本地 backing 支持「先删名后关句柄」，`vfs_rename` 识别隐藏名后直接 unlink 源文件并留属性快照（删除后 `fstat` 常不带 fh）；后端路径（FTP/SFTP）仍走隐藏名。`.fuse_hidden*` 按**普通条目**对待：readdir 不过滤、不清理，可 `getattr`/`open`（隐藏会掩盖现场、抬高取证难度），后端隐藏名同样可见。
- **模块化与 ABI**：规则决策（REDIRECT/SANDBOX/HIDE/ALLOW/RO）、uid→包名、MONITOR 合并都是**框架能力**（`src/daemon/fw_rules.c`/`fw_pkg.c`/`fw_config.c`）；模块只剩后端存储提供者（`backend_*`），从 memfd 加载、inotify 热插拔。当前 `NSP_MODULE_ABI_VERSION=5`、`NSP_FRAMEWORK_API_VERSION=4`；改 `include/nsp_module.h` 语义必须升版本，加载器在 `dlopen` 后、`init` 前拒载旧版。
- **后端 errno 契约**：`backend_*` 用 errno 风格回业务失败（`-ENOENT`/`-EPERM`/`-ENOTEMPTY`/`-EIO`…），框架**不计入熔断窗口**（`backend_rc_is_business()`）；新增 `backend_*` 分支时 `module_guard_error` 必须带这条豁免，否则应用探测缺失路径就会把健康模块置毒 + ban。
- **配置读取归属**：文件 I/O + inotify + 词法解析全在框架（`fw_config.c` + `config_read_view`），模块不读文件（**包括自己的 `<modules_dir>/<名>/<名>.conf`**，框架按 owner 过滤下发）；建索引仍在模块。改 `config_parser.c` 读取/词法须同时跑 `test_rules.py` 与 `test_config_snapshot.py`。
- **zygisk 上报策略受配置控制**：模块只过滤 `uid 0` 与 isolated 区（90000–99999），系统应用是否注入由 `SKIP_SYSTEM_APPS`（默认 ON）在 injector 侧裁决——**别再在模块里写 uid 阈值**（硬编码会让该开关永远不生效，且 v2 下系统应用连还原机会都没有）。
