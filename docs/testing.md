# 测试与验收

本文是**测试怎么跑**与**什么算验收通过**的权威出处。按改动选套件的映射表、分层清单
与退出码约定都在这里；可执行形式在 `tests/run.py`，两边的一致性由
`tests/test_docs_sync.py` 机器校验（不再靠人工同步）。

- 构建细节与陷阱 → `../AGENTS.md`
- 单个用例的判别性设计细节（为什么这样写才能在旧实现上失败）→ `../AGENTS.md` 映射表
- 提交前流程 → `../CONTRIBUTING.md`

## 1. 一条命令

```bash
python3 tests/run.py                  # 按本次改动自动选套件（日常开发用这个）
python3 tests/run.py --list           # 只看会跑哪些，不真跑
python3 tests/run.py --layer L0       # 只跑某一验收层（可重复 --layer L0 --layer L1）
python3 tests/run.py --all --strict   # 全量验收：跳过项计为失败
python3 tests/run.py test_rules.py    # 显式指定（跳过自动匹配）
python3 tests/run.py --jobs 4         # L0 类套件并行；挂载类恒串行
python3 tests/run.py --base <ref>     # 换改动对比基线（默认 HEAD）
scripts/acceptance.sh                 # 完整验收门（构建 + 测试 + 文档 + 报告）
```

**自动选套件的依据**：`git diff --name-only <base>` + 未跟踪文件，再按
`tests/run.py` 的 `SUITE_MAP` 匹配——每个条目给出**文件路径子串**与**符号名**，
任一命中即选中该行的套件。符号只在**本次改动的行**（diff 的 `+`/`-` 行）里找，
因此「改了 `fuse_daemon.c`」不等于「改了后端分派分支」；要全量请用 `--all`。
文档/脚本类改动不命中任何条目时仍跑「通用回归基线」。

### 环境前置

| 项 | 用途 | 缺失后果 |
|---|---|---|
| `build_gnu/` 产物 | 绝大多数 L1 套件 | 整套 skip（rc=77） |
| `fusermount3`、`/dev/fuse` | 真实挂载 | L1 整层 skip |
| Python `sqlite3` | `test_functional` 的 DB 用例 | 子组 skip |
| 本机 vsftpd 匿名服务（127.0.0.1:21，匿名根只读 + `upload/` 可写） | `test_ftp.py`、`test_ftp_parallel.py` | 整套 skip |
| `sshd` + `sftp-server`（套件自起于 127.0.0.1:2222，非 root、仅公钥认证） | `test_sftp.py` | 整套 skip |
| libcurl 编入 libssh2（`-Dsftp=enabled`，GNU 上系统库通常已含） | `test_sftp.py` | 整套 skip（驱动报 rc=3） |
| `cc`（本机编译器） | L0 的「直编实际源码 + `--wrap` 桩」类套件 | 整套 skip |

非默认产物路径用环境变量覆盖：`FUSE_DAEMON`、`FTP_MODULE_SO`、`GLOBAL_REPLACE_CTL`、
`LOG_CTL`、`LOG_MONITOR`、`INJECTOR`。

## 2. 退出码约定（防「假绿」）

单套件与 `run.py` 共用同一套约定，**跳过不计通过**：

| 退出码 | 含义 | 汇总归类 |
|---|---|---|
| `0` | 全部通过 | PASS |
| `1` | 存在失败（`--strict` 下跳过也算） | FAIL |
| `77` | 环境不具备，**整套**跳过 | SKIP（gap，不计通过） |
| `78` | **部分子组**跳过，其余跑了 | GAP（不计通过） |
| `127` | 套件文件不存在 | **FAIL**——拼错名字不得静默通过 |

三条由来都是真踩过的坑，别回退：

1. `127` 曾被当作「跳过」，于是写错套件名的命令行稳定 rc=0。
2. 跳过曾计入「通过」数，环境缺依赖时整屏绿色但其实什么都没验。
3. 套件内部**不得用管道吞退出码**（`cmd | tee` 会把 rc 变成 `tee` 的）。

验收一律加 `--strict`，让 gap 变成失败，再逐条核对跳过原因是否真属环境缺失。

## 3. 两组正交的分类：Tier 与 Layer

容易混，但管的事完全不同，各有唯一出处（都在 `tests/run.py`）：

| | 唯一出处 | 管什么 | 怎么划 |
|---|---|---|---|
| **Tier** | `PARALLEL_SAFE` / `TIER_EXCLUSIVE` | 能不能并行跑 | 按共享状态冲突 |
| **Layer** | `LAYERS` | 验收递进顺序 | 按贴近 Android 的程度 |

### 3.1 Tier（并行安全性）

- **Tier 0**：`PARALLEL_SAFE` 白名单，进线程池并行。判据：CONF/挂载点全由
  `mkdtemp` 派生自管或根本不挂载；无固定端口；无全局 `pkill`；不碰系统
  `log_monitor` 与真实日志文件。**新套件默认串行**，要进白名单须先逐条核对判据。
- **Tier 1**：挂载类，恒串行。
- **Tier 2**：独占，串行且排最后——碰全局 `log_monitor`（抽象套接字单例 + 系统
  `LOG_DIR`）的套件，收尾时系统实例已还原，不干扰别人。

共享资源冲突矩阵（逐个审计得出）记在 `tests/run.py` 的 `PARALLEL_SAFE` 上方注释里：
固定 `CONF` 路径、`/tmp/fuse_proxy_test` 基目录复用、全局 `pkill`、vsftpd 服务端目录、
固定中继端口 2121、全局 `log_monitor`、系统 `injector.conf` 共七项。

### 3.2 Layer（验收分层）

层只决定**验收时的递进顺序**，`run.py --layer` 可直接跑。`SUITE_MAP` 里每个套件
必须恰好属于一层，漏登记会被 `test_docs_sync.py` 判失败——否则分层验收会悄悄
跑不到它（本文档建立前，38 个套件里有 13 个处于这种状态）。

| 层 | 范围 | 环境要求 |
|---|---|---|
| **L0** 静态/契约 | 不挂载、不联网、不起 daemon。多为「直编实际源码 + `--wrap` 桩/ASan」的判别性用例 | 只需 `cc` |
| **L1** GNU 真实后端/FUSE | 起真 daemon、真挂载；部分需 vsftpd、本机 sshd 或系统 `log_monitor` | `/dev/fuse`、`fusermount3`（`test_sftp` 只需 sshd） |
| **L2** Android 拓扑仿真 | rootless `unshare` 沙箱内仿真安卓挂载拓扑 | userns 可用 |
| **L3** 真实 Android 内核/权限 | SELinux / Bionic / vold / FUSE-BPF / Zygisk 双 ABI / 多用户 | emulator/AVD 或真机（**本机无，未做**） |
| **L4** 设备最终验收 | 仅授权后经 `scripts/adb-sh.sh`；全链路功能验证（v1 + 隔离配置根 + 探针 APK）见 `device-verify/README.md` | 真机 + 显式授权 |

**L2 通过 ≠ Android 运行时已验证**。L2 只仿真挂载拓扑，SELinux 标签、Bionic 差异、
vold 行为、Zygisk 双 ABI 注入、多用户都没覆盖，必须由 L3–L4 兜。写验收结论时
不要把 L2 全绿写成「Android 上没问题」。

层与套件的对应关系以 `tests/run.py` 的 `LAYERS` 为准，用 `--list` 查看：

```bash
python3 tests/run.py --layer L0 --list
```

### 3.3 按需套件（不进 `--all`）

压力/基准类套件耗时长、断言的是**指标**而非正确性，故登记在 `ON_DEMAND` 里，
`--all` 不跑，要跑就显式点名：

```bash
python3 tests/run.py test_ftp_stress.py
python3 tests/stress_fuse.py
```

登记而不是「放着不管」，是为了让 `test_docs_sync.py` 能区分「有意按需」与
「新套件漏登记」——此前 `test_ftp_stress.py` 长期游离在 `--all` 之外，
从台账上看不出是故意的还是忘了。

## 4. 验收门

`scripts/acceptance.sh` 把下面各门串成一条命令，逐门出 PASS/FAIL 并落报告到
`.acceptance/<时间戳>/`。单独跑某门用 `--only <门名>`，`--list` 看门清单。

| 门 | 内容 | 单独跑 |
|---|---|---|
| **G1 构建-GNU** | `build_gnu` 全量重建，**零新增代码告警** | `scripts/build.sh` |
| **G2 构建-Android** | NDK 交叉构建，产物齐全；`src/zygisk/*.so` 经 `readelf -d` 确认**无 `libc++_shared.so`** | `scripts/android-build.sh` |
| **G3 文档/台账一致性** | 文档陈述与代码一致、套件台账闭合、每套件已分层 | `python3 tests/test_docs_sync.py` |
| **G4 全量测试** | `run.py --all --strict` 退出码 0，gap 为 0 | 同左 |
| **G9 ACL 不干扰** | 真 `fuse_daemon` + 真挂载：以普通应用 uid 经挂载视图做真实文件操作，断言普通写读删 / REDIRECT 落点 / HIDE / RO / ALLOW / 沙盒镜像 / AOSP 顶层语义的**功能预期**——ACL 层不得改变功能语义（它是模块层可以减策略代码的前提）；条款与判别点见 §附录映射表 | `python3 tests/test_acl_nonintrusive.py` |
| **G5 内存安全**（可选，重） | `build_asan2`（ASan+UBSan）下复跑核心套件，**零 interceptor 报告** | 见 §5 |
| **G6 宿主隔离**（可选，重） | `scripts/test-isolated.sh`，宿主 mountinfo / `/var/fuse-proxy` / FTP 树三项前后零变化 | 同左 |

另有两条**人工判断**、脚本无法代劳的门：

- **G7 判别性**：新增回归用例必须**在旧实现上失败**。本仓库套路：
  `FTP_BACKEND_SRC=<git show HEAD:旧副本>`、`FW_CONFIG_SRC=`、`FDQ_SRC=`、
  `PROBE_VARIANT=old` 等环境变量指向旧源码副本复验，或直编旧源码。
  只说「用例通过」不算验收——那可能是用例根本没测到东西。
- **G8 层级诚实**：结论里写清覆盖到哪层。L3/L4 未做就写「未做」，不要用 L2 的
  绿顶替。

### 告警基线（判定「新增告警」时的参照）

- **`build_gnu`（release，`-O3 -flto`）应零代码告警**，只剩 `lto-wrapper` 的
  LTRANS 提示。完整重建后比对：
  `ninja -C build_gnu -t clean && ninja -C build_gnu`。
- **debug 构建另有约 36 条 `-Wformat-truncation`**（`-O0` 下 GCC 对 `snprintf`
  的 `%s` 做保守分析，release 不报）。均为**既有、非回归**：抽样核实为「错误消息
  截断」或「输入上游已由 `MAX_PATH_LEN`/`PATH_MAX` 界定的近误报」。
  故 debug/ASan 构建的告警基线本就比 release 高，**判定新增告警以 `build_gnu` 为准**。
- `_GNU_SOURCE` 重定义告警：源文件里的 `#define _GNU_SOURCE` 必须包在
  `#ifndef _GNU_SOURCE` 守卫内，否则每个编译单元报一次，把真告警淹没。

## 5. 内存安全复跑（ASan + UBSan）

```bash
meson setup build_asan2 -Dtarget_os=gnu -Denable_debug=true \
      -Db_sanitize=address,undefined
ninja -C build_asan2
```

**sanitizer 标志必须同时进编译与链接**——只进 `link_flags` 会「链接了运行时但零
插桩」，看着全绿实则没测。核对方式：`compile_commands.json` 里每条命令都含
`-fsanitize`。（`-Dwith_asan` / `-Dwith_ubsan` 仅在 `enable_debug=true` 下生效，
release 下给出 warning 并忽略。）

把 `FUSE_DAEMON` / `FTP_MODULE_SO` / `LOG_CTL` / `LOG_MONITOR` / `INJECTOR` /
`GLOBAL_REPLACE_CTL` 指向 `build_asan2/` 的对应产物即可复跑。四个必须知道的点：

1. **报告要落文件**：套件把守护进程的 stderr 重定向到自己的日志或 devnull，
   sanitizer 报错会被吞。用
   `ASAN_OPTIONS=log_path=/tmp/asanrep:detect_leaks=1:print_stacktrace=1`
   （`UBSAN_OPTIONS=log_path=/tmp/ubsanrep:print_stacktrace=1`），报告写
   `/tmp/asanrep.<pid>`。**先做阳性对照**（故意越界的探针）确认落盘机制真的生效，
   再据「无报告」下结论。
2. **`failed to deallocate … munmap … error code 22` 是本环境的 ASan 噪声**
   （分配器 release-to-OS 的 munmap 失败），**非产品缺陷**：加
   `allocator_release_to_os_interval_ms=-1` 即消失。判定时看有没有
   `heap-buffer-overflow` / `use-after-free` / `LeakSanitizer` 这类 **interceptor**
   报告，别被这条吓到。
3. **`detect_leaks=0` 是 L0 直编类套件的必需项**：后端对象是**有意 immortal**
   （`ftp_backend_add` 注释：条目永不 free），LeakSanitizer 会把它们全报成泄漏。
4. **LD_PRELOAD 类套件**（`test_readdir_skel_fallback.py` / `test_modules.py`）
   在 ASan 链接的 daemon 下必须把 ASan 运行时**前置到 `LD_PRELOAD` 首位**，
   否则 daemon 以「ASan runtime does not come first in initial library list」
   拒启（不是产品缺陷）。两个套件均已内置 `asan_runtime_path()` 处理。

**不纳入内存验收的套件**（预期信号或指标不可比）：`test_module_circuit`
（故意 SIGSEGV）、`test_crash_log`（`--crash-test`）、`test_ftp_parallel`
（断言控制面延迟收敛，ASan 的 2~5 倍减速让指标失去可比性）。

## 6. 宿主零污染隔离跑

```bash
scripts/test-isolated.sh [套件名…]      # 不传套件名即 --all
```

在 `unshare --user --map-root-user --map-auto --mount --pid --fork --mount-proc --net`
里跑，并把 `/tmp`、`/var`、FTP 树全部私有化，沙箱内自起一份 vsftpd。退出前对宿主
三项不变量做前后比对：**mountinfo / `/var/fuse-proxy` / FTP 树**，任一变化即报错并
保留现场（`$STAGE/diff.txt`）。

退出码：`0` 全绿且零污染、`1` 有污染、`2` 测试失败、`3` 两者皆有。

四个坑都已写进脚本注释，**改动前务必先读**：客户端须 uid 1000 且带 ambient
`CAP_SYS_ADMIN`；私有 `/var` 后 vsftpd 需显式 `secure_chroot_dir`（否则「端口在听、
连上即挂」，错误只进 syslog）；FTP 树用最小合成树而非整树复制；内层 uid 经
`--map-auto` 落到 subuid 需 `chown` 来回归还。

## 7. 环境坑

**WorkBuddy / CodeBuddy CLI 宿主**会注入两样东西，使删文件的套件**假失败**
（`PermissionError: /.Trash-1000`）：`PYTHONPATH=<…>/cli/vendor/shim`
（其 `sitecustomize.py` 把 `os.unlink`/`shutil.rmtree` 重定向到回收站）与
`BASH_ENV=<…>/shell-runtime-bash-env.sh`（把 `safe-bin` 垫到 `PATH` 最前）。
跑测试须剥掉这两项：

```bash
env -u PYTHONPATH -u BASH_ENV PATH="/usr/local/bin:/usr/bin:/bin:/usr/local/sbin" \
    python3 tests/run.py --all --strict
```

**`pkill` 自杀陷阱**：`test_functional` / `test_rules` 会 `pkill -f fuse_daemon`，
而 `FUSE_DAEMON=…/fuse_daemon` 这样的 env 赋值会出现在**外层 shell 的命令行**里
→ 被自己的 pkill 杀掉（表现为无输出 + SIGTERM）。把 env 与套件列表写进**落盘脚本**
再 `sh 脚本` 执行即可绕开。

**残留挂载点**：`/tmp/fuse_proxy_test/mnt`、`/tmp/fuse_rules_test/mnt`、
`/tmp/fuse_neg_test/mnt` 用 `fusermount3 -u` 清理后重跑。测试规则文件在
`/tmp/Namespace-Proxy/injector.conf`。

**日志不可观测**：daemon 日志走 UDS 交给 `log_monitor`，测试进程直接
`grep daemon.log` 恒为空。判别信号要取**模块侧标记文件**或**套件自记的事件文件**，
靠 grep daemon 日志会把真缺陷误报成环境问题。

## 8. 测试自清约定

写**真实** FTP 树（`upload/`、`upload2/`）的套件适用——那是用户的投递目录，会无界累积。

- 清扫按**宽前缀/模式**（`nsp_`、`nsp_par_`、`conc_*.bin`…），**不得**用含
  `os.getpid()` 的名字限定：否则只能清自己那份，异常退出或修好前的历史运行留下的
  `nsp_par_<旧 pid>_*` 会永久堆积。
- 写盘位置与清扫位置要**成对**：`upload2/` 有写就得有扫。
- 判定是否残留**用 `find -name`，不要用 `ls | grep '^前缀'`**：本机 `ls` 是 eza、
  输出带图标前缀，锚定 grep 恒假阴性。
- 判别性验证时探针要选套件**不碰**的名字，否则会伪装成套件缺陷（例：往真实树预置
  `pat_1m.bin` 会让匿名 ftp 用户无权覆盖，用例报 EIO）。

## 9. 加新套件的清单

1. 写在 `tests/test_<名>.py`，遵守 §2 退出码约定（环境不具备 → 77/78，别返回 0）。
2. 登记进 `tests/run.py` 的 `SUITE_MAP`：给出路径子串与符号名，让改动能自动命中。
   压力/基准类改登记进 `ON_DEMAND`（台账扫的是 `tests/*.py`，只有 `run.py` 与
   `_*.py` 助手模块例外）。
3. 登记进 `LAYERS` 的某一层（L0/L1/L2）。
4. 并行白名单 `PARALLEL_SAFE` **默认不加**；要加须逐条核对 §3.1 判据。
5. 在 `../AGENTS.md` 映射表对应行补一句**判别性设计**：这个用例在旧实现上为什么失败。
6. 跑 `python3 tests/test_docs_sync.py` 确认台账闭合。

漏掉第 2/3 步时 `test_docs_sync.py` 会当场失败并指出缺哪一项，不必靠记性。

### 9.1 加新源文件同理：`src/**/*.c` 与 `include/*.h` 必须能被选中

`run.py` 按「路径谓词 or 符号谓词」选套件，两者都不命中的文件**改了只跑恒跑基线**
——那是一片没有任何断言的绿色（实测过 `include/nsp_module.h` 改动不跑
`test_module_abi.py`、`src/core/path_trie.c` 改动不跑 `test_rules.py`）。故
`test_docs_sync.py` 第 8 组检查要求：

- 新增/既有的每个 `src/**/*.c` 与 `include/*.h`，都要落进某条 `SUITE_MAP` 的
  路径谓词里；
- 确无专属套件的（如 `src/daemon/fuse_thread_naming.c`），登记进
  `test_docs_sync.py` 的 `SOURCE_COVER_EXEMPT` 并写明**可核对**的理由——
  不接受「暂时没写」。

## 10. 相关文档

- `../AGENTS.md` — 构建陷阱、逐套件判别性细节、设备操作纪律
- `../CONTRIBUTING.md` — 开发流程、红线、提交规范
- `architecture.md` — 进程架构与并发模型（§7 维护规范）
- `modules.md` — 模块 ABI 与故障隔离
- `config.md` — 配置语法与禁忌清单

## 附录：逐套件判别性细节 / 分层隔离 / 内存验收 / 设备隔离

> 以下内容原在 `AGENTS.md`，因其每轮都会被注入上下文而迁到这里（内容逐字保留）。
> 需要时按需读：排查某个套件在断言什么、跑 ASan 复验、隔离跑全量、或核对改动的测试映射。

按改动跑映射（全绿方可提交）：

| 改动 | 测试 |
|---|---|
| 内建规则引擎（`src/daemon/fw_rules.c`）/ `fuse_daemon.c` / `config_parser.c` | `test_rules.py`（57，含本地大目录断点续扫；**26. 超长规则路径 fail-closed 判别**——>255 字节的 HIDE/REDIRECT 目标/变量值必须整行拒绝，不得 `snprintf` 静默截断：用例把「截断后的前缀」在底层真实建成目录，旧实现该前缀被隐藏/被重定向命中、新实现照常可见；截断成更短前缀会**放大** HIDE/RO 命中范围，违反 `MAX_PATH_LEN` 红线。变量值用 REDIRECT 观察——变量 HIDE 走 dyn 分支且受 `pkg_resolvable` 门控，测试进程 uid=1000 恒跳过，只有自定义变量目标不经包名门控）、`test_config_snapshot.py`、`test_monitor_layers.py`（MONITOR 三层合并）、`test_decision_enforce.py`（决策强制单点 errno 矩阵）、`test_negative_timeout.py`（-o negative_timeout 熔断：未命中后建文件立即可见）、`test_readdir_skel_fallback.py`（lstat 拒绝时骨架名回退合成目录条目）、`test_backing_gate.py`（backing 仲裁门 36 项：全局门 12 + 按路径门 22 + 2 条源码静态契约——**全局实例不得挂 backing**（下层 DAC 按调用方凭证，`/data/media` 归 MediaProvider，应用一律 EACCES），`ALLOW` 也算要求仲裁，旧实现把 ALLOW 当直通跳过）、`test_c1_sandbox_slot.py`（**C1 判别**：沙盒落点的 `access+mkdir_recursive_p` 不得发生在 `config_read_begin` 持槽期间；**夹具把 `NSP_CONFIG_DIR` 与 `NSP_STORAGE_BASE` 一并私有化到 mkdtemp**——落点是 `<STORAGE_BASE>/<uid>/Android/data/<pkg>/sandbox`，只补 CONFIG_DIR 会让落点留在共享 `/var/fuse-proxy/storage` 下：`--jobs` 下与同样用 `sandbox.conf` 的套件并发时对方先建好该落点 → `access()` 命中 → `mkdir_total=0` 假失败（隔离跑实测复现，2026-10-11）——驱动经 `--wrap=config_read_begin/end` 维护槽状态、`--wrap=mkdir_recursive_p` 记录每次目录创建及其槽状态，断言 `mkdir_in_slot == 0` 且 `mkdir_total ≥ 1`（补建在槽外）；旧实现该 mkdir 就在 `br_check_redir_rule` 内、持槽期间执行，实测 `mkdir_in_slot=1` 必失败）、`test_module_circuit.py`（**§7b/7c 后端回传长度钳制判别**——后端模块谎报 `got`/`wrote = size+64`：旧实现 `return rc == 0 ? (int)got : …` 直接回包，libfuse 从只有 `size` 字节的读缓冲取数（ASan 实测 `got=4160` 命中堆异常）且**不计契约违规**（模块不被熔断、`module_errors.log` 无记录）；新实现按契约违规拒绝（-EIO）并计错误 → 窗口内累计 5 次置毒落 ban。判别看**记账**（ban + errlog `op=backend_read)`），不只看 errno——越界回包被内核拒收，两侧 errno 都是 EIO。另：默认 SELinux 上下文统一为 `NSP_DEFAULT_FILE_CONTEXT`（`nsp_constants.h`，`_Static_assert` 锁长度 33）——`lsetxattr` 调用一律传 `sizeof(...)`，此前 `fuse_daemon.c` 手写 `35` 越过 32 字符字面量读 2 字节） |
| `src/modules/ftp/` 或框架后端分派 | `test_ftp.py`（27，需 vsftpd；含 V5 分页 700 文件大目录列全；3c **fsync 落远端判别用例**——write+fsync 后、close 之前核对远端已有内容，旧实现 `vfs_fsync` 对后端句柄返回 0 时必失败；3d **写模式回灌判别用例**——远端预置非空文件（探针须 0666，否则匿名用户无权覆盖会把权限问题伪装成缺陷）→ `open(O_RDWR)` 先 `pread` 应读到远端内容 → 尾部 `pwrite` → close 后远端**前段仍在**；旧实现只 mkstemp 空 tmp、全量 STOR 覆盖，前段变 NUL 空洞必失败；3e **后端列举可见性判别用例**——FTP 列举里 HIDE 条目必须不出现且直接访问 ENOENT（旧实现后端 readdir 零 probe 过滤，名字泄露）；6b 后端 rename 带 flags 必须 EINVAL（旧实现忽略 flags 直接改名）；6c **跨 server rename 判别用例**——模块配置注册两个 server（同 vsftpd、`remote_dir=/upload` 与 `/upload2`），`rename(/云盘/x, /备份/y)` 必须 EXDEV 且两端原样（旧实现只按 from 取后端、把 to 的远程路径拼到 from 的 server 上 → 文件留在错误 server 被改名，应用以为搬走）；**收尾按 `nsp_` 前缀自清 `/home/bdy/ftp/upload` 与 `upload2/` 两处残留**——upload/ 同时是用户投递目录）、`test_backend_lifecycle.py`（后端引用配对/真卸载，无需 vsftpd）、`test_ftp_read_restart.py`（读缓冲随机跳变竞态，无需 vsftpd）、`test_ftp_parallel.py`（14，控制面并发/连接复用/延迟收敛/热重载竞态/断连熔断自愈，需 vsftpd；自起延迟中继，占用 127.0.0.1:2121；阶段 B 列 12 个不同目录以绕开 V5 LIST 缓存；工件用 `nsp_par_` 前缀并在 finally 对 `upload/` 与 chroot 根下 `upload2/` **两处**按宽前缀自清——按 pid 限定只能清自己那份，历史/异常退出的会永久堆积）、`test_ftp_truncate_list.py`（truncate 清 LIST 缓存：直编后端 + 桩 mux/curl 注入服务端状态，无网络——旧实现不清 LIST 时列举命中旧缓存把截断前 size 回灌 stat。**另含 A15 判别**：合成 LIST 正文含 `.hidden`/`.git`，断言点条目照常上架——旧实现 `name[0] != '.'` 把所有点开头名字一起丢掉；端到端不可观测，因本机 vsftpd 默认 `force_dot_files=NO` 的 LIST 根本不回点条目）、`test_ftp_upload_lock.py`（**上传锁泄漏判别用例**：直编后端 + 桩 mux/curl，乱序改写→FLUSH 全量重传→trylock 断言锁未泄漏 + 看门狗断言续写/release 不挂起；旧实现上必失败）、`test_sftp.py`（50，**SFTP 后端（proto=sftp）**：本机非 root 起 sshd（127.0.0.1:2222，仅公钥）。分两段：**驱动段**（41 项，不经 FUSE）由 `tests/fixtures/sftp_backend_driver.c` 直编**实际后端源码**并用真实 libcurl/libssh2 打真 SFTP 服务器；**FUSE 段**（9 项，有 `/dev/fuse` + GNU 产物时自动执行，否则打印说明并跳过该段）起真 daemon 真挂载，覆盖 列目录/读/写→远端/mkdir/rename/unlink/rmdir/缺失→ENOENT/含空格名 全链路。四条判别：A **空文件 st_size 必须 0**——libssh2 对 0 字节把大小报成未知（CONTENT_LENGTH=-1），透传即 st_size=-1；B **缺失路径 16 连发后完好文件仍可读**——SFTP 下 CURLINFO_RESPONSE_CODE 恒为 0（libcurl 只给 FTP/SMTP 填 info.httpcode），照抄 FTP 的 resp==0 判据会把每个业务失败当断网、8 次即静默误杀完好文件；C **含空格/中文文件名能建/读/删**——SFTP 的 quote 命令由 libcurl 在客户端解析（空白会截断参数）且路径必须先还原百分号编码；D 非空目录 rmdir → ENOTEMPTY。另含目录探针（OpenSSH 允许只读 open 目录，文件探针会把目录报成 S_IFREG size=目录自身大小）、quote 失败 errno 细化（错误串 "No such file"→ENOENT，其余退回 FTP 粗口径）、truncate 0 / 非 0 拒绝 / 随机读 / 120 条大目录分页） |
| `src/modules/ftp/ftp_mux.c`（epoll + curl_multi 控制面复用器）或 `backend_rc_is_business`（业务 errno 豁免） | `test_ftp_parallel.py`（连接复用与延迟收敛）、`test_module_circuit.py` §9（业务 errno 不得触发熔断/ban） |
| `src/config/path_vars.c` | `test_path_vars.py`（`parse_var_assignment` 三态：1=赋值行/0=非赋值行/-1=值放不下；`expand_path_vars` 返回 bool，false=已截断——调用方须 fail-closed 丢弃规则，截断的前缀会放大 HIDE/RO 范围） |
| injector 目标判定 / 注入方法（`inject_target.c`、`--inject-method=v1\|v2\|v3`） | `test_inject_method.py`（44，v1/v2/v3 判定矩阵：v3 忽略 `GLOBAL_INJECT`/`SKIP_SYSTEM_APPS` 而段头 `OFF` 仍生效、派生标志、非法值拒绝；**A1 ACK 时序判别**：直编 `ipc_server.c`，同步挂载桩阻塞在「放行门」上——放行门创建前客户端不得读到 ACK；旧实现 ACK 在派发挂载线程**之前**发出，实测 `early_ack=1` 且同步桩从未被调用，必失败；**A2 两段式补挂载通道判别**：`ipc_plan_channel`/`ipc_channel_readiness` 纯函数矩阵——`REPORT+proto>=2` 必须是 `IPC_CHAN_DEFER`（**pre 只裁决、不挂载**：此刻还在 zygote 的挂载 ns 里，挂载会污染 zygote 与之后所有应用）且预算 0、`POST` 必须是 `IPC_CHAN_POST`（唯一挂载时机）、旧模块（无 proto）与 `REQ` 必须是 `IPC_CHAN_LEGACY`（就地挂载，语义不变）；并断言主线程预算 `IPC_MOUNT_READINESS_MS ≤ 500ms`（旧值 1800/1000ms 直接落在应用主线程上，冷启动可感知）。A1 断言 REQ 通道仍「挂载完成后才 ACK」；**A2b/A3 还原时序**：`ipc_plan_restore` 矩阵 + 还原桩挂门（门未开也必须 300ms 内 ACK；旧实现必败））、`test_global_replace.py`（rootless unshare 沙箱内 v2 替换/还原/审查生命周期，userns 不可用自动跳过；**场景0 未就绪判别**：族根尚未建立时 `replace` 必须返回非 0——旧实现 `return 0` 静默成功，调用方据此永不重试，真机表现即「开机后 v2/v3 不生效」；**场景1b 源活性**：源被 umount 后 `replace` 必须非 0、`status` 为 unknown、族根 dev 不变（旧实现会把空目录 bind 进族根））、`test_inject_tracked_race.py`（**追踪表并发遍历判别**：直编 `inject_target.c` + ASan + `--wrap=kill`，三条遍历路径（`audit_tracked_apps`/`audit_and_remount_specific_apps`/`force_recover_tracked_mounts`）各用钩子在「访问链首 B 时并发摘除已访问过的 A」撑开窗口——旧实现裸遍历 `g_tracked_hash`（游标 `pp = &(*pp)->next` 指向的 next 槽随 A 释放而悬垂，下一轮解引用即 UAF；且路径内 `cleanup_app_mounts`/`perform_app_mount` 会再取 `g_tracked_mutex`，持锁遍历必自锁）→ ASan 实测 `heap-use-after-free in audit_tracked_apps`；新实现改为 **锁内快照 pid 列表 + 锁外做重活**，两处对照（无并发变更不丢节点）同时通过） |
| injector 挂载/清理序列（`ns_utils.c` 跨 ns bind 与 preserve 路径、`ns_global_replace.c` 替换/备份/还原、`cleanup_app_mounts`、`injector.c` 拉起 FUSE 的 execv 参数装配） | `test_inject_mount_env.py`（37/46/42，rootless unshare 沙箱仿真安卓拓扑内 v1/v2/v3 全生命周期：注入→REQ→SIGTERM 清理→退出后宿主 mountinfo 前后比对零污染，缺产物/userns 不可用自动跳过；**vold 重挂对账判别**：v2/v3 段在替换完成后用 tmpfs 覆盖族根模拟 vold 重挂，断言 20s 内被周期对账重新替换回项目 FUSE——旧实现只在 FUSE 就绪时替换一次、此后永不复查，实测超时 20s 仍停在系统视图。**配置含 24 token 的 `FUSE_EXTRA_ARGS`（全为 `-f`，对 libfuse 合法且重复无副作用）——A11 判别**：旧实现 token 守卫 `ai < 31` 未给尾部固定的 `-f`/`-o`/挂载选项/NULL 4 项预留，末条 token 写到 `args[31]` 之后；ASan 构建下必报 `stack-buffer-overflow … inject_global_fuse`，FUSE 起不来）、`test_ns_combined_rollback.py`（合并挂载失败回滚：直编 `ns_utils.c` + `--wrap=mount/umount2` 注入 mount 失败，断言以族根回滚而非留应用于裸状态；**含后台通道静默判别** E/F：`NSP_READINESS_QUIET` 下目标缺失必须只有 DEBUG——零 WARN/ERROR、不出现"重试队列/缺失("措辞，而 readiness=0 的权威尝试仍须 WARN + "交由重试队列"；**含源预检判别** G：源在本 ns 不是 FUSE（`--wrap=statfs` 令其报 tmpfs）→ 零卸载、零挂载、返回 ENODEV（旧实现先把原生视图拆掉再把空目录 bind 成 /storage/emulated → 应用存储全空）；**含挂载后校验判别** H：目标未变成 FUSE 视图 → 卸载本次挂载 + 族根回滚 + EIO；**含传播隔离判别** I：`MS_PRIVATE` 必须早于第一次卸载（共享挂载组上的卸载事件会传播到 zygote/其它应用 ns）；**含快路径判别** K/L：目标是挂载点（`MS_PRIVATE|MS_REC` 返回成功）时**零次 mountinfo 收集**、备份与目标各一条 `MNT_DETACH`（目标那条连整棵子树一起摘），目标非挂载点（`EINVAL`）时必须枚举子树且**只扫一次**（备份树/目标树多目标合并）。旧实现 E3/E4/E5/G2/G3/H1/H2/I1 必失败，旧源码实测 K2「仍枚举子树」、L2「各扫一遍」必失败；**含异步参数零初始化判别** S1：源码里再出现 `malloc(sizeof(struct CombinedMountArgs))` 即失败——该结构字段只增不减，异步通道漏初始化新字段（如 `[ns计]` 的 `seg`）时子进程 `SEG_MARK` 往垃圾地址写 → SIGSEGV → 完成管道 EOF（`read=0`）→ 上层按挂载失败重试，日志只剩「异步挂载结果不可得」；旧源码实测该检查在 `ns_global_mount_async` 那行命中）、`test_retry_queue.py`（**重试收敛判别**：直编 `retry_queue.c` + 虚拟时钟——旧实现「异步派发成功即出队、失败回调重新入队（次数归零）」使退避与 5 次上限永不生效，挂不上的应用 1Hz 永久重试并每轮写一条错误日志；新实现 1/2/4/8s 退避、上限 6 次、超限 loud 一次后放弃、成功才清账。60 秒窗口内尝试次数 ≤ 上限、退避曲线、满队列拒绝、成功清账）、`test_ns_umount_overflow.py`（**mountinfo 扫描栈越界判别**：直编 `ns_utils.c` + ASan + `--wrap=fopen/umount2`，合成 mountinfo 填满容量且末条挂载点 >256 字节——旧实现 `strncpy(mounts[i], mp, PATH_MAX-1)` 写爆 `char[256]` 槽、ASan 必报 stack-buffer-overflow；新实现跳过超长条目并 loud 告警，其余条目仍全量卸载。**含多目标收集/前缀预筛/挂载点探测判别** E/F/G：`ns_collect_mounts_multi` 一次扫描收两棵子树且结果互不串台；500 条无关行下只收本子树，且规模快照 `candidates` 远小于 `lines`（预筛没退化成逐行全解析）、`lines` 仍覆盖整份文件（扫描范围没缩小）；`ns_probe_target_view` 用 `statx` 的 `mnt_id`/`st_dev` 判「是不是挂载点 / 是不是项目 FUSE 视图」，别人的挂载点不算我们的视图、缺失路径判「没挂载」）、`test_ns_global_replace_rollback.py`（**全局替换失败回滚判别**：直编 `ns_global_replace.c` + `--wrap=fopen`（合成 mountinfo）+ `--wrap=mount`（让指定 `(source,target)` 的 bind 失败）——旧实现替换步骤任一步失败直接 `return -1`，族根停在**裸挂载点**（备份树就在手边却不 bind 回去）；新实现把本次已动过的族根逐一根从备份树还原（含 Android/data 子挂载），未动过的族根不误碰，备份缺失时如实报「无法回滚」）。`do_global_restore` 与回滚共用 `restore_root_from_backup`（唯一出口） |
| 已挂载视图的连接活性（`ns_mount_health.c` 的 `ns_mount_conn_state`/`ns_mount_needs_repair`）与启动扫描修复（`mount_manager.c` 的 `repair_stale_app_mounts_at_startup`、`injector.c` 的就绪分支） | `test_mount_liveness.py`（20 + 12 条静态契约：直编 `ns_mount_health.c` + `--wrap=statfs` 控制「连接是否可用」并记录探测路径与次数——健康 FUSE → `LIVE` 且不修复、探测路径必须是 `/proc/<pid>/root<挂载点>`、单次探测；`ENOTCONN`/`ECONNREFUSED` → `DEAD` 且修复；`ENOENT`/`EACCES`/非 FUSE → `UNKNOWN` 不修复；**没有项目挂载时一次探测都不做**（`has_project_fuse=false` 早退，健康进程零额外系统调用）；静态契约锁接线：两条挂载路径都必须先要求 `target_fuse_unverified` 才探测、`ns_mount_needs_repair(` 恰好 3 处、修复分支在「已存在项目 FUSE ⇒ 跳过」之前、启动扫描在 `inject_is_global_replace()` 下直接返回、调用点在 `g_fuse_ready = 1;` 之后且 `g_pending_startup_scan` 置位/消费各一次、探测不得换成会被 FUSE 属性缓存骗过的 `stat`/`statx`。判别性：旧实现没有这套判据（「挂载条目在」= 直接跳过挂载），删掉 `has_project_fuse` 早退则无项目挂载用例必失败；真机现场即「injector 重启后老进程永久 `ENOTCONN`，杀模块进程无效、只能重启设备」） |
| 受管子进程收尸留档（`reaped_managed.c`、`injector.c` 的 `reap_zombies`/崩溃恢复） | `test_reaped_managed.py`（直编收尸留档 + 真实 fork：通用收尸先到仍能取回退出状态——旧实现 waitpid 得 ECHILD 致崩溃现场不入日志环；含未收尸兜底/消费语义/负例） |
| `src/module/`（加载器/内存副本加载/围栏/熔断/ABI） | `test_modules.py`（残留旧 ABI 模块：加载前拒绝/按 mtime 落 ban/不泄漏 memfd fd/不挡真更新 + 旧哈希格式 ban 自愈 + **§6b 框架 ABI 变化后旧 ban 自愈**：`.banned` 记录末字段即落 ban 时的 `NSP_MODULE_ABI_VERSION`，ABI 不同（或无该字段的旧格式）视为 stale——否则「旧框架因 ABI 不匹配落 ban → 升级框架」后 mtime 未变、旧 ban 永久命中，新框架明明支持该模块却再也加载不回来；旧实现下 §6b 两条断言必失败；**§7 A23-2 判别**：LD_PRELOAD 垫片只让第 2 次 .so `stat`（= `module_prepare` 的 st1；第 1 次是 `module_ban_blocks` 的 `so_mtime`）报 ENOENT，并记录紧随其后 1s 窗口内是否出现 `open64`/`memfd_create`——新实现 stat 一失败即返回（只有 `STAT_DENIED`），旧实现带着**未初始化的 st2** 继续跑完 open+memfd+读文件再用它比较（`MEMFD_AFTER_DENY`/`OPEN_AFTER_DENY` 双双出现）；daemon 日志走 UDS、无 log_monitor 时不可观测，故判别信号取垫片自记的事件文件）、`test_module_circuit.py`（故障隔离：后端载体；**§11 A12 quiescence 门控判别**：`backend_hold` 建模 FTP 形态——自带配置线程 + 由句柄拥有的数据面线程（exit 不 join），标记文件使 `nsp_module_active_handles()>0`；熔断置毒后断言 daemon 存活 + `memfd:nsp_module_backend_hold` **仍在 maps**（门控跳过 dlclose）；旧实现实测 daemon rc=-11 且映射消失。**§11 另含 A23-1**：模块未卸载时其 memfd **fd** 不得提前 close——断言 `/proc/<pid>/fd` 下仍有该 memfd；**不能用 maps 是否带 `(deleted)` 判别**，memfd 是匿名 inode 从创建起 maps 就恒带 `(deleted)`）、`test_module_abi.py`（V5 布局契约/旧版本 V1/V2/V3/V4 拒载/最小后端模块/20 模块注册表增长）、`test_backend_lifecycle.py`（后端引用配对/真卸载 + **热重载放弃新实例时必须先经围栏 exit 停其自有线程再 dlclose**：旧实现直接 dlclose，用例实测 daemon rc=-11）、`test_fw_config_view.py`（`push_config_to_slot` 经 `fw_config_view_acquire/release` 取用配置视图——模块加载线程与配置重载线程并发时视图必须有效，见 `fw_config.c` 行） |
| 决策强制单点（`fw_route` 的 appear_missing→ENOENT、read_only→EROFS） | `test_decision_enforce.py`（38，逐回调 errno 矩阵，规则来自配置 HIDE/RO） |
| 访问控制判定表（`src/daemon/fw_acl.c`：AOSP 用户态策略层的唯一执行点，由 `fw_route` 单点调用） | `test_acl.py`（47：路径分类对齐 AOSP `PATTERN_OWNED_PATH`（卷根/骨架目录/他包私有/Android-media/顶层条目）；他包 `Android/data|obb` → ENOENT、自己包（含 `:push` 进程后缀）放行、platform 签名豁免、`[GLOBAL] ALLOW_CROSS_APP_DATA ON` 放行、包名解析失败 fail-open；骨架目录不可列举（EACCES）、不可增删改名（EPERM）；`Android/media` 可读写但不可改名；顶层条目只能建默认目录、不可删/改名；`access(X_OK)` 对普通文件 EACCES（MS_NOEXEC）、目录放行；三码 errno 不混用。另含静态契约：`fw_acl_check(` 在 `fuse_daemon.c` 只出现一次、8 个关键回调都注入了 ACL 操作种类。判别性：本模块为新增（旧树没有 `fw_acl.c`），旧行为对上述路径**全部放行**） |
| ACL 不干扰（验收门 G9：ACL 的功能侧守门——判定层「按 AOSP 拦对了」不等于功能按预期生效） | `test_acl_nonintrusive.py`（37 项；rootless unshare 内起真 `fuse_daemon` + 真挂载，配置同时含 REDIRECT/HIDE/RO/ALLOW/SANDBOX，**以普通调用者身份**（argv[0] 即包名 → `fw_pkg_resolve_exact`，无需 `uid.map`）走真实 FUSE 系统调用，只看功能结果与 errno：普通创建/写入/读回/删除全成功；REDIRECT 内容落在 `movies/` 且虚拟前缀未被实体化；HIDE 的 stat/readdir 均 ENOENT 且父目录列举不出现；RO 的 `open(O_WRONLY)`/`unlink`/`rename` 均 EROFS 而读成功；ALLOW 直通自身存储；沙盒 ON 下他包 `Android/data` 只允许 ENOENT 或权限错误（出现第三种行为即失败）、自己包可建可写、共享目录落 `<pkg>/sandbox/`、应用段 ALLOW 豁免沙盒；AOSP 语义 `/0` 可列举、顶层非默认目录 EPERM/EACCES、`DCIM` 内可建子目录、删顶层被拒。特权应用豁免无 daemon 侧 `packages.list` 夹具入口，套件内显式跳过并注明（判定层见 `test_acl.py`/`test_rules.py` §28）。判别性：把 `fw_acl_check` 改成恒回 `-EACCES`（只改副本）后本套件 31/37 项失败，恢复后全过） |
| FUSE 事件通道（`src/daemon/fw_events.c`：`nsp_fs_events` 推送 + `nsp_fs_query` 查询，`[GLOBAL] FUSE_EVENTS` 默认 OFF） | `test_fw_events.py`（100：直编 `fw_events.c` 与 `fw_pkg.c`，桩掉路径合成/规则决策/访问控制三个事实源——事件字段三域自洽（`vpath` 相对用户根、`spath` 存储视图绝对、`rpath` 真实落盘）、rename 的 `src_vpath`/`src_spath`、`write_denied` 带 `errno`+`spath` 且**不带** `rpath`、200ms 同路径合并（不同路径各自成条）、4096 环满丢最旧且 `dropped` 增量正确、无订阅者与开关关闭时零入队、QUERY 六类响应互不混淆（`ok=0` / `denied=1` / `busy=1` 三码不得复用）、绝对 spath 反解 user 10、`exists` 的 200ms TTL 与「write_done 立即失效」、订阅 filter 生效、白名单默认 root/system/media_rw + `FUSE_EVENTS_UIDS` 追加、白名单自动含 MediaProvider 进程 uid（按包名**真实**解析 packages.list 夹具：写行即入、删行即出、同 uid 去重）、`write_denied` 的 errno 含 ENOSPC/EDQUOT 而 EIO 不发。静态契约锁四件事：判定只问引擎（`fw_events.c` 里不得出现 `"/Android/data"`/`"hidden"` 一类规则字面量；`fw_rules_resolve(` 与 `fw_acl_check(` 的出现次数封顶）、热路径零 `malloc` 且 `lstat(` 只有一处（exists 缓存）、`fw_events_start` 的开关判断先于第一次 `pthread_create`、`fuse_daemon.c` 里 `fw_events_start` 在 `fuse_daemonize` 之后且 `stop` 在 `module_system_shutdown` 之前）、`test_fw_events_fuse.py`（27：真实 daemon + 真实挂载——写穿 FUSE 收到 write_done 且三域自洽、mkdir/rename 的 op 与 src 字段、RO 拒绝 → `write_denied{errno=EROFS}`、QUERY 五类响应（含 REDIRECT 落点 spath 映射回落点视图）、**开关 OFF 时两条 socket 均不可连接**（默认关就是真关）。判别性：`fw_events.c` 为新增模块（旧树整个文件不存在），旧实现下订阅者一条事件也收不到） |
| 存储根一级条目守卫（`src/core/common.c` 的 `common_is_storage_root_entry`/`common_mkdir_within_storage`、`fuse_daemon.c` 的 `fw_route`→`vfs_storage_root_guard`、`fw_rules.c` 的 `br_ensure_sandbox_dir`） | `test_storage_root_guard.py`（66，**历史 bug 判别**：/storage/emulated（底层 /data/media）顶层反复出现纯数字垃圾目录（线上形态如 `1814208618`），且只能在 /data/media 下删除。链路＝应用请求 `/<数字>/…` → `fw_parse_path`/`br_strip_and_sanitize` 把第一个全数字段当 user_id（**无存在性校验**）→ real_path=`<STORAGE_BASE>/<数字>/…` → 创建路径的父目录补建 `mkdir_recursive_p` 以 root 把 `<STORAGE_BASE>/<数字>` 造出来；同一漏洞还让应用能**删掉顶层用户根**（旧实现 `rmdir /999` 返回 0、目录消失）。新语义：`fw_route` 单点 ① 不存在的用户根 → **读写一律** -ENOENT（正例入 16 槽小表缓存、负例每次复查，避免误伤运行期新建用户；**读侧也拦**的理由：根级 REDIRECT 下规则引擎会把 `/<数字>` 合成为“已存在目录”（NSP_VK_ANCESTOR），应用据此下探，CREATE/MKDIR/RENAME/SYMLINK 的父目录补建随即落盘——**这就是“反复出现”的主链路**；读侧返回 ENOENT 后内核不再认为该名字存在，下探不会发生）；② 存储根一级条目 → 变更一律 -EPERM（含删除/改名/元数据/**带写 flags 的 open**：否则已存在的顶层垃圾文件可被以 root 身份截断/改写），读（列出/stat/只读 open 既有条目）照旧。父目录补建唯一出口 `common_mkdir_within_storage`（**永不创建**一级组件，一级组件缺失即 ENOENT；非存储根落点如 FTP 相对目标/自定义 REDIRECT 照旧递归创建；一级组件之后才参与递归，顺带堵掉「查与建之间被删→重建」的窄窗口）。用户层解析收敛为 `common_parse_user_layer`（唯一实现；数字串溢出 int 的 atoi 别名，如 `/4294967296/x` → `/0/x`，一律非法 fail-closed）。`--root=<dir>/` 尾斜杠在入口归一（不归一真实路径会带 `//`、守卫静默失效）。四段判别：无规则 / 根级 REDIRECT+SANDBOX（主链路）/ 尾斜杠 root / 既有数字垃圾目录读放行。**测试夹具约定**：多用户用例须预建 `<root>/<uid>`（真实设备由 vold 建立；不存在即该用户不存在，读写一律 ENOENT——`test_ftp` 的 /1、/2 用例已按此补根）。旧实现 **49/66 失败**：mkdir/create/symlink/rename 四路都在测试根下造出 `1814208618`、`1814208619`、`1814208620`、`_junk_*`，并删掉 `999` 与历史垃圾目录——`FUSE_DAEMON=<预修复二进制>` 可复验） |
| `src/daemon/fd_close_queue.c`（Android backing fd 延迟关闭环形队列） | `test_pending_close.py`（16：多生产者/多消费者下每个 fd 恰好关一次；队满不阻塞且不制造被放弃槽位——饱和→flush→再入队仍能延迟；双消费者独占领取由钩子阻塞撑开窗口断言；**饱和时不得提前关闭本次 fd**（A22：旧实现「满则直接 close」正好做了队列要防的事——内核可能在 reply 发送完成前仍引用该 fd，fd 号可被另一 worker 的 open 立刻复用 → backing 挂到无关文件；新实现先促消费腾位后重试，仅回收无进展才 loud 告警 + 兜底直关）。旧「先占号再判满 + 无独占领取 + 满即直关」实现在饱和、双消费者、提前关闭三条上必现失败。可用 `FDQ_SRC=<旧实现>` 覆盖被测源码） |
| `log_ctl` / `rule_server` 规则编辑（`nsp_rule_file`） | `test_log_ctl_rules.py`（58，含**停用态**：编辑仍落 `.conf.disabled`、不新建 `.conf`；**含 A5 段内索引判别**：`[GLOBAL]` 与 `[USER_APPS:0]` 各一条同类型规则时 `remove-rule USER_APPS <type> 0` 必须删类别段那条——旧实现按整文件序号计数必删到 GLOBAL）、`test_rule_server.py`（**R7b 模块热插拔判别**：模块目录 mtime 精度不足（mkdir+写文件落在同一时钟 tick）时，新增模块的 schema 仍必须被发现——用例把 `modules` 目录 mtime 显式拨回创建前的值稳定复现该窗口，旧实现（快速路径只比 mtime）返回『模块未声明配置 schema』必失败；新实现同时比对目录条目数 → 正常发现。此前整套 `run.py --all` 连跑两次均在此偶发失败；含 **EXPORT_LOGS**：落点必须在 `<CONFIG_DIR>/export`（root 私有 0700，**不得**落共享存储——旧实现落 `/data/media/0`，任意应用可预置软链令 root 的 tar/chmod 覆盖任意文件）、包内含 log、连续两次导出只留最新一份、历史堆积一次调用收敛、日志目录缺失明确拒绝；**含 A5 混合段往返**：GET 类别段报段内索引、REMOVE/ENABLE/DISABLE 同口径，且 `GET GLOBAL` 只回 `[GLOBAL]` 段不混类别段）、`test_rule_file_lock.py`（4 进程并发 upsert 各 150 条 → 恰好 600 条无重复：目录 flock 串行化读改写 + 临时名带 pid；去掉锁实测只剩约 200 条。**另含 A10 判别**：规则文件 chmod 000 后 upsert 必须返回 EIO 且原文件逐字不动——旧实现把「读失败」的 NULL 当空文件，写回「段头+1 条」把 3 条原规则全丢；以 root 运行该组跳过计 gap。**另含 A6 判别**：另起进程持有规则目录 flock 不放，断言「调用侧读改写」形态立即返回（不串行化的窗口）、`nsp_rule_file_toggle_nth_scoped` 阻塞到放行——toggle 若又退化成不持锁的读改写即失败） |
| `src/rule/rule_server.c` 的 `reply_error`（拒绝应答落日志） | `test_log_pipeline.py` 用例 4（**A17 注入判别**，见下）——落日志前必须经 `nsp_log_line_sanitize` 清洗 + 同 cmd 限频 |
| `ftp_conf.c` 的 `#` 注释边界与 `port` 校验、`nsp_ini_store.c` 的 `nsp_ini_save` 落盘持久性 | `test_a26_misc.py`（31：直编 `ftp_conf.c` + `nsp_ini_store.c`。**A26-⑤ 判别**：`pass = p#ssw0rd` 必须整串保留——旧实现 `strchr(line,'#')` 无条件截断成 `p`，服务器 530 拒绝而配置看不出异常；`#` 仅行首/空白后起注释。`port = 0/-1/65536/abc/21x` 必须整段作废（旧实现 `atoi` 照收，最终以 `ftp://host:0/` 交给 libcurl）。**A26-⑨ 判别**：`nsp_ini_save` 临时名须带 pid，同一目录两个写者不互相 rename 掉对方未写完的 `.tmp`；写后立即读回内容完整（内容 fsync + rename + 目录 fsync）。**A26-⑨ 附带判别**：`nsp_ini_store` 取值同样不得在词中间的 `#` 处截断（与 `ftp_conf` 同源缺陷，此前含 `#` 的密码经 INI 通道也被改成首段）。**A3 组（SFTP 配置面 11 项）**：`proto=sftp` 未写 port 必须补默认 22（ftp 仍 21）且与书写顺序无关、显式 port 优先；`proto=scp` 等拼错值**整段作废**（静默退回明文 ftp 会把账号密码发到错误协议）；`host_key_check` 默认 on、只认 on/off/true/false/1/0（垃圾值整段作废）；`key_file` 超长整段作废（不截断路径去连错文件）） |
| `fuse_daemon.c` 的 `passthrough_probe`（B3：探测文件 TOCTOU + 延迟探测去重） | `test_pt_probe_toctou.py`（6：直编驱动 + `-Wl,--wrap=open/unlink` 桩，`PROBE_VARIANT=old/new` 各跑一遍。**判别**：探测目录（`/tmp`、`/data/local/tmp`）对普通用户可写、名可预测，旧实现 `open(O_CREAT\|O_RDWR, 0600)` 既跟随攻击者预置的**符号链接**（root daemon 打开任意路径并把 fd 当 backing 交内核）、又复用攻击者预置的**同名普通文件/FIFO**；新实现 `O_CREAT\|O_EXCL\|O_NOFOLLOW` 两条都堵（残留 `EEXIST` 先 `unlink` 不跟随，再独占创建）。另：GNU 延迟探测标志 `g_pt_probe_pending` 由 `bool` 改 `atomic_bool`，多 worker 首次 open 用 `atomic_compare_exchange_strong` test-and-set，保证只探测一次） |
| 日志链路（`src/log/`、`nsp_comm.*`、`nsp_log.h` / `nsp_util.c` 的 `nsp_log_level_*`、`common.c` 的 `vfs_log_io` / `monitor_on` / `persist_stage` / `drain_async`） | `test_log_pipeline.py`（35，框架闸门矩阵：无规则记录 / 路径无 `<uid>/` 层 / `MONITOR OFF` / 类别段 `[SYSTEM_APPS]` 否决与开启五态 + 磁盘历史全量可查（`count`/`search`/历史转储三条路径）+ 等级字段渲染为名称且旧数字行仍可解析、非法等级行跳过 + sock 查询端到端；**含 A17 拒绝日志注入判别**：起 rule_server 发 `{"cmd":"GET","pkg":"x\n3:伪造\n"}`（JSON 转义解码后是真换行），断言 `sys.log` 无伪造的 `|ERROR|` 行且原文以 `\n` 转义保留在单条 WARN 行内——旧实现必现伪造行；**含 A24 查询通道判别**：查询通道必须取自**已匹配的固定前缀**（`QUERY_IO:`/`QUERY_SYS:`/`QUERY_LOGCAT:` 三选一），不得在**整行**（含搜索关键字）上 `strstr("IO")`/`strstr("LOGCAT")`——`log_ctl search-sys IO` 拼出的 `QUERY_SYS:-1:IO:100:0` 会被误判成 io 通道且 rest 错位（key 变 `-1`、limit 被 `atoi("IO:100:0")` 成 0），静默返回另一个环且一条不返回；用例组合成只存在于 sys 环的关键字行断言 `search-sys <含 IO/LOGCAT 的关键字>` 必须命中，并以 `search-io` 同关键字作对照；**会重启 log_monitor 并备份还原 `io.log{,.1}` 与 `sys.log{,.1}`**） |
| `src/daemon/fw_config.c`（含规则文件/App-rules 的 inotify 监听线程——热重载触发路径本身） | `test_monitor_layers.py`、`test_cfg_watch.py`、`test_rules.py`（重载语义端到端）、`test_cfg_reload_split.py`（**C11 事件分流判别**：直编 `fw_config.c` 并注册自己的 reload 钩子计数，依次改写 `uid.map` / 规则文件 / `sys_pkgs.cache`——旧实现三者都触发全量重载（实测 uid.map 一次改写触发 2 次），新实现只有规则文件触发；`FW_CONFIG_SRC=` 可指向旧源码复现失败）、`test_fw_config_view.py`（**下发视图并发重载判别**：直编 `fw_config.c` + 依赖，驱动复刻模块真实访问模式——先缓存 `cfg->recs/generation` 再触发真实重载（改写规则文件 → inotify → `reload_once`）——旧实现解锁后交出 `&s->cfg` 借用指针、`reload_once` 原地 free 数组，故缓存指针被改写且为已释放数组（ASan 报 heap-use-after-free）；新实现为不可变 + 引用计数快照，`release` 前指针/代际/内容恒定。`ASAN=1` 追加内存安全验证；`FW_CONFIG_SRC=` 可指向旧语义源码复现失败） |
| `src/daemon/cfg_watch.c`（App-rules* 与模块目录的子目录 watch 对账） | `test_cfg_watch.py`（7：只对 `App-rules[-<uid>]` 挂 watch、普通子目录不挂；子目录内 tmp+rename 能产生可读事件（旧实现完全不监听这些目录→应用级规则改了不生效）；目录消失摘表、基目录不可读返回 false 走兜底重扫） |
| 模块配置下发（`include/nsp_cfg_view.h` 的 `NSP_CFG_REC_MODULE_FILE`/`MODULE_LINE`、`config_set_modules_dir`/`view_scan_module_confs`、`fw_config.c` 的 owner 过滤） | `test_module_cfg_push.py`（13：框架读 `<modules_dir>/<名>/<名>.conf` 后**按 owner 过滤**下发给同名模块（视图版本 2）——模块不读文件、不跑 inotify（**含它自己的配置**）。**判别性**：`CONFIG_PARSER_SRC=<去掉 view_scan_module_confs 的副本> python3 tests/test_module_cfg_push.py` 必失败（旧实现视图里没有任何 MODULE_* 记录）。断言：标记 + 逐行下发（注释行与含 `#` 的值原样到达模块——框架不替模块剥注释，否则模块的 `#` 边界语义被改写）、无配置文件时标记仍下发且 `file` 是**期望路径**（模块据此 loud 报出确切路径而非静默无后端）、owner 隔离（A 的视图不含 B 的行）、订阅不存在的类型不影响模块拿回自有配置（订阅只过滤 RULE）、模块配置行不被当规则解析进框架 AppConfig） |
| 框架侧规则解析：uid→包名（`fw_pkg.c`）、MONITOR 三层合并（`fw_config_monitor_for`）、沙盒/ALLOW 解析（`fw_rules.c`） | `test_monitor_layers.py`（20：uid→包名与 MONITOR 合并 11 项；**沙盒解析契约 9 项**——`SANDBOX ON` 时 Download/Pictures/Documents 等共享目录一并重定向进本应用沙盒、自己的 data/obb 与 `/Android` 下非 data/obb 不重定向、`ALLOW` 落回真实路径。本机 uid<10000 恒走 system 分支测不到这些，故自编译实际源码 + 合成 uid，不经 Meson）、`test_cfg_watch.py`（`fw_config.c` 改动同时跑配置目录 watch 套件） |
| 通用回归 | `test_functional.py`（IO/SQLite/并发/rmdir 标准语义/**rename flags**/**跨设备 rename**/**打开中删除不产生 .fuse_hidden**——模块 9：普通路径与本地 REDIRECT 路径各一组，断言删除瞬间**无新增**隐藏名、fstat/读/写仍可用、关闭后路径消失；模块 9b：打开中 unlink + 同名重建，真实目标目录在 unlink 瞬间、重建后、旧句柄读写与关闭后都无新增 `.fuse_hidden`（全程 `os.listdir`/`Path.iterdir` 直读真实目录，不经 FUSE），并断言隐藏名**恢复为普通条目**（列举可见、可 stat、磁盘保留，不再隐藏/自动清理）；旧实现（libfuse 默认隐藏名）与带过滤的实现（隐藏名不可见）都必失败；**模块 11 官方 FUSE 语义补齐**：`fallocate` 预分配与 `FALLOC_FL_KEEP_SIZE`（ctypes 直调 `fallocate(2)`，不走 libc 封装）、硬链接存活性与跨虚拟目录 `EXDEV` 口径、`mkfifo`、设备节点（`EPERM` 或成功都算过）、目录 `fsync`——旧二进制缺这些回调：KEEP_SIZE=`ENOSYS`(95)、硬链接=`EPERM`(1)、mkfifo=`ENOSYS`(38)，101 通过/11 失败）、`test_crash_log.py`、`test_docs_sync.py`（文档/台账一致性，恒跑） |
| 提交信息规范（`scripts/commit_msg.py`、`.gitmessage`、`.githooks/`） | `test_commit_msg_lint.py`（**CJK 显示宽度判别**：60 个 ASCII 字符 = 60 列放行、30 个汉字 = 60 列放行，而 40 个汉字是 40 字符却占 80 列必须拒绝——按字符数计的校验器（commitlint 的默认口径）会放行第三种，本仓库实测 25% 的正文行超宽即由此而来。另含 `!`↔`BREAKING CHANGE:` 成对、正文可选（无固定标签）、正文行宽 URL 豁免、Merge/Revert/fixup! 跳过、未入库本地引用黑名单、`.gitmessage` 提示行必须全是 `#` 注释（漏了会被提交进正文）） |
| 压力（按需） | `stress_fuse.py`、`test_ftp_stress.py` |

特殊前置：`test_ftp.py` 需本机 vsftpd 匿名服务（127.0.0.1:21，匿名根只读 + `upload/` 可写）；`test_config_snapshot.py`、`test_module_abi.py` 不经 Meson，直接用本机 `cc` 临时编译实际源码（前者另需 json-c），故不依赖 `build_gnu/`；

### 2026-10-18 审计修复的判别性要点

本轮清空 `review-findings-20261018.md` 的 15 条（R1–R15）。新增/扩展用例的判别信号
（旧实现均为 HEAD `f55b572`；直编类均支持 `*_SRC=` 指向旧源码副本复验）：

- **R1/R2 跨设备 rename**：`test_functional.py` 模块 6b 从实际源码逐字抽取
  `vfs_rename` 五个函数 + `--wrap=rename` 强制首次 EXDEV。旧实现非空目标 `rc=0`
  且目标子树消失、预置可预测临时名符号链接时受害者被写；新实现 `ENOTEMPTY`/
  `EISDIR`、目标逐字节保留、随机临时名 + `O_EXCL|O_NOFOLLOW`。
- **R10 假 fsync 成功**：`test_module_circuit.py` §0 直编 `vfs_backend_finish_data`，
  acquire 桩返回 -1；旧 rc=0，新 -EIO。
- **R3 truncate 句柄一致性**：`test_ftp.py` 3g / `test_sftp.py` FUSE 段——远端
  100 字节 → open(O_RDWR) → ftruncate(0) → 写 1 字节 → close，远端必须恰好
  1 字节；`FTP_BACKEND_SRC=` 现编旧后端复验。
- **R5/R6/R7/R12/R13 rule_server**：`test_rule_server.py` 的 fields 非 object
  （旧 rc=-11）、`REMOVE ../../outside`（旧 status=ok 且外部文件被改）、schema
  前缀比较（旧 sensitive 丢失 + 明文回读）、`--wrap=fopen` EACCES（旧整份覆盖）、
  bool garbage（旧落盘且 GET=true）；`RULE_SERVER=` 可指向旧二进制，
  `A26_INI_SRC=` 指向旧 `nsp_ini_store.c`。
- **R8/R9 injector**：`test_inject_method.py` 直编组，`IPC_SERVER_SRC=` /
  `NS_UTILS_SRC=` 指向旧源码；旧实现四种伪造身份全 ACK 并写 uid.map、
  ECHILD 两组 retries/removed=0。
- **R14 v2 OFF→ON**：`test_inject_mount_env.py` v2 段在 rootless unshare 沙箱
  断言 app2 从系统视图重新接入项目 FUSE、再 OFF 还原；用旧 `inject_target.c`
  现编 injector 时该断言 10s 超时必失败。
- **R4 模块配置超长行**：`test_module_cfg_push.py` 断言超长行时该模块零
  `MODULE_LINE`，并做 `ftp_conf_load(file)` 与视图喂入的差分；
  `CONFIG_PARSER_SRC=` 指向旧源码复验。
- **R11 log_monitor 退出 UAF**：`test_log_pipeline.py` 用例 5 直编 log_monitor +
  ASan + `--wrap=read/shutdown/accept` 跑 SIGTERM 退出路径；`LOG_MONITOR_SRC=`
  指向旧源码时 ASan 报 heap-use-after-free。
- **R15 构建脚本**：新增 `tests/test_build_scripts.py`（L0），假 HOME + rm/cmake
  桩断言危险路径在 rm 之前被拒；`BUILD_SSH2_SCRIPT=` 指向旧脚本必失败。

内存验收：`meson setup build_asan2 -Dtarget_os=gnu -Denable_debug=true -Db_sanitize=address,undefined`（等价 `-Dwith_asan=true -Dwith_ubsan=true`）。**sanitizer 标志必须同时进编译与链接**——只进 `link_flags` 会「链接了运行时但零插桩」，核对方式：`compile_commands.json` 里每条命令都含 `-fsanitize`（`-Dwith_asan/with_ubsan` 仅在 `enable_debug=true` 下生效，release 下给出 warning 并忽略）。

内存验收实际范围与结果（2026-10-06 实测，**共 26 套全绿、0 条 sanitizer 报告**）：
- **L0 13 套全跑**：`CC="cc -fsanitize=address,undefined -fno-omit-frame-pointer" ASAN_OPTIONS=detect_leaks=0`，13/13。`detect_leaks=0` 是必需的——后端对象是**有意 immortal**（`ftp_backend_add` 注释：条目永不 free），LeakSanitizer 会把它们全报成泄漏。
- **L1 7 套**：把 `FUSE_DAEMON`/`FTP_MODULE_SO`/`LOG_CTL`/`LOG_MONITOR` 指向 `build_asan2/`，functional / rules / decision_enforce / negative_timeout / modules / backend_lifecycle / ftp 全绿。
- **L1/L2 余下 6 套**：inject_method / global_replace / inject_mount_env / log_ctl_rules / log_pipeline / rule_server 全绿（`INJECTOR`/`GLOBAL_REPLACE_CTL` 同样指向 `build_asan2/`）。
- **不纳入内存验收的套件**（预期信号或指标不可比）：`test_module_circuit`（故意 SIGSEGV）、`test_readdir_skel_fallback`（LD_PRELOAD 垫片）、`test_crash_log`（`--crash-test`）、`test_ftp_parallel`（断言控制面延迟收敛，ASan 的 2~5 倍减速会让指标失去可比性）。
- **垫片 + ASan 的 LD_PRELOAD 顺序**：ASan 要求其运行时在 `LD_PRELOAD` 里**排第一**，否则进程直接以「ASan runtime does not come first in initial library list」拒绝启动（不是产品缺陷）。`test_modules.py` §7 与 `test_readdir_skel_fallback.py` 的垫片都自己用 `ldd` 找出 libasan 并前置（`libasan:<垫片>`），故两者在 `FUSE_DAEMON=build_asan2/fuse_daemon` 下均全绿。
- **§C 曾约两成概率失败（已修，非产品缺陷）**：`test_backend_lifecycle` §C 断言「热重载放弃新实例时 exit 必被执行」。热重载是**事件驱动**的，单次 stage 后 daemon 有时没走到 prepare，exit 标记自然不出现——与 exit 无关。修法两层：① 判别改用**模块侧 init/exit 标记对**（`swap-init-v2`/`swap-exit-v2`），不再 grep daemon 日志——日志走 UDS 交给 log_monitor，测试进程拿不到，实测 `daemon.log` 恒为空，靠它判别会把真缺陷误报成环境问题；② 走到 prepare 即收敛，否则最多重放 3 次 stage（重放不会掩盖缺陷：任一次 init 出现即可判定）。同时把 `SWAP_HOLD_CAP_MS` 从 30s 抬到 120s——必须大于全部等待窗口，否则 hold 中途到期会让引用归零走 commit 分支，届时 init 跑了而 exit 不该跑，会被误判成"exit 未执行"的真缺陷。改造后连跑 17 次全过。
- **跑 L1 的坑**：`test_functional`/`test_rules` 会 `pkill -f fuse_daemon`，而 `FUSE_DAEMON=…/fuse_daemon` 会出现在外层 shell 命令行里 → 自杀（无输出、SIGTERM）。把 env 与套件列表写进**落盘脚本**再 `sh 脚本` 执行即可。

### 分层验收流程（尽量贴近 Android）

**层定义与套件归属的唯一出处是 `tests/run.py` 的 `LAYERS`**（可执行：`run.py --layer L0`），
说明见 `docs/testing.md` §3.2。此前这里是散文清单，既跑不了也对不上账——实测 38 个套件
里有 13 个没被任何层点名，分层验收悄悄跑不到它们；现由 `tests/test_docs_sync.py` 强制
「每个套件恰好属一层」。

- **L0 静态/契约**（无挂载无网络，可并行）：多为「直编实际源码 + `--wrap` 桩/ASan」的判别性用例，只需 `cc`。
- **L1 GNU 真实 FUSE**（串行）：起真 daemon、真挂载，部分需 vsftpd 或系统 log_monitor。
- **L2 Android 拓扑仿真**：rootless unshare 沙箱内仿真安卓拓扑，须核对宿主 `mountinfo` 前后零变化。
- **L3 真实 Android 内核/权限**（需 emulator/AVD 或真机；本机无，未做）：SELinux/Bionic/vold/FUSE-BPF/Zygisk 双 ABI/多用户。
- **L4 设备最终验收**：仅授权后经 `scripts/adb-sh.sh`（强制降权 `su shell`、`SAFE_ROOT` 合成 fixture）。

```bash
python3 tests/run.py --layer L0 --list    # 看某层有哪些套件
scripts/acceptance.sh                     # 跑完整验收门并落报告
```

**验收标准**（全绿方可提交；完整门定义见 `docs/testing.md` §4，`CONTRIBUTING.md` §4 是提交侧清单）：

1. GNU 与 Android 交叉构建零**新增**告警、产物齐全（含 `src/zygisk/*.so` 的 `readelf -d` 无 `libc++_shared.so`）。
2. `python3 tests/run.py --all --strict` 退出码 0：跳过项（77/78）为 0，或逐条记录原因并确认非产品缺陷。
3. `python3 tests/test_docs_sync.py` 通过：文档陈述与代码一致、套件台账闭合、每套件已分层。
4. **判别性**：新增回归用例必须在旧实现上失败（本仓库套路：`FTP_BACKEND_SRC=<git show HEAD:旧副本>` 复验，或直编旧源码副本）。
5. 隔离证据：L2 套件宿主 `mountinfo` 前后零变化；挂载未消失前禁删 fixture。
6. L2 通过 ≠ Android 运行时已验证——SELinux/Bionic/vold/Zygisk/多用户须 L3–L4 覆盖，未做就写未做。

### 隔离跑全量（宿主零污染）

`scripts/test-isolated.sh [套件名…]`（不传套件名即 `--all`）。在
`unshare --user --map-root-user --map-auto --mount --pid --fork --mount-proc --net`
里跑，并把 **/tmp、/var、/home/bdy/ftp 全部私有化**，沙箱内自起一份 vsftpd。
退出前对宿主三项不变量做前后比对：**mountinfo / `/var/fuse-proxy` / FTP 树**；
任一变化即报错并保留现场（`$STAGE/diff.txt`）。退出码：0 全绿且零污染、1 有污染、
2 测试失败、3 两者皆有。

实测：**30 套全绿且宿主零变化**，跑完自动清理（含属主归还）。四个坑都已写进脚本注释，
改动前务必先读：
- 客户端必须 uid 1000 **且带 ambient CAP_SYS_ADMIN**：RO 用例要求非 root
  （`vfs_check_read_only` 对 `uid==0` 有框架级豁免），但降权后 setuid 的 `fusermount3`
  在本 userns 内提不了权（EPERM），故须显式给 cap；它不影响 RO 判定（那条只看 uid）。
- 私有 `/var` 后 vsftpd 会因缺 `secure_chroot_dir` 而「端口在听、连上即挂」
  （守护化后错误只进 syslog，stderr 恒空，极易误判成网络问题）→ 显式指定到 stage 下。
- FTP 树**不能整树复制**（`/home/bdy/ftp` 有 4.7G）→ 用最小合成树
  （根 0755 不可写、`upload/` 与 `upload2/` 0777），测试自建全部数据。
- 内层 uid 1000 经 `--map-auto` 落到 subuid，与 ns-root 属主错配 → FTP 树与
  `build_gnu/` 需 `chown` 给客户端，收尾再 `chown -R 0:0` 归还，否则仓库里会留下
  宿主无法覆盖的 subuid 属主 .so。

## 已按标准语义修复（原「待裁决」，2026-10-06 裁定）

以下两处此前只取证未改，现按标准语义修复，各配判别性用例（旧实现上均必失败）。

1. **`vfs_rmdir` 非空目录返回 ENOTEMPTY**（`src/daemon/fuse_daemon.c`，旧实现由 `51abd2c`
   引入）。旧实现对本地真实路径的 ENOTEMPTY 直接 `recursive_rmdir(p)` 并返回 0——即
   **对非空目录调 `rmdir` 会静默删掉整个子树**（实测一次普通 `os.rmdir()` 让
   `dir/a/sub/c` 全部消失），不符 POSIX，也与同函数的虚拟路径分支（返回 ENOTEMPTY）不一致。
   现本地分支直接返回 `-ENOTEMPTY`。`recursive_rmdir` 仍保留给 `rename` 的 EXDEV 回退
   （跨设备移动 = 拷贝后删源树，那里递归删除才是正确语义）。
   用例：`test_functional.py` 模块4「rmdir 标准语义」——非空→ENOTEMPTY、失败后子树完整
   保留、清空后 rmdir 成功（正对照）。

2. **`vfs_fsync` 对后端句柄真正落盘**（同上文件）。旧实现对后端句柄直接返回 0，数据留在
   模块缓冲里——依赖 `fsync()` 持久化的调用方（SQLite `synchronous=FULL`、编辑器保存）
   会拿到「成功」而远端无数据。现改为调用模块 `backend_flush`（与 FLUSH 同一条收尾路径，
   已抽成 `vfs_backend_finish_data` 供两者共用），成功则失效路径缓存；不销毁句柄，可重复
   调用（FUSE 的 FLUSH 会因 dup/fork 对同一句柄多次触发）。
   用例：`test_ftp.py` 3c——write+fsync 后、**close 之前**核对远端已有内容。

## 设备操作（生产级隔离，血的教训）

真机视为生产：一切设备命令经 `scripts/adb-sh.sh` 执行（会话强制 PATH 垫片 + source `adb-safe.sh` + `set -u` + 变更/生产路径文本预检），禁止裸 `adb shell` 做变更。隔离主体是 Linux 原生机制（内核强制，非约定）：测试 I/O 一律 `su shell` 降级执行——实测 uid=gid=groups=2000（1078 等危险组已脱）、CapEff=0，`assert_downgraded()` 每次先验，root 只建/卸挂载（/dev/fuse 0600，只能 root 开）且 `need_root()` 留痕；backing 只用 `SAFE_ROOT` 合成 fixture（生产 backing 永不进测试挂载，需真实下层行为时 cp -a 快照到沙盒）。纵深为 shell 层：设备侧脚本 source harness 即自动影子危险命令（rm/umount/mv/cp/dd/tee/chcon/chmod/chown/restorecon/setenforce/kill），绕过须 `command`/绝对路径（评审可见）；umount 循环卸直到消失、失败即 die 且错误禁止重定向吞掉；`set -u` 常开。SELinux 现状：测试树自动落 `shell_data_file`，root 段尚无专用受限域（ksu 域基本不受限，需 policy 新域——列为二期，不在这次范围内）。

**真机全链路功能验证**（v1 逐应用挂载 + 隔离配置根 + 探针 APK，覆盖 FTP/SFTP/REDIRECT/SANDBOX/HIDE/侧漏，并用不等待就绪的 `race` 探针量化 v1 的未覆盖窗口与侧漏，以及 `unlink` 探针验证打开中删除不留隐藏名）见 `device-verify/README.md`，入口 `device-verify/host/run-verify.py`：验证二进制编译期配置根固定 `/data/local/tmp/nsp_verify/config`，生产 `/data/Namespace-Proxy` 只读并在前后比对 sha256；设备写操作只经 vetted 的 `device/verify-device.sh`（安装 APK / `adb reverse` / 只读查询用 adb 原语），异常路径在 finally 恢复生产服务。
