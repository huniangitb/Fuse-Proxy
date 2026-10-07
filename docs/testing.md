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
| **L1** GNU 真实 FUSE | 起真 daemon、真挂载；部分需 vsftpd 或系统 `log_monitor` | `/dev/fuse`、`fusermount3` |
| **L2** Android 拓扑仿真 | rootless `unshare` 沙箱内仿真安卓挂载拓扑 | userns 可用 |
| **L3** 真实 Android 内核/权限 | SELinux / Bionic / vold / FUSE-BPF / Zygisk 双 ABI / 多用户 | emulator/AVD 或真机（**本机无，未做**） |
| **L4** 设备最终验收 | 仅授权后经 `scripts/adb-sh.sh` | 真机 + 显式授权 |

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
   压力/基准类改登记进 `ON_DEMAND`。
3. 登记进 `LAYERS` 的某一层（L0/L1/L2）。
4. 并行白名单 `PARALLEL_SAFE` **默认不加**；要加须逐条核对 §3.1 判据。
5. 在 `../AGENTS.md` 映射表对应行补一句**判别性设计**：这个用例在旧实现上为什么失败。
6. 跑 `python3 tests/test_docs_sync.py` 确认台账闭合。

漏掉第 2/3 步时 `test_docs_sync.py` 会当场失败并指出缺哪一项，不必靠记性。

## 10. 相关文档

- `../AGENTS.md` — 构建陷阱、逐套件判别性细节、设备操作纪律
- `../CONTRIBUTING.md` — 开发流程、红线、提交规范
- `architecture.md` — 进程架构与并发模型（§7 维护规范）
- `modules.md` — 模块 ABI 与故障隔离
- `config.md` — 配置语法与禁忌清单
