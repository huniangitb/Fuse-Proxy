# device-verify/probes — NSP 设备验证探针 APK

7 个探针 APK 用于在真实 Android 设备上验证 FUSE 存储代理模块的 v1 注入视图。
离线构建（javac + d8 + aapt2 + zipalign + apksigner），**不需要 gradle、不联网、不调用 adb**。

## 构建

```bash
device-verify/probes/build-probes.sh
```

可选环境变量：

- `ANDROID_SDK`（默认 `$HOME/Android/Sdk`）：需要 `platforms/android-36/android.jar`
  与 `build-tools/<最新版本>/{aapt2,d8,zipalign,apksigner}`。
- `SKIP_CHECK=1`：只构建，不跑静态自检。

产物：

| 文件 | 说明 |
|---|---|
| `device-verify/dist/apks/nsp.probe.{ftp,sftp,hide,iso,plain,unlink,race}.apk` | 7 个场景 APK |
| `device-verify/dist/apks/BUILD-CHECK.txt` | 自检摘要（包名/minSdk/签名/zip/dex 契约） |
| `device-verify/dist/keys/debug.keystore` | 首次运行生成、之后复用（alias `androiddebugkey`，口令 `android`） |

单独跑自检：`device-verify/probes/check-probes.sh`。

## 运行方式（宿主侧）

安装对应场景的 APK 后拉起 launcher activity（`nsp.probe.<case>/nsp.probe.ProbeActivity`）。
探针在 `Application.onCreate()` 中**同步**执行（主线程、不新起线程）。执行 I/O 前先
`waitFuseReady`：轮询 `/proc/self/mountinfo`，直到 `/storage/emulated` 的挂载源变为
`fuse_daemon`（ColorOS 型 ROM 上 v1 注入在进程启动后 ~0.1–1s 才完成），然后才开始
场景步骤。宿主编排脚本用 logcat 过滤 tag `NSP_PROBE`：

```
adb logcat -d -s NSP_PROBE:I
```

每行格式：

```
case=<ftp|sftp|hide|iso|plain|unlink>|step=<name>|ok=<0|1>|detail=<...>
```

`detail` 内不会出现 `'|'`（会被替换成 `'/'`），可含空格与逗号。
最后一行 `step=done` 表示探针执行完毕；`done` 前若出现 `step=exception|ok=0` 表示
探针内部异常（仍会补一行 `done|ok=0`）。

> 因为探针在 `Application.onCreate` 同步跑文件 I/O，`am start -W` 可能先返回
> `Status: timeout`（进程仍在继续跑）。宿主应以 `step=done` 行为完成信号，
> 而不是以 `am start` 的返回值为准。

### 各场景步骤

| case | step 序列 |
|---|---|
| 除 race 外 | `start`, `ready`（`ms=` 就绪耗时；超时则 `ok=0`） |
| ftp / sftp | `mkdir`, `write`, `read`, `list`, `canary`, `done` |
| hide | `phase_a` 或（`phase_b` + `write_denied`）, `list`, `done` |
| iso | `download`, `pictures`, `android_root`, `android_list`, `android_obb_own`, `android_media_own`, `android_allow`, `done` |
| plain | `write`, `read`, `done` |
| unlink | `delete`, `hidden_open`, `fstat`, `read`, `hidden_closed`, `exists_closed`, `hidden_legacy`, `done` |
| race | `attempt`×N, `summary`, `done`（**无 ready**：不等就绪，见下） |

关键语义：

- `ftp`/`sftp`：在 `/sdcard/<case>_probe/`（虚拟前缀必须等于模块配置段名，
  如 `FTP /ftp_probe ftp_probe`）下写 `probe_<case>.txt`（内容
  `NSP_PROBE:<pkg>:<毫秒时间戳>`）并逐字节读回；`list` 的 detail 为目录条目
  逗号分隔（空目录为 `-`）；`canary` 探测同目录 `REAL_CANARY.txt`，`ok=1` 表示
  不存在（期望）。
- `hide`：宿主预置真实夹具 `/data/media/0/nsp_verify/hide/secret.txt`（内容
  `NSP_HIDE_CANARY`）。`Os.stat` 成功且内容匹配 → `phase_a`；`ENOENT` →
  `phase_b`（detail `enoent`），再尝试 `FileOutputStream` 写入，期望同样 ENOENT
  → `write_denied`，detail `errno=<n>`；其它 errno → `phase|ok=0|detail=errno=<n>`。
  `list` 列 `/sdcard/nsp_verify`（阶段 A 应含 `hide`，HIDE 生效后不含）。
  注：`/Android/data` 是原生子挂载，HIDE 不作用于该子树，故夹具放 FUSE 树内。
- `iso`：`Environment.getExternalStorageDirectory()` 下的
  `Download/nsp_probe_sandbox.txt` 与 `Pictures/nsp_probe_sandbox.jpg`，写入含
  包名+时间戳的内容并读回；detail 带实际绝对路径。
  其后是 /Android 整树的判别步骤：`android_root` 写 `Android/nsp_probe_sandbox.txt`
  （沙盒开启时应落镜像），`android_list` 列 `/sdcard/Android`（detail 为条目，
  用来确认自建条目在自己视图里可见），`android_obb_own`/`android_media_own`
  写 `Android/obb|media/<pkg>/`（私有目录让位，应落真实目录），`android_allow`
  写 ALLOW 豁免路径。后三个目录由宿主预建并 chown 给本应用——真实设备上它们由
  系统或安装器建立，以免把「目录不存在」误判成重定向错误。
- `plain`：写 `/sdcard/Android/data/<pkg>/files/plain.txt` 并读回。
- `unlink`：在 `/sdcard/nsp_verify/unlink/` 写 `nsp_probe_unlink.txt` 并保持读句柄，
  删除后立即列举目录（`hidden_open`，期望**新增** `.fuse_hidden` 计数为 0）、用
  `getChannel().size()` 做 fstat、从原句柄读回内容；关闭后再次列举（`hidden_closed`）
  并确认路径消失（`exists_closed`）。宿主还会预置一个历史隐藏名夹具
  `.fuse_hidden0000000000000001`：本层**不做列举过滤、也不自动清理**（保留取证能力），
  因此该夹具必须列举可见（`hidden_legacy`），残留判定只看「新增」。该探针只配一条
  无关 HIDE 以保证被 v1 注入，被测目录本身无任何规则。
- `race`：**刻意不等待就绪**，`onCreate` 起每 ~20ms 尝试写两个判别路径并记录
  `i`（序号）、`ms`（相对 `onCreate` 的毫秒）、`fuse`（当时 `/storage/emulated` 是否已是
  `fuse_daemon`）、`a`（写 `/sdcard/Download/nsp_race_a<i>.txt` 的结果，该包配 `SANDBOX ON`）、
  `b`（写 `/sdcard/nsp_race_b/nsp_race_b<i>.txt` 的结果，该包配 `HIDE`）。结果值为
  `ok` 或 errno 名（`EACCES`/`ENOENT`/`EROFS`…）。拿到就绪后 300ms 样本即收尾，
  末行 `summary` 带 `attempts=` 与 `first_fuse_ms=`（-1 = 6s 内始终未就绪）。

所有 `mkdirs()` 返回值一律忽略：虚拟前缀 / FUSE 合成目录可能返回 `false` 但写入仍成功。

探针 APK 在 manifest 里 `android:debuggable="true"`（仅测试用途，便于 `run-as` 排障）。
