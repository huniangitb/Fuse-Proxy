#!/usr/bin/env python3
"""模块故障防护测试 — 熔断器 / 崩溃围栏 / ban 持久化（Phase 1a-1c）。

V4 起规则引擎已内建（`src/daemon/fw_rules.c`），模块只剩「后端存储提供者」形态，
故故障注入一律改由 `backend_*` 承载；「模块还活着」的观测点也从"规则是否生效"
换成"后端是否仍在服务该路径"。

观测口径：配置 `FTP /<关键字> seg1` 后，该虚拟路径由后端模块接管——
`isdir(mnt/0/<健康关键字>)` 为真即模块在册，模块被置毒/卸载后落回本地直通
（本地无此目录）→ 假。

覆盖：
  0. L0 直编契约：槽位失效（acquire 失败）时 fsync/flush 必须返回 -EIO，
     不得对「数据从未交给后端」报成功
  1. 熔断：后端对 /0/berrN 返回**非 errno 契约**码（窗口内 5 次）→ 立即置毒卸载，
     其健康路径随之失效（行为化证据）
  2. 崩溃围栏：backend_match 触发 SIGSEGV → 围栏 longjmp 恢复，daemon 存活，
     单次即置毒；ban 记录 kind=crash
  3. 回调缺失（BADFN）：模块未实现 backend_open/read 时框架静默跳过，
     不得误毒化（模块仍在册、无 ban 记录）
  4. .banned 重写完整性：stale 条目移除不破坏其他模块的 ban 记录
  5. ban 持久化：重启 daemon 后同 mtime 坏 .so 不重载（防崩溃-重载震荡）
  6. backend_readdir 崩溃围栏 → 恢复 + 置毒
  7. backend_readdir 谎报条数（>max）→ 整批丢弃 + 计错误，ls 无垃圾条目
  7b. backend_read 谎报读取量（>size）→ read 返回 EIO + 计错误（不得越界读）
  7c. backend_write 谎报写入量（>size）→ write 返回 EIO + 计错误
  8. 同进程连续两次崩溃（两个模块各一次）daemon 均存活（in_handler 复位）
  9. backend_match 崩溃围栏 + 业务 errno 不计熔断（连续多次 -ENOENT 不得置毒）
  10. ban 自愈 + 槽位复用：坏模块熔断后换同名修复版 .so（mtime 变化）→ 重载恢复

测试模块（gcc 现场编译，第三方视角仅依赖 nsp_module.h，见 docs/modules.md）：
  backend_crash.so — backend_match: bcrash→SIGSEGV / bmatch→认领 / biznoent→业务 -ENOENT
  backend_bad.so   — berr→非 errno 契约违规 / bovf→谎报条数 / breaddir_crash→SIGSEGV
                     / brovf→read 谎报量 / bwovf→write 谎报量 / bhealth→健康基线；
                     -DFIXED 编译出同名修复版供用例 10

前置：build_gnu/ 产物；/dev/fuse；gcc；fusermount3；/var/fuse-proxy/log 可写。
"""
import subprocess, os, sys, time, shutil, errno, tempfile
from pathlib import Path

HERE  = Path(__file__).resolve().parent
ROOT  = HERE.parent
MNT   = Path("/tmp/fuse_circuit_test/mnt")
STORAGE= Path("/tmp/fuse_circuit_test/storage")
MODDIR= Path("/tmp/fuse_circuit_test/modules")
CONF  = Path("/tmp/fuse_circuit_test/injector.conf")  # 本套件 BASE 内，勿与其他套件共用
DLOG  = Path("/tmp/fc.log")
DAEMON= os.environ.get("FUSE_DAEMON") or str(ROOT / "build_gnu" / "fuse_daemon")
# 熔断参数：3 秒窗口 5 次阈值（env 透传给 daemon 进程）
GUARD_ENV = {"NSP_GUARD_WINDOW_SEC": "3", "NSP_GUARD_ERR_MAX": "5"}
ERRLOG  = Path("/var/fuse-proxy/log/module_errors.log")
BANFILE = MODDIR / ".banned"

PASS = 0; FAIL = 0; ERRS = []
def ok(d):  global PASS; PASS += 1; print(f"  ✅ {d}")
def fail(d, dt=""): global FAIL; FAIL += 1; print(f"  ❌ {d}: {dt}"); ERRS.append((d, dt))

def build_modules():
    """按模块 ABI 编译故障测试模块（第三方模块视角：仅 nsp_module.h）。
    只编译到 build_gnu/，不预置进模块目录——各用例 stage_module 按需放置。"""
    if not Path(DAEMON).exists():
        print(f"!! 缺少 {DAEMON}，请先 ninja -C build_gnu"); sys.exit(2)
    for name, extra, cflags in (("backend_crash", "-O1 -g", []),
                                ("backend_bad", "-O1 -g", []),
                                # 同名修复版：模块名仍是 backend_bad，只有 mtime 不同
                                ("backend_bad_fixed", "-O1 -DFIXED", []),
                                # A12：自带配置线程 + 由句柄拥有的数据面线程（exit 不收）
                                ("backend_hold", "-O1 -g", ["-pthread"])):
        out = ROOT / "build_gnu" / f"{name}.so"
        r = subprocess.run(["gcc", "-shared", "-fPIC", *extra.split(), "-DNSP_MODULE_BUILD",
                            *cflags, f"-I{ROOT}/include", "-o", str(out), str(HERE / f"{name.split('_fixed')[0]}.c")],
                           capture_output=True, text=True)
        if r.returncode != 0:
            print(f"!! 测试模块 {name} 编译失败:\n{r.stderr}"); sys.exit(2)

def stage_module(name, as_name=None):
    """放置单个模块进模块目录（用例隔离：每次只加载本用例要测的模块）。
    as_name 用于"同名修复版"（backend_bad_fixed.so 以 backend_bad.so 名义放置）。"""
    as_name = as_name or name
    d = MODDIR / as_name
    d.mkdir(parents=True, exist_ok=True)
    # 原子替换（tmp + rename）：就地覆盖已 dlopen 的 .so 会让其映射页失效，
    # 半写文件被重新缺页后 ops 函数指针变成链接期残值 → 野指针跳转崩溃
    tmp = d / f"{as_name}.so.tmp"
    shutil.copy(ROOT / "build_gnu" / f"{name}.so", tmp)
    os.replace(tmp, d / f"{as_name}.so")
    time.sleep(0.6)   # 模块加载稳定性校验窗口 0.5s，等文件写入完成

def unstage_module(name):
    """用例结束移除模块目录（保留 .banned ban 记录供后续用例使用）"""
    shutil.rmtree(MODDIR / name, ignore_errors=True)

def setup():
    shutil.rmtree("/tmp/fuse_circuit_test", ignore_errors=True)
    subprocess.run(["fusermount3", "-u", str(MNT)], capture_output=True)
    (STORAGE / "0" / "normal").mkdir(parents=True)
    (STORAGE / "0" / "normal" / "n.txt").write_text("normal")
    MNT.mkdir(parents=True)
    CONF.parent.mkdir(parents=True, exist_ok=True)
    if ERRLOG.exists(): ERRLOG.unlink()
    CONF.write_text("[GLOBAL]\nMONITOR OFF\nSANDBOX OFF\n")

def wconf(*kws):
    """写入配置：每个关键字一条 FTP 规则——引擎据此置 is_ftp，框架才会走后端查找"""
    lines = ["[GLOBAL]", "MONITOR OFF", "SANDBOX OFF"]
    lines += [f"FTP /{kw} seg1" for kw in kws]
    CONF.write_text("\n".join(lines) + "\n")

def start(extra_env=None):
    """启动 daemon 并等待挂载就绪（任意内容可见即返回）"""
    env = dict(os.environ, **GUARD_ENV)
    if extra_env:
        env.update(extra_env)
    p = subprocess.Popen([DAEMON, f"--root={STORAGE}", f"--rules={CONF}",
                          f"--modules-dir={MODDIR}", "-f", str(MNT)],
                         stdout=open(DLOG, "w"), stderr=subprocess.STDOUT, env=env)
    for _ in range(45):
        time.sleep(0.3)
        try:
            if list(MNT.iterdir()): return p
        except OSError: pass
        if p.poll() is not None: return None
    return p

def node(kw):
    return MNT / "0" / kw

def alive(kw, timeout=10.0):
    """后端是否仍在服务该关键字路径（模块在册证据）；超时返回最后一次结果"""
    end = time.time() + timeout
    while time.time() < end:
        try:
            if os.path.isdir(node(kw)): return True
        except OSError: pass
        time.sleep(0.3)
    try:
        return os.path.isdir(node(kw))
    except OSError:
        return False

def gone(kw, timeout=12.0):
    """等待该路径不再由后端服务（置毒/卸载后落回本地直通）"""
    end = time.time() + timeout
    while time.time() < end:
        try:
            if not os.path.isdir(node(kw)): return True
        except OSError:
            return True
        time.sleep(0.3)
    try:
        return not os.path.isdir(node(kw))
    except OSError:
        return True

def maps_gone(pid, needle, timeout=8.0):
    """轮询 /proc/<pid>/maps 直到 needle 消失：模块内存副本（memfd:nsp_module_<名>）
    被 dlclose 的内核证据——置毒后若引用未归零会跳过 dlclose，映射永久保留。"""
    end = time.time() + timeout
    while time.time() < end:
        try:
            if needle not in Path(f"/proc/{pid}/maps").read_text():
                return True
        except OSError:
            return False
        time.sleep(0.3)
    try:
        return needle not in Path(f"/proc/{pid}/maps").read_text()
    except OSError:
        return False


def maps_has(pid, needle, timeout=8.0):
    """轮询 /proc/<pid>/maps 直到 needle 出现（模块内存副本仍映射）"""
    end = time.time() + timeout
    while time.time() < end:
        try:
            if needle in Path(f"/proc/{pid}/maps").read_text():
                return True
        except OSError:
            return False
        time.sleep(0.3)
    try:
        return needle in Path(f"/proc/{pid}/maps").read_text()
    except OSError:
        return False


def fd_has_memfd(pid, needle):
    """/proc/<pid>/fd 下是否有指向该 memfd 的 fd（模块映像 memfd 仍被持有的内核证据）。

    注意：不能用 maps 行是否带 `(deleted)` 判别——memfd 是匿名 inode，从创建起
    maps 就恒显示 `/memfd:<名> (deleted)`，close 与否都一样；能区分 fd 是否仍被
    持有的只有 /proc/<pid>/fd。"""
    try:
        for n in os.listdir(f"/proc/{pid}/fd"):
            try:
                if needle in os.readlink(f"/proc/{pid}/fd/{n}"):
                    return True
            except OSError:
                continue
    except OSError:
        return False
    return False


def stop(p):
    if p:
        p.terminate()
        try: p.wait(5)
        except subprocess.TimeoutExpired: p.kill()
    time.sleep(0.3)
    subprocess.run(["fusermount3", "-u", str(MNT)], capture_output=True)

def errlog_text():
    try: return ERRLOG.read_text()
    except OSError: return ""

def banned_text():
    try: return BANFILE.read_text()
    except OSError: return ""

def storm(kw, n=9):
    """错误风暴：路径必须落在 FTP 规则的**组件作用域内**（/berr 覆盖 /berr/x 但不覆盖
    /berr0），故在 kw 下逐次换叶子名——内核对失败 lookup 缓存负 dentry，同名只触达一次"""
    for i in range(n):
        try: (node(kw) / f"x{i}").stat()
        except OSError: pass
        time.sleep(0.12)

# ── §0 L0 直编契约：后端收尾既不能假成功，也不能漏发媒体刷新 ──
# 直编实际源码的 vfs_backend_finish_data，把 module_backend_acquire_slot
# 桩成返回 -1（槽位被置毒/卸载后快照置空）；旧实现 return 0（假成功），
# 新实现必须 -EIO。同一个探针再验三件事：写意图句柄收尾成功时先物化落点、
# 再发一次 media_refresh（reason=ftp_upload，带上调用方 uid/pid 与落点路径），
# 只读句柄收尾两件事都不做——后端内容不产生本地 write 事件，这是扫描侧唯一的
# 机会，而扫描侧只认本地文件。
# FUSE_DAEMON_SRC=<旧源码副本> 可复现失败。
FINISH_DATA_DRIVER = r'''
#define _GNU_SOURCE
#define FUSE_USE_VERSION 317
#include <fuse3/fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <unistd.h>
#include "fw_rules.h"
#include "module_loader.h"
#include "fw_events.h"
#define NSP_FH_HANDLE_MASK ((1ULL << 40) - 1)
#define LOG_ERR(...) ((void)0)
#define LOG_WRN(...) ((void)0)
static struct fuse_context g_ctx;
struct fuse_context* fuse_get_context(void) { return &g_ctx; }
#define NSP_FENCE_FAULT (-5000)
#define NSP_FENCE_BADFN (-5001)
static bool backend_rc_is_business(int rc) { return rc < 0 && rc >= -4095; }
/* 槽位可用性由场景变量控制：0 = 置毒（acquire 失败） */
static int g_slot_ok;
static int fake_flush(uint64_t fh) { (void)fh; return 0; }
static const NspModuleOps g_ops = { .backend_flush = fake_flush };
int module_backend_acquire_slot(int slot, const NspModuleOps** out) {
    (void)slot;
    if (!g_slot_ok) return -1;
    *out = &g_ops;
    return 0;
}
void module_backend_release_slot(int slot) { (void)slot; }
int nsp_fence_backend_flush(int a, const char* b, int (*f)(uint64_t), uint64_t c) {
    (void)a; (void)b; return f(c);
}
static void vfs_inval_path(struct fuse* f, const char* p) { (void)f; (void)p; }
void module_guard_fault(int a, const char* b, const char* c) { (void)a; (void)b; (void)c; }
void module_guard_error(int a, const char* b, int c, const char* d, const char* e) {
    (void)a; (void)b; (void)c; (void)d; (void)e;
}
/* 媒体刷新埋点的替身：只记次数与入参，证明调用点在该调时调、不该调时不调 */
static int g_refresh;
static uid_t g_refresh_uid;
static pid_t g_refresh_pid;
static uint8_t g_refresh_reason;
static char g_refresh_path[PATH_MAX];
/* 物化替身（fw_ingest.c）：发布刷新请求时必须已经调过它——扫描侧按本地路径
   工作，落点下没有真实文件就只能扫到空 */
static int g_ingest;
static int g_refresh_saw_ingest;
static uid_t g_ingest_uid;
static pid_t g_ingest_pid;
static char g_ingest_path[PATH_MAX];
void fw_events_note_media_refresh(uid_t uid, pid_t pid, const char* path, uint8_t reason) {
    g_refresh++;
    g_refresh_uid = uid;
    g_refresh_pid = pid;
    g_refresh_reason = reason;
    g_refresh_saw_ingest = g_ingest;
    snprintf(g_refresh_path, sizeof g_refresh_path, "%s", path);
}
int fw_ingest_materialize(int slot, const char* fuse_path, uid_t uid, pid_t pid) {
    (void)slot;
    g_ingest++;
    g_ingest_uid = uid;
    g_ingest_pid = pid;
    snprintf(g_ingest_path, sizeof g_ingest_path, "%s", fuse_path);
    return 0;
}
__FINISH_FN__
int main(void) {
    g_ctx.uid = 10123;
    g_ctx.pid = 4242;

    int rc_dead = vfs_backend_finish_data(0, 1, "/0/probe.jpg", true);
    int refresh_dead = g_refresh;
    int ingest_dead = g_ingest;

    g_slot_ok = 1;
    g_refresh = 0;
    g_ingest = 0;
    int rc_write = vfs_backend_finish_data(0, 1, "/0/probe.mp3", true);
    int refresh_write = g_refresh;
    int ingest_write = g_ingest;
    int ordered_write = g_refresh_saw_ingest;
    uid_t ingest_uid_write = g_ingest_uid;
    pid_t ingest_pid_write = g_ingest_pid;
    uid_t uid_write = g_refresh_uid;
    pid_t pid_write = g_refresh_pid;
    uint8_t reason_write = g_refresh_reason;
    char path_write[PATH_MAX];
    char ingest_path_write[PATH_MAX];
    snprintf(path_write, sizeof path_write, "%s", g_refresh_path);
    snprintf(ingest_path_write, sizeof ingest_path_write, "%s", g_ingest_path);

    g_refresh = 0;
    g_ingest = 0;
    int rc_read = vfs_backend_finish_data(0, 1, "/0/probe.mp3", false);
    int refresh_read = g_refresh;
    int ingest_read = g_ingest;

    printf("dead_slot_rc=%d dead_refresh=%d dead_ingest=%d\n", rc_dead, refresh_dead, ingest_dead);
    printf("write_rc=%d write_refresh=%d uid=%u pid=%d reason=%u path=%s ingest=%d "
           "ingest_path=%s ordered=%d ingest_uid=%u ingest_pid=%d\n",
           rc_write, refresh_write, (unsigned)uid_write, (int)pid_write,
           (unsigned)reason_write, path_write, ingest_write, ingest_path_write, ordered_write,
           (unsigned)ingest_uid_write, (int)ingest_pid_write);
    printf("read_rc=%d read_refresh=%d read_ingest=%d\n", rc_read, refresh_read, ingest_read);

    int bad = 0;
    if (rc_dead != -EIO || refresh_dead != 0 || ingest_dead != 0) bad = 1;
    if (rc_write != 0 || refresh_write != 1) bad = 1;
    if (uid_write != 10123 || pid_write != 4242) bad = 1;
    if (reason_write != FW_REFRESH_FTP_UPLOAD) bad = 1;
    if (strcmp(path_write, "/0/probe.mp3") != 0) bad = 1;
    /* 物化先于刷新、作用于同一个落点：否则扫描侧拿到的是一个本地不存在的路径 */
    if (ingest_write != 1 || strcmp(ingest_path_write, "/0/probe.mp3") != 0) bad = 1;
    /* 物化落点要按调用方的规则解析：uid/pid 传错就会落到别人扫不到的目录 */
    if (ingest_uid_write != 10123 || ingest_pid_write != 4242) bad = 1;
    if (ordered_write != 1) bad = 1;
    /* 只读句柄收尾不宣称写入：不得物化，也不得发媒体刷新 */
    if (rc_read != 0 || refresh_read != 0 || ingest_read != 0) bad = 1;
    return bad;
}

'''


def _extract_one_function(src_text, name):
    """从实际源码里逐字抽出 static 函数定义（跳过同名前向声明）。"""
    needle = "static int " + name + "("
    start = 0
    while True:
        i = src_text.find(needle, start)
        if i < 0:
            return None
        brace = src_text.find("{", i)
        semi = src_text.find(";", i)
        if brace >= 0 and (semi < 0 or brace < semi):
            break
        start = i + 1
    body = src_text.index("{", i)
    depth = 1
    j = body + 1
    while depth and j < len(src_text):
        if src_text[j] == "{":
            depth += 1
        elif src_text[j] == "}":
            depth -= 1
        j += 1
    return src_text[i:j]


def check_finish_data_contract():
    """R10：槽位失效时 fsync/flush 必须返回 EIO，不得宣称数据已落盘。

    同族的 vfs_read/vfs_write 在同样状态下返回 -EIO；vfs_release 的宽容
    返回 0 保留（release 是幂等销毁，不宣称数据落盘）。
    """
    print("\n── 0. L0 直编契约：后端收尾的 EIO 与媒体刷新 ──")
    src_path = os.environ.get("FUSE_DAEMON_SRC") or str(ROOT / "src/daemon/fuse_daemon.c")
    try:
        src_text = Path(src_path).read_text()
    except OSError as e:
        fail("R10 读取被测源码", f"{src_path}: {e}")
        return
    fn = _extract_one_function(src_text, "vfs_backend_finish_data")
    if not fn:
        fail("R10 抽取 vfs_backend_finish_data", f"{src_path} 中未找到定义")
        return
    cc = os.environ.get("CC", "cc").split()
    if not shutil.which(cc[0]):
        print("  (跳过 R10 直编契约：无 cc)")
        return
    stage = tempfile.mkdtemp(prefix="nsp_finish_data.")
    try:
        c_path = os.path.join(stage, "finish_probe.c")
        exe = os.path.join(stage, "finish_probe")
        Path(c_path).write_text(FINISH_DATA_DRIVER.replace("__FINISH_FN__", fn))
        cmd = [*cc, "-std=gnu23", "-D_GNU_SOURCE", "-Wall", "-Wextra",
               "-Wno-unused-parameter",
               "-I", str(ROOT / "include"), "-I", str(ROOT / "src/daemon"),
               c_path, "-o", exe]
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            fail("R10 直编探针", (r.stderr or r.stdout).strip()[:400])
            return
        p = subprocess.run([exe], capture_output=True, text=True, timeout=30)
        out = (p.stdout + p.stderr).strip()
        if p.returncode == 0:
            ok("槽位失效返回 EIO；写意图收尾发一次 ftp_upload 刷新，只读不收尾不发")
        else:
            fail("后端收尾契约不成立（EIO / 媒体刷新计数）", out[-300:] or f"rc={p.returncode}")
    finally:
        shutil.rmtree(stage, ignore_errors=True)


def check_write_intent_handle():
    """L0 静态契约：写意图必须记在句柄上，不能在 FLUSH/FSYNC 里重算。

    FUSE 的 FLUSH/FSYNC 请求不带 open 标志，libfuse 把 fi->flags 填 0。旧实现
    在这两个回调里算 (fi->flags & O_ACCMODE) != O_RDONLY，后端写句柄的收尾因此
    恒按只读处理：数据照样交给 backend_flush，但"这个落点刚长出媒体文件"的刷新
    请求一条都发不出（真机插桩原文 flags=0 wi=0）。端到端行为回归见 test_ftp.py
    的物化一节。
    """
    print("\n── 0b. L0 静态契约：写意图随句柄走（FLUSH/FSYNC 不带 open 标志）──")
    src_path = os.environ.get("FUSE_DAEMON_SRC") or str(ROOT / "src/daemon/fuse_daemon.c")
    try:
        src_text = Path(src_path).read_text()
    except OSError as e:
        fail("读写意图契约源码", f"{src_path}: {e}")
        return
    bodies = {}
    for name in ("vfs_open", "vfs_create", "vfs_flush", "vfs_fsync"):
        fn = _extract_one_function(src_text, name)
        if fn:
            bodies[name] = fn
        else:
            fail(f"抽取 {name}", f"{src_path} 中未找到定义")
    if len(bodies) != 4:
        return
    for name in ("vfs_open", "vfs_create"):
        if "|= NSP_FH_WRITE_INTENT_FLAG" in bodies[name]:
            ok(f"{name}：按调用方 flags 记录写意图")
        else:
            fail(f"{name} 未记录写意图", "后端句柄置位里没有 NSP_FH_WRITE_INTENT_FLAG")
    for name in ("vfs_flush", "vfs_fsync"):
        body = bodies[name]
        i = body.find("vfs_backend_finish_data(")
        if i < 0:
            fail(f"{name} 收尾调用", "未见 vfs_backend_finish_data 调用")
            continue
        seg = body[i:body.find(");", i) + 2]
        if "O_ACCMODE" in seg:
            fail(f"{name} 收尾写意图", f"仍从 fi->flags 重算（FLUSH/FSYNC 恒为 0）：{seg[:80]!r}")
        elif "NSP_FH_WRITE_INTENT_FLAG" not in seg:
            fail(f"{name} 收尾写意图", f"实参既不是句柄位也不是表达清楚的组合：{seg[:80]!r}")
        else:
            ok(f"{name}：收尾写意图取自句柄")


def main():
    global PASS, FAIL
    check_finish_data_contract()
    check_write_intent_handle()
    setup()
    build_modules()


    # ── 1. 熔断：后端持续契约违规（非 errno 返回码）→ 窗口内 5 次后置毒 ──
    print("\n── 1. 熔断：契约违规风暴 → 自动卸载 + 后端失效 ──")
    wconf("berr", "bhealth")
    stage_module("backend_bad")
    p = start()
    if not p: fail("启动失败"); return 1
    try:
        ok("普通路径直通") if (MNT/"0/normal/n.txt").exists() else fail("普通路径", "n.txt 不可见")
        ok("模块加载：/0/bhealth 由后端服务") if alive("bhealth") else fail("后端前置", "backend_bad 加载后 /0/bhealth 不是目录")
        storm("berr")
        ok("daemon 存活（熔断不杀进程）") if p.poll() is None else fail("daemon 崩溃", f"rc={p.poll()}")
        ok("熔断后后端不再服务（置毒卸载）") if gone("bhealth") else fail("bhealth 应失效", "熔断后仍由后端服务")
        ok("普通路径不受影响") if (MNT/"0/normal/n.txt").exists() else fail("普通路径", "熔断后 n.txt 不可见")
        if "backend_bad" in banned_text() and "circuit" in banned_text():
            ok("ban 落盘（circuit_break）")
        else:
            fail("ban 落盘", f".banned 内容: {banned_text()!r}")
        if "circuit_break" in errlog_text():
            ok("module_errors.log 记录熔断事件")
        else:
            fail("module_errors.log", f"内容: {errlog_text()[:200]!r}")
    finally:
        stop(p)
        unstage_module("backend_bad")

    # ── 2. 崩溃围栏：backend_match 触发 SIGSEGV → longjmp 恢复，单次即置毒 ──
    print("\n── 2. 崩溃围栏：backend_match SIGSEGV → 恢复 + 置毒 ──")
    wconf("bcrash", "bmatch")
    stage_module("backend_crash")
    p = start()
    if not p: fail("启动失败（backend_crash）"); return 1
    try:
        ok("模块加载：/0/bmatch 由后端服务") if alive("bmatch") else fail("后端前置", "backend_crash 加载后 /0/bmatch 不是目录")
        try: (MNT/"0/bcrash/x").stat()
        except OSError: pass
        time.sleep(1.2)
        ok("daemon 存活（崩溃被围栏恢复）") if p.poll() is None else fail("daemon 崩溃", f"rc={p.poll()}")
        ok("崩溃后后端失效（置毒）") if gone("bmatch") else fail("bmatch 应失效", "崩溃后仍由后端服务")
        ok("普通路径不受崩溃影响") if (MNT/"0/normal/n.txt").exists() else fail("普通路径", "崩溃后 n.txt 不可见")
        if "backend_crash" in banned_text():
            ok("崩溃置毒 ban 落盘")
        else:
            fail("崩溃 ban 落盘", f".banned: {banned_text()!r}")
        if "backend_crash" in errlog_text() and "kind=crash" in errlog_text():
            ok("module_errors.log 记录崩溃事件")
        else:
            fail("module_errors.log(崩溃)", f"内容: {errlog_text()[:200]!r}")
    finally:
        stop(p)
        unstage_module("backend_crash")

    # ── 3. BADFN 不触发毒化：模块未实现某后端回调时静默跳过 ──
    print("\n── 3. BADFN 不触发毒化：未实现的后端回调不得误 ban ──")
    # backend_crash 在本用例上一轮（用例 2）已因崩溃被 ban，同 mtime 会加载不上；
    # 本用例要验的是"回调缺失不毒化"，故先清掉 ban 记录（ban 机制本身由 4/5 覆盖）
    if BANFILE.exists(): BANFILE.unlink()
    wconf("bmatch")
    stage_module("backend_crash")   # 只实现 match/getattr/readdir，无 open/read/write
    p = start()
    if not p: fail("启动失败（BADFN）"); return 1
    try:
        ok("模块加载：/0/bmatch 由后端服务") if alive("bmatch") else fail("后端前置", "bmatch 不是目录")
        ok("普通路径直通") if (MNT/"0/normal/n.txt").exists() else fail("普通路径", "n.txt 不可见")
        # 触发未实现回调：open/read 走 backend_open/backend_read（均为 NULL）
        for _ in range(6):
            try:
                with open(node("bmatch") / "x.txt", "rb") as fh: fh.read()
            except OSError:
                pass
            time.sleep(0.2)
        ok("daemon 存活（BADFN 不杀进程）") if p.poll() is None else fail("daemon 崩溃", f"rc={p.poll()}")
        ok("BADFN 后模块仍在册（未被误毒化）") if alive("bmatch") else fail("模块被误毒化", "bmatch 不再由后端服务")
        ok("普通路径不受影响") if (MNT/"0/normal/n.txt").exists() else fail("普通路径", "BADFN 后 n.txt 不可见")
        if "backend_crash" not in banned_text():
            ok("BADFN 未写入 ban 记录")
        else:
            fail("BADFN 误写 ban", f".banned 内容: {banned_text()!r}")
    finally:
        stop(p)
        unstage_module("backend_crash")

    # ── 4. .banned 文件重写完整性：stale 条目移除不破坏其他条目 ──
    print("\n── 4. .banned 重写完整性：stale 条目移除后其他条目保留 ──")
    BANFILE.parent.mkdir(parents=True, exist_ok=True)
    BANFILE.write_text("other_mod|abc123fakehash|test_reason|1700000000\n")
    wconf("berr", "bhealth")
    stage_module("backend_bad")
    p = start()
    if not p: fail("启动失败（ban 重写测试）"); return 1
    try:
        ok("模块加载：/0/bhealth 由后端服务") if alive("bhealth") else fail("后端前置", "bhealth 不是目录")
        storm("berr")
        ok("熔断触发") if gone("bhealth") else fail("bhealth 应失效", "熔断后仍由后端服务")
    finally:
        stop(p)
        unstage_module("backend_bad")

    ban_content = banned_text()
    if "backend_bad" in ban_content and "circuit" in ban_content:
        ok("backend_bad ban 记录已写入")
    else:
        fail("backend_bad ban 记录", f".banned: {ban_content!r}")
    if ("other_mod" in ban_content and "abc123fakehash" in ban_content
            and "test_reason" in ban_content and "1700000000" in ban_content):
        ok("other_mod ban 记录完整保留（未被查找的名字不受重写影响）")
    else:
        fail("other_mod ban 记录被破坏", f".banned: {ban_content!r}")
    if BANFILE.exists(): BANFILE.unlink()

    # ── 5. ban 持久化：重启 daemon 后同 mtime .so 不重载 ──
    print("\n── 5. ban 持久化：重启不重载同 mtime 坏模块 ──")
    wconf("berr", "bhealth")
    stage_module("backend_bad")
    p = start()
    if not p: fail("启动失败（ban 持久化测试）"); return 1
    try:
        ok("模块加载：/0/bhealth 由后端服务") if alive("bhealth") else fail("后端前置", "bhealth 不是目录")
        storm("berr")
        ok("首次熔断并落盘 ban") if "backend_bad" in banned_text() else fail("ban 未落盘", banned_text()[:120])
    finally:
        stop(p)
    # 同 mtime .so 仍在目录：重启后必须被 ban 拦截，不重载
    p = start()
    if not p: fail("重启失败"); return 1
    try:
        time.sleep(1.5)
        ok("重启后同 mtime 坏模块未重载") if not alive("bhealth", timeout=3) else fail("ban 失效", "重启后坏模块又被加载")
        ok("重启后普通路径正常") if (MNT/"0/normal/n.txt").exists() else fail("普通路径", "重启后 n.txt 不可见")
    finally:
        stop(p)
        unstage_module("backend_bad")
    if BANFILE.exists(): BANFILE.unlink()

    # ── 6. backend_readdir 崩溃围栏 ──
    print("\n── 6. backend_readdir 崩溃围栏：SIGSEGV → 恢复 + 置毒 ──")
    wconf("breaddir_crash", "bhealth")
    stage_module("backend_bad")
    p = start()
    if not p: fail("启动失败（readdir 崩溃）"); return 1
    try:
        ok("模块加载：/0/bhealth 由后端服务") if alive("bhealth") else fail("后端前置", "bhealth 不是目录")
        try: list(node("breaddir_crash").iterdir())
        except OSError: pass
        time.sleep(1.2)
        ok("daemon 存活（readdir 崩溃被围栏恢复）") if p.poll() is None else fail("daemon 崩溃", f"rc={p.poll()}")
        ok("readdir 崩溃后模块失效（置毒）") if gone("bhealth") else fail("bhealth 应失效", "readdir 崩溃后仍由后端服务")
        if "backend_readdir" in errlog_text():
            ok("module_errors.log 记录 op=backend_readdir")
        else:
            fail("errlog 缺 op", f"内容: {errlog_text()[:200]!r}")
        # 置毒回收：readdir 崩溃时上报线程还攥着自己那份在途引用，若在持有期间
        # 等引用归零必然 2s 超时 → 跳过 dlclose，模块映射与自有线程永不回收。
        # 断言内核证据：memfd 映射从 maps 消失
        needle = "memfd:nsp_module_backend_bad"
        if maps_gone(p.pid, needle):
            ok("置毒后模块映射已回收（引用先交还 → exit/dlclose）")
        else:
            fail("置毒后模块映射未回收", f"{needle} 仍在 /proc/{p.pid}/maps（引用自持必然超时）")
    finally:
        stop(p)
        unstage_module("backend_bad")
    if BANFILE.exists(): BANFILE.unlink()

    # ── 7. backend_readdir 谎报条数（>max）：整批丢弃，不得越界读 ──
    print("\n── 7. backend_readdir 超限：谎报条数 → 丢弃 + 计错误 ──")
    wconf("bovf", "bhealth")
    stage_module("backend_bad")
    p = start()
    if not p: fail("启动失败（readdir 超限）"); return 1
    try:
        ok("模块加载：/0/bhealth 由后端服务") if alive("bhealth") else fail("后端前置", "bhealth 不是目录")
        entries = []
        # 谎报条数 = 契约违规：每次 readdir 记一次错误，窗口内 5 次即熔断
        for _ in range(7):
            try: entries = [e.name for e in os.scandir(node("bovf"))]
            except OSError: pass
            time.sleep(0.3)
        ok("daemon 存活（超限不越界读）") if p.poll() is None else fail("daemon 崩溃", f"rc={p.poll()}")
        ok("不填充越界条目（无 ovf 垃圾）") if not any("ovf" in e for e in entries) else fail(
            "越界条目", f"entries={entries[:6]}")
        ok("超限被记为契约违规（累计够阈值即熔断）") if gone("bhealth") else fail(
            "超限未记账", f"bhealth 仍由后端服务；errlog: {errlog_text()[:200]!r}")
    finally:
        stop(p)
        unstage_module("backend_bad")
    if BANFILE.exists(): BANFILE.unlink()

    # ── 7b. backend_read 回传 got>size：拒绝 + 计错误（不得越界读） ──
    #     判别：旧实现 `return rc == 0 ? (int)got : …` 直接回包，libfuse 从只有
    #     size 字节的读缓冲取数（ASan 实测 got=4160 时命中堆异常）；且**不计契约
    #     违规**——模块不被熔断、module_errors.log 无记录。新实现按契约违规拒绝
    #     （-EIO）并计错误，窗口内累计 5 次即置毒落 ban。判别看**记账**（ban +
    #     errlog），不只看 read 的 errno：越界回包会被内核拒收，两侧 errno 都是 EIO。
    print("\n── 7b. backend_read 谎报读取量（>size）：拒绝 + 计错误 ──")
    wconf("brovf")
    stage_module("backend_bad")
    p = start()
    if not p: fail("启动失败（read 超限）"); return 1
    try:
        got_eio = False
        try:
            fd = os.open(str(node("brovf")), os.O_RDONLY)
            try:
                os.read(fd, 4096)
            except OSError as e:
                got_eio = (e.errno == errno.EIO)
            finally:
                os.close(fd)
        except OSError as e:
            fail("read 超限前置：open 后端文件", str(e))
        ok("backend_read 回传超长 → read 不返回成功（EIO）") if got_eio else fail(
            "read 超长未拒绝", "read 未返回 EIO（旧实现直接回包，堆越界读）")
        # 累计到熔断阈值（窗口内 5 次）→ 置毒卸载 + ban 落盘 + module_errors.log
        for _ in range(6):
            try:
                fd = os.open(str(node("brovf")), os.O_RDONLY)
                try: os.read(fd, 4096)
                except OSError: pass
                finally: os.close(fd)
            except OSError: pass
            time.sleep(0.2)
        ok("daemon 存活（read 超限不越界）") if p.poll() is None else fail("daemon 崩溃", f"rc={p.poll()}")
        ok("read 超限被记为契约违规（累计够阈值即熔断落 ban）") if (
            BANFILE.exists() and "backend_bad" in BANFILE.read_text()) else fail(
            "read 超限未记账", f"ban: {BANFILE.read_text()[:200] if BANFILE.exists() else '(无)'!r}")
        # 注意 "op=backend_read)" 带右括号：避免被 backend_readdir 的日志误命中
        ok("module_errors.log 记录 op=backend_read") if "op=backend_read)" in errlog_text() else fail(
            "errlog 缺 op=backend_read", f"内容: {errlog_text()[:200]!r}")
    finally:
        stop(p)
        unstage_module("backend_bad")
    if BANFILE.exists(): BANFILE.unlink()

    # ── 7c. backend_write 回传 wrote>size：拒绝 + 计错误 ──
    #     判别同 7b：旧实现回报「写入量大于请求量」且不计契约违规（模块不被熔断）；
    #     新实现拒绝（-EIO）并计错误 → 累计熔断落 ban + errlog。
    print("\n── 7c. backend_write 谎报写入量（>size）：拒绝 + 计错误 ──")
    wconf("bwovf")
    stage_module("backend_bad")
    p = start()
    if not p: fail("启动失败（write 超限）"); return 1
    try:
        got_eio = False
        try:
            fd = os.open(str(node("bwovf")), os.O_WRONLY)
            try:
                os.write(fd, b"x" * 128)
            except OSError as e:
                got_eio = (e.errno == errno.EIO)
            finally:
                os.close(fd)
        except OSError as e:
            fail("write 超限前置：open 后端文件", str(e))
        ok("backend_write 回传超长 → write 不返回成功（EIO）") if got_eio else fail(
            "write 超长未拒绝", "write 未返回 EIO（旧实现回报大于请求量）")
        for _ in range(6):
            try:
                fd = os.open(str(node("bwovf")), os.O_WRONLY)
                try: os.write(fd, b"x" * 128)
                except OSError: pass
                finally: os.close(fd)
            except OSError: pass
            time.sleep(0.2)
        ok("daemon 存活（write 超限不越界）") if p.poll() is None else fail("daemon 崩溃", f"rc={p.poll()}")
        ok("write 超限被记为契约违规（累计够阈值即熔断落 ban）") if (
            BANFILE.exists() and "backend_bad" in BANFILE.read_text()) else fail(
            "write 超限未记账", f"ban: {BANFILE.read_text()[:200] if BANFILE.exists() else '(无)'!r}")
        ok("module_errors.log 记录 op=backend_write") if "op=backend_write)" in errlog_text() else fail(
            "errlog 缺 op=backend_write", f"内容: {errlog_text()[:200]!r}")
    finally:
        stop(p)
        unstage_module("backend_bad")
    if BANFILE.exists(): BANFILE.unlink()

    # ── 8. 同进程连续两次崩溃均恢复（in_handler 复位） ──
    print("\n── 8. 连续两次崩溃：daemon 全程存活 ──")
    wconf("bcrash", "breaddir_crash", "bhealth")
    stage_module("backend_crash")
    stage_module("backend_bad")
    p = start()
    if not p: fail("启动失败（连续崩溃）"); return 1
    try:
        try: (MNT/"0/bcrash/x").stat()
        except OSError: pass
        time.sleep(1.2)
        ok("第一次崩溃后 daemon 存活") if p.poll() is None else fail("首次崩溃即死", f"rc={p.poll()}")
        try: list(node("breaddir_crash").iterdir())
        except OSError: pass
        time.sleep(1.2)
        ok("第二次崩溃后 daemon 仍存活") if p.poll() is None else fail("二次崩溃带崩", f"rc={p.poll()}")
        ok("普通路径仍可用") if (MNT/"0/normal/n.txt").exists() else fail("普通路径", "两次崩溃后 n.txt 不可见")
    finally:
        stop(p)
        unstage_module("backend_crash")
        unstage_module("backend_bad")
    if BANFILE.exists(): BANFILE.unlink()

    # ── 9. 业务 errno 不计熔断（FTP 路径频繁 ENOENT 不得置毒） ──
    print("\n── 9. 业务 errno 豁免：连续 -ENOENT 不得触发熔断 ──")
    wconf("biznoent")
    stage_module("backend_crash")
    p = start()
    if not p: fail("启动失败（业务 errno）"); return 1
    try:
        # FTP 是**组件级**前缀：规则 `FTP /biznoent` 只覆盖 /0/biznoent 及其子路径，
        # 不覆盖 /0/biznoent0（那是另一个组件名）。旧实现 stat /0/biznoent0..5 全部
        # 落本地直通，业务 errno 生产者（backend_crash 的 bc_getattr）根本没被调用
        # ——用例空转。storm() 在 /0/biznoent/<叶子> 逐次换名，既落在组件作用域内，
        # 又绕开内核失败 lookup 的负 dentry 缓存（同名只触达一次）。
        storm("biznoent")
        time.sleep(1.0)
        ok("daemon 存活") if p.poll() is None else fail("daemon 崩溃", f"rc={p.poll()}")
        if "backend_crash" not in banned_text():
            ok("业务 errno 未触发熔断（无 ban 记录）")
        else:
            fail("业务 errno 误熔断", f".banned: {banned_text()!r}")
        ok("普通路径正常") if (MNT/"0/normal/n.txt").exists() else fail("普通路径", "n.txt 不可见")
    finally:
        stop(p)
        unstage_module("backend_crash")
    if BANFILE.exists(): BANFILE.unlink()

    # ── 10. ban 自愈 + 槽位复用：换同名修复版 .so（mtime 变化）→ 重载恢复 ──
    print("\n── 10. ban 自愈：同 mtime 被 ban → 换修复版 .so → 重载恢复 ──")
    wconf("berr", "bhealth")
    stage_module("backend_bad")
    p = start()
    if not p: fail("启动失败（ban 自愈）"); return 1
    try:
        ok("坏版本加载并生效") if alive("bhealth") else fail("后端前置", "bhealth 不是目录")
        storm("berr")
        ok("坏版本被熔断") if gone("bhealth") else fail("bhealth 应失效", "坏版本仍生效")
        if "backend_bad" in banned_text():
            ok("坏版本已 ban")
        else:
            fail("坏版本未 ban", banned_text()[:120])
    finally:
        stop(p)

    # 同目录换入同名修复版（.so 内容不同 → mtime 变化 → 允许重载）
    # 注意 .banned 需保留：正是"mtime 不同才放行"的验证点
    unstage_module("backend_bad")
    stage_module("backend_bad_fixed", as_name="backend_bad")
    p = start()
    if not p: fail("重启失败（修复版）"); return 1
    try:
        ok("换修复版后重载恢复（mtime 变化绕过 ban）") if alive("bhealth") else fail(
            "修复版未恢复", "bhealth 仍不可用（ban 未按 mtime 放行）")
        ok("普通路径正常") if (MNT/"0/normal/n.txt").exists() else fail("普通路径", "n.txt 不可见")
    finally:
        stop(p)
        unstage_module("backend_bad")
    if BANFILE.exists(): BANFILE.unlink()

    # ── 11. A12 quiescence 门控：应用仍持有句柄时置毒不得 dlclose ──
    # 建模 FTP 形态：模块自有**数据面**线程由「打开句柄」拥有（exit 不 join），
    # active_handles>0 时 dlclose 会让它在失效页上执行 → 不在围栏窗口内 → daemon 死。
    print("\n── 11. A12 置毒 quiescence 门控：活跃句柄 > 0 → 保持 .so 映射不 dlclose ──")
    wconf("bhbad", "bhok")
    stage_module("backend_hold")
    active_marker = MODDIR / "hold_active"
    active_marker.write_text("1")  # 标记文件存在 → nsp_module_active_handles() 返回 1
    p = start(extra_env={"NSP_TEST_ACTIVE": str(active_marker)})
    if not p: fail("启动失败（A12 quiescence）"); return 1
    needle = "memfd:nsp_module_backend_hold"
    try:
        ok("模块加载：/0/bhok 由后端服务") if alive("bhok") else fail(
            "后端前置", "backend_hold 加载后 /0/bhok 不是目录")
        storm("bhbad")
        time.sleep(0.8)
        ok("daemon 存活（活跃句柄时置毒不 dlclose → 数据面线程不踩空）") if p.poll() is None else fail(
            "daemon 崩溃", f"rc={p.poll()}（残留数据面线程执行已解除映射的代码）")
        ok("置毒后模块失效（槽位已置空）") if gone("bhok") else fail(
            "bhok 应失效", "置毒后仍由后端服务")
        if "backend_hold" in banned_text():
            ok("ban 落盘（circuit_break）")
        else:
            fail("ban 落盘", f".banned: {banned_text()!r}")
        # A12 的判别证据：活跃句柄 > 0 → 门控跳过 dlclose → memfd 映射必须仍在
        if maps_has(p.pid, needle, 1.5):
            ok("活跃句柄 > 0 → 保持 .so 映射（未 dlclose）")
        else:
            fail("模块映射被解除", f"{needle} 已从 maps 消失"
                 "（旧实现 dlclose → 残留数据面线程带崩 daemon）")
        # ── A23-1：模块继续持映射时，其 memfd **fd** 也不得提前 close ──
        #    旧实现在 drain/exit 之前就 close(mfd)，且放弃卸载的回滚分支不复原
        #    m->mfd → 模块还在册却已无 memfd fd，maps 行退化为 (deleted)，
        #    违反「加载成功后保持打开到模块卸载」的槽位契约。
        #    判别信号：/proc/<pid>/fd 里仍有该 memfd（maps 判别不了，见 fd_has_memfd
        #    注释：memfd 从创建起 maps 就带 (deleted)）。
        if fd_has_memfd(p.pid, needle):
            ok("未卸载模块仍持有 memfd fd（无提前 close）")
        else:
            fail("memfd 被提前 close",
                 f"/proc/{p.pid}/fd 下已无 {needle}（旧实现在 drain/exit 前就 close，"
                 "且放弃卸载的回滚不复原 m->mfd）")
    finally:
        active_marker.unlink(missing_ok=True)
        stop(p)
        unstage_module("backend_hold")
    if BANFILE.exists(): BANFILE.unlink()

    print(f"\n═══════════════════════════════════════")
    print(f"[{time.strftime('%H:%M:%S')}] 测试完成 | ✅ {PASS} 通过 | ❌ {FAIL} 失败 | 共 {PASS+FAIL}")
    if ERRS:
        for d, dt in ERRS: print(f"  失败: {d}: {dt}")
    # 退出码必须反映失败：此前入口是裸 main()，子用例 fail() 后仍 0 退出（假绿）。
    # 各前置失败分支已改为 return 1，此处兜住正常走完的路径。
    return 1 if ERRS else 0

if __name__ == "__main__":
    sys.exit(main())
