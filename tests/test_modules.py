#!/usr/bin/env python3
"""热插拔模块测试 — 后端模块的动态加载/卸载/容错，以及"规则与模块解耦"。

V4 起模块只有后端形态、规则引擎内建，故本套件覆盖：
  1. 规则不依赖模块：模块目录为空时 REDIRECT 照样生效
  2. 后端模块随 .so 放入而接管路径（热插）
  3. 运行中移除 .so：后端不再服务该路径，落回本地直通（热拔）
  4. 损坏 .so：加载失败但 daemon 存活、其它路径正常
  5. 热拔后规则仍在（引擎不受模块存亡影响）
  6. 旧哈希格式 ban 自愈（内容哈希校验弃用后的迁移）
  7. A23-2 首 stat 失败即放弃本轮加载（不得带着未初始化的 st2 继续跑完
     整个「读文件 + memfd + dlopen」流程再误报「在读取期间被写入」）
"""
import subprocess, os, sys, time, shutil
from pathlib import Path

HERE   = Path(__file__).resolve().parent
ROOT   = HERE.parent
MNT    = "/tmp/fuse_mod_test/mnt"
STORAGE= "/tmp/fuse_mod_test/storage"
MODDIR = "/tmp/fuse_mod_test/modules"
CONF   = "/tmp/fuse_mod_test/injector.conf"  # 本套件 BASE 内，勿与其他套件共用
DAEMON = os.environ.get("FUSE_DAEMON") or os.path.abspath(
    os.path.join(HERE, "..", "build_gnu", "fuse_daemon"))
MODULE = "backend_bad"

PASS = 0; FAIL = 0; ERRS = []
def ok(d): global PASS; PASS += 1; print(f"  ✅ {d}")
def fail(d, dt=""): global FAIL; FAIL += 1; print(f"  ❌ {d}: {dt}"); ERRS.append((d, dt))

# ── A23-2 判别垫片：让 daemon 进程内**指定后缀路径的第 N 次 stat** 报 ENOENT ──
#   daemon 以 -D_FILE_OFFSET_BITS=64 编译，只引用 stat64（readelf 可验），
#   故两个符号都拦截；其余一律透传。
#   为何要「第 N 次」而不是「首次」：扫描到新模块时 `module_ban_blocks` 先经
#   so_mtime() 对 .so 做一次 stat（第 1 次），module_prepare 的 st1 才是第 2 次。
#   只打第 2 次，恰好命中 st1 失败而 st2/st3 正常——正是 A23-2 的现场。
STAT_SHIM_C = "/tmp/fuse_mod_test/stat_shim.c"
STAT_SHIM_SO = "/tmp/fuse_mod_test/stat_shim.so"
STAT_SHIM_LOG = "/tmp/fuse_mod_test/shim_events.log"
STAT_SHIM_SRC = r"""
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>

static int (*real_stat64)(const char*, struct stat64*) = NULL;
static int (*real_stat)(const char*, struct stat*) = NULL;
static int (*real_open64)(const char*, int, ...) = NULL;
static int (*real_memfd)(const char*, unsigned int) = NULL;
static int g_hits = 0;
static long g_denied_ms = 0;

static long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* 「紧随首 stat 失败」的窗口：旧实现 stat 一失败就继续 open+memfd_create
   （毫秒级），合法重试要等 5s 定时唤醒——1000ms 窗口两者绝不重叠。 */
static int in_deny_window(void) {
    return g_denied_ms && (now_ms() - g_denied_ms) < 1000;
}

/* 事件记录（本进程内独立文件，不经 daemon 日志系统）：判别「首 stat 失败后
   是否仍继续 open/memfd_create 整个加载流程」——正是 A23-2 的行为分界。 */
static void note(const char* what, const char* detail) {
    const char* p = getenv("NSP_TEST_SHIM_LOG");
    if (!p || !*p) return;
    FILE* f = fopen(p, "a");
    if (!f) return;
    fprintf(f, "%s\t%s\n", what, detail ? detail : "");
    fclose(f);
}

static int matches(const char* path) {
    const char* suf = getenv("NSP_TEST_STAT_DENY_SUFFIX");
    if (!suf || !*suf || !path) return 0;
    size_t pl = strlen(path), sl = strlen(suf);
    return (pl >= sl && strcmp(path + pl - sl, suf) == 0);
}

static int hit(const char* path) {
    const char* nth_s = getenv("NSP_TEST_STAT_DENY_NTH");
    if (!matches(path)) return 0;
    int nth = nth_s ? atoi(nth_s) : 1;
    if (++g_hits != nth) return 0;
    g_denied_ms = now_ms();
    note("STAT_DENIED", path);
    return 1;
}

int stat64(const char* path, struct stat64* buf) {
    if (!real_stat64) real_stat64 = dlsym(RTLD_NEXT, "stat64");
    if (hit(path)) { errno = ENOENT; return -1; }
    return real_stat64(path, buf);
}

int stat(const char* path, struct stat* buf) {
    if (!real_stat) real_stat = dlsym(RTLD_NEXT, "stat");
    if (hit(path)) { errno = ENOENT; return -1; }
    return real_stat(path, buf);
}

/* 首 stat 被拒后**紧随窗口内**出现的 open/memfd_create = 旧实现「带着未初始化
   的 st2 继续跑完整个加载流程」。注意 memfd_create 在 module_prepare 里排在
   open 之前，故两者都要在窗口内独立判定，不能用「命中即清标记」的做法。 */
int open64(const char* path, int flags, ...) {
    if (!real_open64) real_open64 = dlsym(RTLD_NEXT, "open64");
    mode_t mode = 0;
    if (flags & (O_CREAT | O_TMPFILE)) {
        va_list ap; va_start(ap, flags); mode = (mode_t)va_arg(ap, int); va_end(ap);
    }
    if (in_deny_window() && matches(path)) note("OPEN_AFTER_DENY", path);
    return real_open64(path, flags, mode);
}

int memfd_create(const char* name, unsigned int flags) {
    if (!real_memfd) real_memfd = dlsym(RTLD_NEXT, "memfd_create");
    if (in_deny_window()) note("MEMFD_AFTER_DENY", name);
    return real_memfd(name, flags);
}
"""


def build_stat_shim():
    Path(STAT_SHIM_C).write_text(STAT_SHIM_SRC)
    r = subprocess.run(["cc", "-std=c23", "-D_GNU_SOURCE", "-shared", "-fPIC", "-O1",
                        "-Wno-deprecated-declarations",
                        STAT_SHIM_C, "-o", STAT_SHIM_SO, "-ldl"],
                       capture_output=True, text=True)
    if r.returncode != 0:
        print("stat 垫片编译失败:", r.stderr, file=sys.stderr)
        return False
    return True


def asan_runtime_path():
    """daemon 若动态链接了 ASan 运行时，返回其路径（否则空串）。

    ASan 要求自己的运行时**在 LD_PRELOAD 里排第一**，垫片必须排在它之后——
    否则 daemon 直接以「ASan runtime does not come first in initial library
    list」拒绝启动（内存验收跑本套件时就会踩到）。"""
    try:
        out = subprocess.run(["ldd", DAEMON], capture_output=True, text=True).stdout
    except OSError:
        return ""
    for ln in out.splitlines():
        if "libasan" not in ln:
            continue
        parts = ln.split("=>")
        if len(parts) == 2:
            p = parts[1].strip().split(" ")[0]
            if p.startswith("/"):
                return p
    return ""


def build_module():
    """现场编译后端测试模块（第三方模块视角：仅 nsp_module.h）"""
    if not os.path.exists(DAEMON):
        print(f"!! 缺少 {DAEMON}，请先 ninja -C build_gnu"); sys.exit(2)
    out = ROOT / "build_gnu" / f"{MODULE}.so"
    r = subprocess.run(["gcc", "-shared", "-fPIC", "-O1", "-DNSP_MODULE_BUILD",
                        f"-I{ROOT}/include", "-o", str(out), str(HERE / f"{MODULE}.c")],
                       capture_output=True, text=True)
    if r.returncode != 0:
        print(f"!! 测试模块编译失败:\n{r.stderr}"); sys.exit(2)

def build_abi_variants():
    """同一份 backend_abi.c 编两份：合法 ABI 与旧 ABI（-DNSP_TEST_ABI=1）。

    旧 ABI 那份模拟设备上残留的旧 basic_rules.so：模块目录里这类 .so 不随包
    更新消失，而每次事件扫描都会重试一次。"""
    for tag, extra in (("", []), ("_stale", ["-DNSP_TEST_ABI=1"])):
        out = ROOT / "build_gnu" / f"backend_abi{tag}.so"
        r = subprocess.run(["gcc", "-shared", "-fPIC", "-O1", "-DNSP_MODULE_BUILD",
                            f"-I{ROOT}/include", *extra, "-o", str(out),
                            str(HERE / "backend_abi.c")],
                           capture_output=True, text=True)
        if r.returncode != 0:
            print(f"!! backend_abi{tag} 编译失败:\n{r.stderr}"); sys.exit(2)

def setup():
    shutil.rmtree("/tmp/fuse_mod_test", ignore_errors=True)
    subprocess.run(["fusermount3", "-u", MNT], capture_output=True)
    os.makedirs(f"{STORAGE}/0/real_dir", exist_ok=True)   # REDIRECT 相对目标 → storage/0/real_dir
    os.makedirs(f"{STORAGE}/0/normal", exist_ok=True)
    (Path(STORAGE)/"0/real_dir/hi.txt").write_text("redirected")
    (Path(STORAGE)/"0/normal/n.txt").write_text("normal")
    os.makedirs(MNT, exist_ok=True)
    os.makedirs(os.path.dirname(CONF), exist_ok=True)
    os.makedirs(MODDIR, exist_ok=True)   # 空模块目录：case1 验证"无模块也有规则"

def wconf(t): open(CONF, "w").write(t.strip())
def put_module(name=MODULE):
    """原子替换模块 .so：先写 .tmp 再 rename。
    **就地覆盖已被 dlopen 的 .so 会让其已映射页失效**（truncate 使映射页被丢弃，
    再访问时从半写文件中重新缺页 → ops 函数指针变成链接期残值 → 野指针跳转崩
    溃）。rename 换 inode，旧映射不受影响，加载器再按新文件热重载。"""
    os.makedirs(f"{MODDIR}/{name}", exist_ok=True)
    tmp = f"{MODDIR}/{name}/{name}.so.tmp"
    shutil.copy(ROOT / "build_gnu" / f"{name}.so", tmp)
    os.replace(tmp, f"{MODDIR}/{name}/{name}.so")
def rm_module(name=MODULE):
    p = Path(f"{MODDIR}/{name}/{name}.so")
    if p.exists(): p.unlink()

def put_so(src, name):
    """把任意 .so 装成模块 <name>（原子 rename，见 put_module 的说明）。"""
    os.makedirs(f"{MODDIR}/{name}", exist_ok=True)
    tmp = f"{MODDIR}/{name}/{name}.so.tmp"
    shutil.copy(src, tmp)
    os.replace(tmp, f"{MODDIR}/{name}/{name}.so")

def fd_count(proc):
    """daemon 当前打开的 fd 总数（含内存副本 memfd）。"""
    try:
        return len(os.listdir(f"/proc/{proc.pid}/fd"))
    except OSError:
        return -1

def memfd_count(proc, name=None):
    """映射中的模块内存副本数（/proc/<pid>/maps 的 memfd:nsp_module_<名>）。

    模块是否真在册、是否真卸载，都以它为证据（路径名不进 maps）。"""
    pat = f"memfd:nsp_module_{name}" if name else "memfd:nsp_module_"
    try:
        with open(f"/proc/{proc.pid}/maps") as f:
            return sum(1 for line in f if pat in line)
    except OSError:
        return -1

def ban_lines(name):
    """<modules_dir>/.banned 里该模块的记录（name|mtime|reason|ts[|abi]）。"""
    p = Path(MODDIR) / ".banned"
    if not p.exists(): return []
    return [l for l in p.read_text().splitlines() if l.startswith(name + "|")]

def framework_abi():
    """从公开 ABI 头取当前 NSP_MODULE_ABI_VERSION（ban 记录末字段即此值）。"""
    for ln in (ROOT / "include" / "nsp_module.h").read_text().splitlines():
        s = ln.strip()
        if s.startswith("#define NSP_MODULE_ABI_VERSION"):
            return int(s.split()[-1].rstrip("uU"))
    raise RuntimeError("未在 include/nsp_module.h 找到 NSP_MODULE_ABI_VERSION")

def start(extra_env=None):
    env = dict(os.environ)
    if extra_env:
        env.update(extra_env)
    p = subprocess.Popen([DAEMON, "--root="+STORAGE, "--rules="+CONF,
                          "--modules-dir="+MODDIR, "-f", MNT, "info"],
                         stdout=open("/tmp/fm.log", "w"), stderr=subprocess.STDOUT, env=env)
    for _ in range(30):
        time.sleep(0.3)
        try:
            if os.listdir(MNT): return p
        except OSError: pass
        if p.poll() is not None: return None
    return p
def stop(p):
    if p: p.terminate()
    try: p.wait(3)
    except Exception: p.kill()
    subprocess.run(["fusermount3", "-u", MNT], capture_output=True)

def wait_check(path, want, timeout=10.0):
    """轮询等待热插拔生效（loader inotify 归并 1s + 扫描）"""
    p = Path(path)
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            exists = p.exists()
        except OSError:
            exists = False
        if exists == want: return True
        time.sleep(0.4)
    try:
        return p.exists() == want
    except OSError:
        return not want

def backend_serves(timeout=10.0):
    """后端是否在服务 /0/bhealth（isdir 为真 = 模块在册）"""
    end = time.time() + timeout
    while time.time() < end:
        try:
            if os.path.isdir(f"{MNT}/0/bhealth"): return True
        except OSError: pass
        time.sleep(0.3)
    try:
        return os.path.isdir(f"{MNT}/0/bhealth")
    except OSError:
        return False

def run_case(label, body, extra_env=None):
    print(f"\n── {label} ──")
    wconf("""
[GLOBAL]
MONITOR OFF
SANDBOX OFF
REDIRECT /云盘 real_dir
FTP /bhealth seg1
""")
    p = start(extra_env)
    if not p: return fail("启动失败")
    try:
        body(p, Path(MNT))
    finally:
        stop(p)
        try:
            shutil.copy("/tmp/fm.log", f"/tmp/fm_{label.split('.')[0]}.log")
        except OSError:
            pass

def main():
    global PASS, FAIL
    build_module()
    build_abi_variants()
    setup()

    def case1(p, m):
        """引擎内建：模块目录为空，REDIRECT 照样生效"""
        ok("无模块时 REDIRECT 生效") if (m/"0/云盘/hi.txt").exists() else fail(
            "REDIRECT 未生效", "空模块目录下 /0/云盘/hi.txt 不可见（规则不应依赖模块）")
        got = (m/"0/云盘/hi.txt").read_text().strip() if (m/"0/云盘/hi.txt").exists() else ""
        ok("内容重定向") if got == "redirected" else fail("内容", f"got='{got}'")
        ok("普通路径直通") if (m/"0/normal/n.txt").exists() else fail("普通路径", "/0/normal/n.txt 不可见")
        ok("无后端模块时不服务 FTP 路径") if not backend_serves(timeout=2) else fail(
            "FTP 路径不应可用", "/0/bhealth 在没有后端模块时也是目录")
    run_case("1. 规则不依赖模块（空模块目录）", case1)

    def case2(p, m):
        """热插后端模块：放入 .so → 该路径由后端接管"""
        put_module()
        ok("热插：后端接管路径") if backend_serves() else fail("热插", "放入 .so 后 /0/bhealth 仍不是目录")
        ok("热插后规则照常") if (m/"0/云盘/hi.txt").exists() else fail("规则", "热插后 /0/云盘 不可见")
    run_case("2. 热插后端模块", case2)

    def case3(p, m):
        """热拔：移除 .so → 后端不再服务，落回本地直通"""
        put_module()
        if not backend_serves():
            return fail("前置", "后端未接管，无法测热拔")
        rm_module()
        ok("热拔：后端不再服务") if wait_check(f"{MNT}/0/bhealth", False) else fail(
            "热拔", "/0/bhealth 仍由后端服务（应落回本地直通）")
        ok("热拔：普通路径不受影响") if (m/"0/normal/n.txt").exists() else fail("热拔-普通", "直通后普通文件不可见")
        ok("热拔后规则仍在（引擎独立于模块）") if (m/"0/云盘/hi.txt").exists() else fail(
            "热拔后规则", "/0/云盘/hi.txt 不可见——规则不应随模块消失")
    run_case("3. 运行中移除模块（热拔）", case3)

    def case4(p, m):
        """损坏 .so：加载失败但 daemon 存活、普通路径正常"""
        os.makedirs(f"{MODDIR}/broken", exist_ok=True)
        with open(f"{MODDIR}/broken/broken.so", "w") as fh: fh.write("not a real elf")
        time.sleep(3)
        ok("daemon 存活") if p.poll() is None else fail("daemon 崩溃", f"rc={p.poll()}")
        ok("普通路径正常") if (m/"0/normal/n.txt").exists() else fail("普通路径", "坏模块后普通文件不可见")
        rm_module("broken")
    run_case("4. 损坏 .so 容错", case4)

    def case5(p, m):
        """残留的旧 ABI 模块：加载前拒绝 + 按 mtime 落 ban + 不泄漏内存副本 fd

        设备现场：规则引擎内建进框架后删掉了 basic_rules，但 CONFIG_DIR/modules
        不在 Magisk 模块目录内，卸载/更新都不会动它，安装脚本也只 cp 不删 →
        旧 .so 永久残留。每次事件扫描都会重试一次：修复前每次留一条
        ERROR 并泄漏一个 memfd（累积到 nofile 上限即 EMFILE），
        修复后只报一次、之后按文件 mtime 静默跳过。"""
        put_so(ROOT / "build_gnu" / "backend_abi_stale.so", "backend_abi")
        # 首次事件扫描：拒绝 + 落 ban（留足 20s 等 inotify 事件 + 稳定性窗口）
        deadline = time.time() + 20
        while time.time() < deadline and not ban_lines("backend_abi"):
            time.sleep(0.5)
        lines = ban_lines("backend_abi")
        ok("旧 ABI 模块被拒绝并落 ban") if lines else fail(
            "旧 ABI 模块未落 ban", f".banned={lines}")
        if lines:
            ok("ban 原因标注 ABI 不匹配") if "ABI mismatch" in lines[0] else fail(
                "ban 原因", lines[0])
        ok("旧 ABI 模块未加载") if memfd_count(p, "backend_abi") == 0 else fail(
            "旧 ABI 模块被加载了", f"maps 含 {memfd_count(p,'backend_abi')} 个 memfd")

        # 落 ban 后无事件即无扫描：fd 不得增长（修复前每次扫描泄漏一个 memfd）
        fd0 = fd_count(p)
        time.sleep(12)
        fd1 = fd_count(p)
        ok("拒绝后 fd 不增长（静默 12s）") if fd0 == fd1 else fail(
            "fd 泄漏", f"{fd0} → {fd1}（每次扫描各泄漏一个 memfd）")
        ok("拒绝后无残留内存副本") if memfd_count(p, "backend_abi") == 0 else fail(
            "内存副本泄漏", f"maps 含 {memfd_count(p,'backend_abi')} 个 memfd")

        # ban 按文件 mtime：同名文件换了内容（真更新）必须放行，不能挡升级
        put_so(ROOT / "build_gnu" / "backend_abi.so", "backend_abi")
        deadline = time.time() + 20
        while time.time() < deadline and memfd_count(p, "backend_abi") == 0:
            time.sleep(0.5)
        ok("mtime 变化后放行（旧 ban 不挡真更新）") if memfd_count(p, "backend_abi") > 0 else fail(
            "更新被 ban 挡住", "换成合法 ABI 的同名模块后仍未加载")
        ok("放行后陈旧 ban 记录被清除") if not ban_lines("backend_abi") else fail(
            "陈旧 ban 未清除", str(ban_lines("backend_abi")))
        ok("旧 ABI 期间规则/普通路径不受影响") if (m/"0/normal/n.txt").exists() else fail(
            "普通路径", "旧 ABI 模块在场时 /0/normal/n.txt 不可见")
    run_case("5. 残留旧 ABI 模块（拒绝/落 ban/不泄漏 fd/不挡更新）", case5)

    def case6(p, m):
        """旧哈希格式 ban 自愈：.banned 里残留的 name|SHA256|reason|ts 行
        （内容哈希校验已弃用，含 bionic 误杀的 self-hash mismatch 行）命中时
        按 stale 清除并放行"""
        # 先清上一个 case 残留的同名模块，等卸载落定（memfd 从 maps 消失）
        shutil.rmtree(f"{MODDIR}/backend_abi", ignore_errors=True)
        deadline = time.time() + 20
        while time.time() < deadline and memfd_count(p, "backend_abi") != 0:
            time.sleep(0.5)
        so = ROOT / "build_gnu" / "backend_abi.so"
        # 线上真实残留行（ftp self-hash 误杀现场）：第二字段 64 位哈希即旧格式
        with open(Path(MODDIR) / ".banned", "w") as f:
            f.write("backend_abi|1e2513d1f86358166e8fb88304153610e6fcccfcf2d6238726ea8ac0caaa2958|self-hash mismatch|1790780214\n")
        put_so(so, "backend_abi")
        deadline = time.time() + 20
        while time.time() < deadline and memfd_count(p, "backend_abi") == 0:
            time.sleep(0.5)
        ok("陈旧哈希格式 ban 不挡加载") if memfd_count(p, "backend_abi") > 0 else fail(
            "旧格式 ban 未自愈", "残留哈希格式记录阻挡了正常模块")
        ok("旧格式 ban 记录被清除") if not ban_lines("backend_abi") else fail(
            "旧格式 ban 未清除", str(ban_lines("backend_abi")))
    run_case("6. 旧哈希格式 ban 自愈", case6)

    def case6b(p, m):
        """框架 ABI 变化后旧 ban 必须自愈（**升级框架不挡模块**）

        现场：框架 ABI 从旧值升到当前值之前，模块已因 ABI 不匹配被落 ban
        （`name|mtime|ABI mismatch|ts`）。用户升级框架后通常**不会重装/触碰
        .so**，mtime 不变 → 修复前该 ban 永久命中：新框架明明支持该模块，却一直
        静默跳过（症状就是「更新框架后模块再也起不来」）。

        判别构造：手工写 .banned（同名 + 当前 .so 的 mtime），只改末字段 ABI：
          (1) ABI = 当前值     → ban 仍生效（模块**不得**加载）；
          (2) ABI = 别的值     → 视为 stale，记录被清除且模块**加载**。
        修复前（记录无 ABI 字段、查询不看 ABI）(2) 必失败。"""
        # 前置：卸载干净 + 无残留 ban
        shutil.rmtree(f"{MODDIR}/backend_abi", ignore_errors=True)
        try: (Path(MODDIR) / ".banned").unlink()
        except OSError: pass
        deadline = time.time() + 20
        while time.time() < deadline and memfd_count(p, "backend_abi") != 0:
            time.sleep(0.5)

        abi = framework_abi()
        stage = f"/tmp/fm_abi_stage_{os.getpid()}.so"
        shutil.copy(ROOT / "build_gnu" / "backend_abi.so", stage)
        T = int(time.time()) - 60          # 确定的过去时刻，避免与当前秒撞车
        os.utime(stage, (T, T))
        cur_mtime = int(os.stat(stage).st_mtime)

        def install_with_ban(abi_field):
            """写 .banned（同名 + 该 mtime + 指定 ABI 字段）后装入模块。"""
            with open(Path(MODDIR) / ".banned", "w") as f:
                f.write(f"backend_abi|{cur_mtime}|ABI mismatch|{int(time.time())}|{abi_field}\n")
            os.makedirs(f"{MODDIR}/backend_abi", exist_ok=True)
            tmp = f"{MODDIR}/backend_abi/backend_abi.so.tmp"
            shutil.copy2(stage, tmp)        # copy2 保留 mtime
            os.utime(tmp, (T, T))           # 双保险
            os.replace(tmp, f"{MODDIR}/backend_abi/backend_abi.so")

        # (1) 同 ABI：ban 语义不得被削弱
        install_with_ban(str(abi))
        time.sleep(8)
        ok("框架 ABI 未变时 ban 仍生效（模块不加载）") if memfd_count(p, "backend_abi") == 0 else fail(
            "同 ABI 的 ban 被误放行", "模块被加载了，ban 语义被破坏")

        # (2) ABI 变化（模拟框架已升级）：旧 ban 必须自愈
        install_with_ban(str(abi + 1))
        deadline = time.time() + 20
        while time.time() < deadline and memfd_count(p, "backend_abi") == 0:
            time.sleep(0.5)
        ok("框架 ABI 变化后旧 ban 自愈（模块加载）") if memfd_count(p, "backend_abi") > 0 else fail(
            "框架升级仍被旧 ban 挡住", "改 ABI 字段后模块仍未加载（升级框架救不回来）")
        ok("自愈后陈旧记录被清除") if not ban_lines("backend_abi") else fail(
            "陈旧记录未清除", str(ban_lines("backend_abi")))
        try: os.unlink(stage)
        except OSError: pass
    run_case("6b. 框架 ABI 变化后旧 ban 自愈（升级框架不挡模块）", case6b)

    def case7(p, m):
        """A23-2：.so 首次 stat 失败（替换间隙）→ 立即放弃本轮，不得继续跑完
        「读文件 + memfd + dlopen」再用**未初始化的 st2** 做比较。

        旧实现把整个稳定性块包在 `if (stat(so_path,&st1)==0)` 里，st1 失败时
        st2 保持未初始化，却仍在读取后与 st3 比较（UB）：文件明明完好，却按
        「在读取期间被写入」误报并放弃加载，同时白白建/关一个 memfd。
        判别：垫片只让第 2 次 .so stat（= st1）报 ENOENT，并记录此后是否
        **立刻**出现 open/memfd_create（同一轮加载内）：
          新实现 stat 一失败即返回，故只有 STAT_DENIED，无 OPEN/MEMFD_AFTER_DENY；
          旧实现继续 open 该 .so 并建 memfd（UB 比较还在后面），两条都会出现。
        两者都应在 5s 定时重试后成功加载（证明只是放弃本轮，不是卡死）。
        daemon 日志经 UDS 通道、无 log_monitor 时不可观测，故判别信号取垫片
        自记的事件文件（进程内旁路，不受日志系统开关影响）。
        """
        so = ROOT / "build_gnu" / f"{MODULE}.so"
        put_so(so, MODULE)
        deadline = time.time() + 25
        while time.time() < deadline and memfd_count(p, MODULE) == 0:
            time.sleep(0.5)
        try:
            events = Path(STAT_SHIM_LOG).read_text(errors="replace")
        except OSError:
            events = ""
        kinds = {ln.split("\t", 1)[0] for ln in events.splitlines() if ln.strip()}
        ok("首 stat 失败被垫片命中（用例非空转）") if "STAT_DENIED" in kinds else fail(
            "垫片未命中 st1", f"事件: {events!r}（垫片/时序问题，非产品缺陷）")
        ok("首 stat 失败即放弃本轮（未继续 open .so）") if "OPEN_AFTER_DENY" not in kinds else fail(
            "stat 失败后仍 open", "旧实现带着未初始化的 st2 继续跑完加载流程")
        ok("首 stat 失败后未建 memfd") if "MEMFD_AFTER_DENY" not in kinds else fail(
            "stat 失败后仍建 memfd", "白建/白关一个 memfd 后才放弃")
        ok("模块经定时重试后成功加载（未卡死）") if memfd_count(p, MODULE) > 0 else fail(
            "重试未收敛", f"{MODULE} 25s 内仍未加载")
        ok("后端接管路径") if backend_serves(timeout=5) else fail("后端未接管", "/0/bhealth 不是目录")
    if build_stat_shim():
        try:
            os.remove(STAT_SHIM_LOG)
        except OSError:
            pass
        preload = ":".join(p for p in (asan_runtime_path(),
                                       os.environ.get("LD_PRELOAD", ""), STAT_SHIM_SO) if p)
        run_case("7. A23-2 .so 首 stat 失败即放弃本轮", case7,
                 extra_env={"LD_PRELOAD": preload,
                            "NSP_TEST_STAT_DENY_SUFFIX": f"/{MODULE}/{MODULE}.so",
                            "NSP_TEST_STAT_DENY_NTH": "2",
                            "NSP_TEST_SHIM_LOG": STAT_SHIM_LOG})
    else:
        fail("stat 垫片不可用", "无法验证 A23-2（cc 缺失？）")

    print(f"\n═══════════════════════════════════════")
    print(f"[{time.strftime('%H:%M:%S')}] 测试完成 | ✅ {PASS} 通过 | ❌ {FAIL} 失败 | 共 {PASS+FAIL}")
    if ERRS:
        for d, dt in ERRS: print(f"  失败: {d}: {dt}")
        sys.exit(1)

if __name__ == "__main__":
    main()
