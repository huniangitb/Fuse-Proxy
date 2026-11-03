#!/usr/bin/env python3
"""SFTP 后端测试 — ftp_module(proto=sftp) 经真实 libcurl/libssh2 连本机 sshd。

夹具：非 root 起一份 sshd（127.0.0.1:2222，仅公钥认证，Subsystem sftp），登录
用户 = 当前用户；驱动 tests/fixtures/sftp_backend_driver.c 直接编入**实际后端
源码**（ftp_backend_libcurl.c + ftp_mux.c + ftp_conf.c）并按 backend_* 接口驱动。

为什么不经 FUSE：FUSE 侧要 /dev/fuse（本机沙箱无），且框架的 backend_* 分派
与协议无关——FTP 的端到端链路已由 test_ftp.py 覆盖；本套件要判别的正是 SFTP
特有的那几处（URL scheme / 错误分类 / getattr 探测 / quote 命令映射 / 数据面），
它们在驱动里走的都是真实代码路径。

判别性用例（未做协议分派时必失败）：
  A. 空文件 st_size 必须 0——libssh2 对 0 字节文件把大小报成未知
     （CURLINFO_CONTENT_LENGTH_DOWNLOAD_T = -1），直接透传会得到 st_size=-1。
  B. 缺失路径 16 连发后**完好文件仍可读**——SFTP 下 CURLINFO_RESPONSE_CODE 恒为
     0（libcurl 只给 FTP/SMTP 填 info.httpcode），照抄 FTP 的 resp==0 判据会把
     业务失败当断网 → 8 次即静默，随后完好文件被误杀成 EIO。
  C. 含空格的名字必须能建/读/删——SFTP 的 quote 命令由 libcurl 在**客户端**解析
     （Curl_get_pathname），空白会截断参数；路径还必须先还原百分号编码
     （POSTQUOTE 串不是 URL，带 %20 的命令会让服务器去找字面量名字）。
  D. 非空目录 rmdir 必须 ENOTEMPTY（SFTP: SSH_FX_DIR_NOT_EMPTY → CURLE_QUOTE_ERROR）。
  E. 目录 getattr 的 mtime 来自 SFTP 真目录 stat（非 0），类型位必须是 S_IFDIR。

退出码：0 全过 / 1 失败 / 77 跳过（缺 sshd、sftp-server、libcurl 无 SFTP）。
"""
import os, pwd, re, shlex, shutil, subprocess, sys, tempfile, time
from pathlib import Path

BASE       = "/tmp/fuse_sftp_test"
REMOTE     = f"{BASE}/remote"          # sftp-server 暴露的真实目录（remote_dir）
SSH_DIR    = f"{BASE}/ssh"
CONF_DIR   = f"{BASE}/conf"
MODDIR     = f"{BASE}/modules"
# 模块自有配置：框架读 <modules-dir>/<模块名>/<模块名>.conf 后经视图下发
# （模块不读文件、不跑 inotify——见 docs/modules.md §6.1.1）。
# 驱动段（不经 FUSE）仍用 ftp_conf_load 直接读同一份文件，故两段共用此路径。
CONF_FTP   = f"{MODDIR}/ftp_module/ftp_module.conf"
SERVER     = "SFTP盘"
VP         = f"/{SERVER}"
PORT       = 2222
REPO       = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
MNT        = f"{BASE}/mnt"
STORAGE    = f"{BASE}/storage"
CONF       = f"{CONF_DIR}/injector.conf"
DAEMON     = os.environ.get("FUSE_DAEMON") or f"{REPO}/build_gnu/fuse_daemon"
FTP_MOD_SO = os.environ.get("FTP_MODULE_SO") or f"{REPO}/build_gnu/ftp_module.so"
DRIVER_SRC = f"{REPO}/tests/fixtures/sftp_backend_driver.c"
BACKEND    = os.environ.get("FTP_BACKEND_SRC") or f"{REPO}/src/modules/ftp/ftp_backend_libcurl.c"
SSHD       = "/usr/sbin/sshd"
SFTP_SERVER = "/usr/lib/ssh/sftp-server"

PASS = 0; FAIL = 0; ERRS = []
def ok(d): global PASS; PASS += 1; print(f"  ✅ {d}")
def fail(d, dt=""): global FAIL; FAIL += 1; print(f"  ❌ {d}: {dt}"); ERRS.append((d, dt))
def skip(msg):
    print(f"  ⏭  跳过: {msg}")
    sys.exit(77)

def login_user():
    """本套件的 sshd 只允许非 root 登录（PermitRootLogin no），登录用户取运行者 uid。
    不能依赖 USER 环境变量：非交互 shell / CI 里它常常为空，
    回退到 root 会让全部用例报 EIO（而不是跳过）。"""
    try:
        return pwd.getpwuid(os.getuid()).pw_name
    except KeyError:
        return os.environ.get("USER") or ""

def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)

# ---------------- 夹具 ----------------

def start_sshd():
    if not (os.path.exists(SSHD) and os.path.exists(SFTP_SERVER)):
        skip(f"缺 sshd({SSHD}) 或 sftp-server({SFTP_SERVER})")
    login = login_user()
    if not login or login == "root":
        skip("需非 root 登录用户（sshd 侧 PermitRootLogin no）")
    shutil.rmtree(BASE, ignore_errors=True)
    for d in (REMOTE, SSH_DIR, CONF_DIR):
        os.makedirs(d, exist_ok=True)
    host_key, cli_key = f"{SSH_DIR}/host_ed25519", f"{SSH_DIR}/client_ed25519"
    for k in (host_key, cli_key):
        r = run(["ssh-keygen", "-t", "ed25519", "-f", k, "-N", "", "-q"])
        if r.returncode != 0:
            skip(f"ssh-keygen 失败: {r.stderr.strip()}")
    shutil.copy(f"{cli_key}.pub", f"{SSH_DIR}/authorized_keys")
    os.chmod(f"{SSH_DIR}/authorized_keys", 0o600)
    with open(f"{SSH_DIR}/sshd_config", "w") as fh:
        fh.write(f"""Port {PORT}
ListenAddress 127.0.0.1
HostKey {host_key}
PidFile {SSH_DIR}/sshd.pid
AuthorizedKeysFile {SSH_DIR}/authorized_keys
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
UsePAM no
StrictModes no
PermitRootLogin no
Subsystem sftp {SFTP_SERVER}
LogLevel ERROR
""")
    log = open(f"{BASE}/sshd.log", "w")
    proc = subprocess.Popen([SSHD, "-f", f"{SSH_DIR}/sshd_config", "-D", "-e"],
                            stdout=log, stderr=subprocess.STDOUT)
    for _ in range(50):
        if proc.poll() is not None:
            skip("sshd 启动失败: " + Path(f"{BASE}/sshd.log").read_text(errors="replace")[-300:])
        if run(["ssh-keyscan", "-p", str(PORT), "127.0.0.1"]).stdout.strip():
            break
        time.sleep(0.2)
    else:
        proc.terminate(); skip("sshd 未在 10s 内就绪")
    ks = run(["ssh-keyscan", "-p", str(PORT), "127.0.0.1"])
    if not ks.stdout.strip():
        proc.terminate(); skip("ssh-keyscan 未取到主机密钥")
    Path(f"{SSH_DIR}/known_hosts").write_text(ks.stdout)

    os.makedirs(os.path.dirname(CONF_FTP), exist_ok=True)
    with open(CONF_FTP, "w") as fh:
        fh.write(f"""[{SERVER}]
proto = sftp
host = 127.0.0.1
port = {PORT}
user = {login_user()}
key_file = {cli_key}
known_hosts = {SSH_DIR}/known_hosts
host_key_check = on
remote_dir = {REMOTE}
""")
    return proc

def stop_sshd(proc):
    if proc and proc.poll() is None:
        proc.terminate()
        try: proc.wait(3)
        except Exception: proc.kill()

def wait_remote(rel, want, timeout=8.0):
    """轮询远端（sftp-server 侧）文件内容：写路径是 tmp + 流式上传，异步落远端"""
    deadline = time.time() + timeout
    while time.time() < deadline:
        fp = Path(REMOTE) / rel
        try:
            if fp.is_file() and fp.read_text(errors="replace").strip() == want:
                return True
        except Exception:
            pass
        time.sleep(0.2)
    return False


def fuse_phase():
    """FUSE 端到端：fuse_daemon → 框架 backend_* 分派 → ftp_module(proto=sftp) → sshd。

    需要 /dev/fuse + fusermount3 + GNU 产物（FUSE_DAEMON / FTP_MODULE_SO，默认
    build_gnu/）。三者缺一即**跳过本阶段**（驱动阶段已覆盖协议语义；框架分派与
    协议无关，FTP 侧由 test_ftp.py 端到端覆盖）——但一旦挂上就按真实断言判成败。"""
    if not os.path.exists("/dev/fuse"):
        print("  ⏭  FUSE 阶段跳过：无 /dev/fuse（驱动阶段已覆盖 SFTP 协议语义）")
        return
    if not (os.path.exists(DAEMON) and os.path.exists(FTP_MOD_SO)):
        print(f"  ⏭  FUSE 阶段跳过：缺产物（{DAEMON} / {FTP_MOD_SO}）")
        return
    os.makedirs(f"{STORAGE}/0", exist_ok=True)
    os.makedirs(MNT, exist_ok=True)
    os.makedirs(f"{MODDIR}/ftp_module", exist_ok=True)
    shutil.copy(FTP_MOD_SO, f"{MODDIR}/ftp_module/ftp_module.so")
    with open(CONF, "w") as fh:
        fh.write(f"[GLOBAL]\nFTP /{SERVER} {SERVER}\n")
    subprocess.run(["fusermount3", "-u", MNT], capture_output=True)
    p = subprocess.Popen([DAEMON, "--root=" + STORAGE, "--rules=" + CONF,
                          "--modules-dir=" + MODDIR, "-f", MNT, "info"],
                         stdout=open(f"{BASE}/fuse.log", "w"), stderr=subprocess.STDOUT)
    V = Path(MNT) / "0" / SERVER
    deadline = time.time() + 10
    ready = False
    while time.time() < deadline:
        try:
            if V.is_dir():
                ready = True
                break
        except Exception:
            pass
        if p.poll() is not None:
            break
        time.sleep(0.3)
    if not ready:
        logf = Path(f"{BASE}/fuse.log")
        log = logf.read_text(errors="replace") if logf.exists() else ""
        p.terminate()
        subprocess.run(["fusermount3", "-u", MNT], capture_output=True)
        fail("FUSE 阶段：后端未就绪", log[-300:].replace("\n", " "))
        return
    print("  ✅ FUSE 阶段：daemon 已挂载且 /0/" + SERVER + " 命中 SFTP 后端")
    try:
        items = sorted(os.listdir(V))
        if "orig.txt" in items and "sub" in items:
            ok(f"FUSE 列目录（{len(items)} 项，远端内容可见）")
        else:
            fail("FUSE 列目录", f"{items[:8]}")
        got = (V / "orig.txt").read_text().strip()
        ok("FUSE 读远端文件") if got == "sftp-original-content" else fail("FUSE 读文件", repr(got))
        nf = "nsp_fuse_sftp.txt"
        (V / nf).write_text("via-fuse-sftp")
        if wait_remote(nf, "via-fuse-sftp"):
            ok("FUSE 写入 → 远端出现（经 daemon 全链路）")
        else:
            fail("FUSE 写入", "远端未见内容")
        d = "nsp_fuse_dir"
        (V / d).mkdir()
        ok("FUSE mkdir → 远端目录") if (Path(REMOTE) / d).is_dir() else fail("FUSE mkdir", "远端未见")
        (V / nf).rename(V / "nsp_fuse_ren.txt")
        if (Path(REMOTE) / "nsp_fuse_ren.txt").exists() and not (Path(REMOTE) / nf).exists():
            ok("FUSE rename → 远端一致")
        else:
            fail("FUSE rename", "远端不一致")
        (V / "nsp_fuse_ren.txt").unlink()
        ok("FUSE unlink → 远端删除") if not (Path(REMOTE) / "nsp_fuse_ren.txt").exists() \
            else fail("FUSE unlink", "远端仍在")
        (V / d).rmdir()
        ok("FUSE rmdir → 远端删除") if not (Path(REMOTE) / d).exists() else fail("FUSE rmdir", "远端仍在")
        try:
            (V / "nsp_fuse_missing.txt").stat()
            fail("FUSE 缺失路径", "竟然存在")
        except FileNotFoundError:
            ok("FUSE 缺失路径 → ENOENT")
        sp = "nsp fuse space.txt"
        (V / sp).write_text("SPACED-FUSE")
        if wait_remote(sp, "SPACED-FUSE"):
            (V / sp).unlink()
            if not (Path(REMOTE) / sp).exists():
                ok("FUSE 含空格名：写入 + 删除（quote 转义全链路）")
            else:
                fail("FUSE 含空格删除", "远端仍在")
        else:
            fail("FUSE 含空格写入", "远端未见内容")
        # R3 判别：truncate 必须同步已打开写句柄的本地缓存。
        # 远端预置 100 字节 → open(O_RDWR) 回灌 → ftruncate(0) → 写 1 字节 →
        # close。旧实现只按路径发空 STOR、不碰句柄 tmp_fd，close 时按旧
        # file_end 全量 STOR → 远端复活成 100 字节。旧实现复验：
        # FTP_MODULE_SO=<用旧后端源码现编的 ftp_module.so>。
        tf = "nsp_fuse_trunc.bin"
        tfp = Path(REMOTE) / tf
        tfp.write_bytes(b"0123456789" * 10)
        fd = os.open(str(V / tf), os.O_RDWR)
        try:
            os.ftruncate(fd, 0)
            os.pwrite(fd, b"x", 0)
        finally:
            os.close(fd)
        got = None
        deadline = time.time() + 8
        while time.time() < deadline:
            try:
                got = tfp.read_bytes()
            except Exception:
                got = None
            if got == b"x":
                break
            time.sleep(0.2)
        if got == b"x":
            ok("FUSE truncate 同步已打开写句柄：远端恰好 1 字节（R3）")
        else:
            shown = repr(got[:24]) if got is not None else "<读失败>"
            n = len(got) if got is not None else 0
            fail("FUSE truncate 已打开写句柄",
                 f"远端 {n} 字节 = {shown}（期望 b'x'；旧实现旧尾部复活）")
    finally:
        p.terminate()
        try:
            p.wait(3)
        except Exception:
            p.kill()
        subprocess.run(["fusermount3", "-u", MNT], capture_output=True)


def build_driver(tmp):
    exe = Path(tmp) / "sftp_driver"
    cc = shlex.split(os.environ.get("CC", "cc"))
    cmd = cc + ["-std=c23", "-O1", "-g", "-D_GNU_SOURCE", "-DNSP_MODULE_BUILD",
                f'-DFTP_BACKEND_SRC="{BACKEND}"',
                "-I", f"{REPO}/include",
                "-I", f"{REPO}/src/modules/ftp",
                DRIVER_SRC,
                f"{REPO}/src/modules/ftp/ftp_mux.c",
                f"{REPO}/src/modules/ftp/ftp_conf.c",
                f"{REPO}/src/core/nsp_util.c",
                "-o", str(exe), "-pthread", "-lcurl", "-lm"]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print("C 编译/链接失败：", file=sys.stderr)
        print(r.stderr[-3000:], file=sys.stderr)
        sys.exit(1)
    return exe

# ---------------- 驱动调用 ----------------

def batch(drv, cmds, timeout=180):
    """同一进程（同一后端实例：熔断/缓存状态连续）跑一批命令，逐行解析"""
    r = subprocess.run([str(drv), CONF_FTP, "-"], input="\n".join(cmds) + "\n",
                       capture_output=True, text=True, timeout=timeout)
    if r.returncode == 3:
        skip("本 libcurl 未编入 SFTP（libssh2）")
    lines = [l for l in r.stdout.splitlines() if l.strip()]
    if len(lines) != len(cmds):
        raise RuntimeError(f"驱动输出 {len(lines)} 行 != 命令 {len(cmds)} 条\n"
                           f"STDOUT:\n{r.stdout}\nSTDERR:\n{r.stderr[-2000:]}")
    return [parse(l) for l in lines]

def parse(line):
    d = {"line": line.strip()}
    m = re.match(r"rc=(-?\d+)(.*)$", line.strip())
    if not m:
        return d
    d["rc"] = int(m.group(1))
    rest = m.group(2).strip()
    for kv in re.finditer(r"(\w+)=(\S*)", rest):
        d[kv.group(1)] = kv.group(2)
    return d

def main():
    sshd = start_sshd()
    Path(REMOTE, "orig.txt").write_text("sftp-original-content")
    Path(REMOTE, "sub").mkdir(exist_ok=True)
    Path(REMOTE, "sub", "inner.txt").write_text("INNER")
    Path(REMOTE, "empty.txt").write_bytes(b"")
    Path(REMOTE, "backfill.txt").write_text("REMOTE-PREFIX-DATA")

    try:
        with tempfile.TemporaryDirectory(prefix="sftp_drv_") as tmp:
            drv = build_driver(tmp)

            # ---- 1. 基础：命中/stat/列举/读 ----
            R = batch(drv, [
                f"match {VP}/orig.txt",
                f"getattr {VP}/orig.txt",
                f"getattr {VP}/sub",
                f"getattr {VP}/empty.txt",
                f"getattr {VP}/nsp_missing.txt",
                f"readdir {VP}",
                f"pread {VP}/orig.txt 0 64",
                f"pread {VP}/sub/inner.txt 0 16",
            ])
            ok("backend_match 命中 SFTP 前缀") if R[0]["rc"] == 1 else fail("match", R[0]["line"])

            st = R[1]
            want_len = len("sftp-original-content")
            if st["rc"] == 0 and int(st["size"]) == want_len and (int(st["mode"], 8) & 0o170000) == 0o100000:
                ok(f"文件 getattr：S_IFREG + size={want_len}（SIZE/stat 走通）")
            else:
                fail("文件 getattr", st["line"])
            if st["rc"] == 0 and int(st["mtime"]) > 0:
                ok("文件 mtime 来自远端 stat（非 0）")
            else:
                fail("文件 mtime", st["line"])

            sd = R[2]
            if sd["rc"] == 0 and (int(sd["mode"], 8) & 0o170000) == 0o040000:
                ok("目录 getattr：S_IFDIR（目录探针不被当成文件）")
            else:
                fail("目录 getattr", sd["line"])
            # 判别 E：SFTP 有真目录 stat，mtime 应非 0（FTP 才需要父 LIST 解析）
            if sd["rc"] == 0 and int(sd["mtime"]) > 0:
                ok("目录 mtime 来自 SFTP 目录 stat（非 0）")
            else:
                fail("目录 mtime", sd["line"])

            # 判别 A：空文件 size 必须 0（libssh2 对 0 字节报未知，透传即 -1）
            em = R[3]
            if em["rc"] == 0 and int(em["size"]) == 0:
                ok("判别 A：空文件 st_size == 0（未知大小已归一）")
            else:
                fail("判别 A 空文件 size", em["line"] + "（期望 size=0；-1 即 libssh2 未知大小被透传）")

            # 缺失路径 → ENOENT（文件探针 + 目录探针都判缺失）
            ms = R[4]
            if ms["rc"] == -2:
                ok("缺失路径 getattr → ENOENT")
            else:
                fail("缺失路径", ms["line"] + "（期望 rc=-2）")

            rd = R[5]
            names = set(rd.get("names", "").split(",")) if rd.get("names") else set()
            if rd["rc"] >= 3 and {"orig.txt", "sub", "empty.txt"} <= names:
                ok(f"readdir 列出远端条目（{rd['rc']} 项，含文件与目录）")
            else:
                fail("readdir", rd["line"][:200])

            pr = R[6]
            if pr["rc"] == 0 and pr.get("data") == "sftp-original-content":
                ok("读现有文件内容一致（REST/range 读）")
            else:
                fail("读文件", pr["line"])
            p2 = R[7]
            if p2["rc"] == 0 and p2.get("data") == "INNER":
                ok("读子目录文件一致（路径映射 remote_dir + 相对路径）")
            else:
                fail("读子目录文件", p2["line"])

            # ---- 2. 判别 B：16 连发缺失后完好文件仍可读（熔断误杀） ----
            cmds = [f"getattr {VP}/nsp_brk_{i}.txt" for i in range(16)]
            cmds += [f"getattr {VP}/orig.txt"]
            R = batch(drv, cmds)
            miss_rc = {r["rc"] for r in R[:16]}
            if miss_rc == {-2}:
                ok("判别 B：缺失路径 16 连发全部 ENOENT（未误报 EIO）")
            else:
                fail("判别 B 缺失路径", f"rc 集合={miss_rc}（期望全 -2）")
            last = R[16]
            if last["rc"] == 0:
                ok("判别 B：16 连发缺失后完好文件仍可读（SFTP 业务失败未计入熔断）")
            else:
                fail("判别 B 熔断误杀", last["line"] +
                     "（旧判据把 SFTP 的 resp==0 当断网，8 次即静默 → 完好文件报 EIO）")

            # ---- 3. 写路径 + FLUSH 落远端 + 含空格名字 ----
            wf = f"{VP}/nsp_w.txt"
            sp = f"{VP}/nsp space.txt"
            R = batch(drv, [
                f'write {wf} hello-sftp verify "{REMOTE}/nsp_w.txt"',
                f"pread {wf} 0 32",
                f'write "{sp}" SPACED verify "{REMOTE}/nsp space.txt"',
                f'pread "{sp}" 0 16',
                f"getattr {VP}/nsp_w.txt",
            ])
            if R[0]["rc"] == 0 and R[0].get("remote") == "hello-sftp":
                ok("判别（写路径）：write + FLUSH 后、release 之前远端已有内容")
            else:
                fail("FLUSH 落远端", R[0]["line"])
            if R[1]["rc"] == 0 and R[1].get("data") == "hello-sftp":
                ok("写入内容可读回（上传→下载闭环）")
            else:
                fail("读回写入内容", R[1]["line"])
            # 含空格名（数据面）：write/pread 走 URL，libcurl 自己解码 URL 里的 %20，
            # 故这两条不校验 quote 参数转义——真正的判别在下一批（POSTQUOTE 类操作）。
            if R[2]["rc"] == 0 and R[2].get("remote") == "SPACED":
                ok("含空格名：write+FLUSH 落远端（URL 通道）")
            else:
                fail("含空格名写入", R[2]["line"])
            if R[3]["rc"] == 0 and R[3].get("data") == "SPACED":
                ok("含空格名：pread 读回（URL 通道）")
            else:
                fail("含空格名读取", R[3]["line"])
            if R[4]["rc"] == 0 and int(R[4]["size"]) == len("hello-sftp"):
                ok("新文件 stat size 与写入长度一致")
            else:
                fail("新文件 stat", R[4]["line"])

            # ---- 3b. 判别 C：含空格名的 **POSTQUOTE** 操作 ----
            # SFTP 的 rm/mkdir/rmdir/rename 由 libcurl 在**客户端**用
            # Curl_get_pathname 解析：空白会截断参数（旧实现 → CURLE_QUOTE_ERROR
            # → -EPERM）；路径还须先还原百分号编码，否则服务器找的是字面量
            # "nsp%20space.txt"。这一批才是判别 C 的真正落点。
            spd = f"{VP}/nsp space dir"
            sp2 = f"{VP}/nsp space2.txt"
            R = batch(drv, [f'mkdir "{spd}"',
                            f'rename "{sp}" "{sp2}"',
                            f'getattr "{sp2}"'])
            if R[0]["rc"] == 0 and (Path(REMOTE) / "nsp space dir").is_dir():
                ok("判别 C：含空格目录名 mkdir 成功（quote 参数已加引号）")
            else:
                fail("判别 C 含空格 mkdir", R[0]["line"] +
                     "（旧实现：空白截断参数 → CURLE_QUOTE_ERROR → -EPERM）")
            if R[1]["rc"] == 0 and (Path(REMOTE) / "nsp space2.txt").exists() \
                    and not (Path(REMOTE) / "nsp space.txt").exists():
                ok("判别 C：含空格名 rename 成功（源消失/目标出现）")
            else:
                fail("判别 C 含空格 rename", R[1]["line"])
            if R[2]["rc"] == 0:
                ok("判别 C：改名后 getattr 命中（路径映射一致）")
            else:
                fail("判别 C 改名后 getattr", R[2]["line"])

            # ---- 4. 写模式回灌（O_RDWR 先读远端已有内容） ----
            R = batch(drv, [f"pread {VP}/backfill.txt 0 32 rdwr"])
            if R[0]["rc"] == 0 and R[0].get("data") == "REMOTE-PREFIX-DATA":
                ok("O_RDWR 打开远端已有文件：回灌生效（pread 读到原内容）")
            else:
                fail("O_RDWR 回灌", R[0]["line"])

            # ---- 5. 目录/改名/删除 + 判别 D ----
            # 每批之间做本地核对：同一批里的后续操作会改变状态（例如 rmdir 会把
            # 刚建好的目录删掉），故「建了没」必须在建完那一批之后立刻看。
            R = batch(drv, [f"mkdir {VP}/nsp_d", f"getattr {VP}/nsp_d"])
            if R[0]["rc"] == 0 and (Path(REMOTE) / "nsp_d").is_dir():
                ok("mkdir：远端出现目录")
            else:
                fail("mkdir", R[0]["line"] + f" is_dir={ (Path(REMOTE)/'nsp_d').is_dir() }")
            if R[1]["rc"] == 0 and (int(R[1]["mode"], 8) & 0o170000) == 0o040000:
                ok("新建目录 getattr → S_IFDIR")
            else:
                fail("新建目录 getattr", R[1]["line"])

            R = batch(drv, [
                f"rmdir {VP}/nsp_d",
                f"rmdir {VP}/sub",              # 非空 → ENOTEMPTY（判别 D）
                f"mkdir {VP}/sub",              # 已存在 → EEXIST
                f"rmdir {VP}/nsp_missing_dir",  # 不存在 → ENOENT
            ])
            if R[0]["rc"] == 0 and not (Path(REMOTE) / "nsp_d").exists():
                ok("rmdir 空目录：远端删除")
            else:
                fail("rmdir", R[0]["line"])
            if R[1]["rc"] == -39:
                ok("判别 D：非空目录 rmdir → ENOTEMPTY")
            else:
                fail("判别 D rmdir 非空", R[1]["line"] + "（期望 rc=-39）")
            if (Path(REMOTE) / "sub" / "inner.txt").exists():
                ok("非空目录未被误删（内容完整）")
            else:
                fail("非空目录被删", "inner.txt 消失")
            # mkdir 已存在：OpenSSH 的 sftp-server 只回 SSH_FX_FAILURE（libssh2 文案
            # 是通用的 "Operation failed"），无法细分到 EEXIST——只要求「明确的
            # 业务失败码且不是 EIO」，即不得谎报成功。
            if R[2]["rc"] != 0 and R[2]["rc"] != -5:
                ok(f"mkdir 已存在 → 业务失败码 {R[2]['rc']}（服务器不细分，不谎报成功）")
            else:
                fail("mkdir 已存在", R[2]["line"] + "（期望非 0 业务码）")
            if R[3]["rc"] == -2:
                ok("rmdir 不存在 → ENOENT（错误串细化映射）")
            else:
                fail("rmdir 不存在", R[3]["line"] + "（期望 rc=-2）")

            R = batch(drv, [f"rename {VP}/nsp_w.txt {VP}/nsp_w2.txt",
                            f"getattr {VP}/nsp_w2.txt"])
            if R[0]["rc"] == 0 and (Path(REMOTE) / "nsp_w2.txt").exists() \
                    and not (Path(REMOTE) / "nsp_w.txt").exists():
                ok("rename：远端一致（源消失/目标出现）")
            else:
                fail("rename", R[0]["line"])

            R = batch(drv, [
                f"unlink {VP}/nsp_w2.txt",
                f"getattr {VP}/nsp_w2.txt",     # 已删 → ENOENT
                f'unlink "{sp2}"',              # 判别 C：含空格名 rm
                f'rmdir "{spd}"',               # 判别 C：含空格名 rmdir
                f'unlink {VP}/nsp_w2.txt',      # 再删 → ENOENT
            ])
            if R[0]["rc"] == 0 and not (Path(REMOTE) / "nsp_w2.txt").exists():
                ok("unlink：远端删除")
            else:
                fail("unlink", R[0]["line"])
            if R[1]["rc"] == -2:
                ok("unlink 后 getattr → ENOENT（负缓存/探针一致）")
            else:
                fail("unlink 后 getattr", R[1]["line"] + "（期望 rc=-2）")
            if R[2]["rc"] == 0 and not (Path(REMOTE) / "nsp space2.txt").exists():
                ok("判别 C：含空格文件名 rm 成功")
            else:
                fail("判别 C 含空格 rm", R[2]["line"] + "（旧实现：空白截断参数 → -EPERM）")
            if R[3]["rc"] == 0 and not (Path(REMOTE) / "nsp space dir").exists():
                ok("判别 C：含空格目录名 rmdir 成功")
            else:
                fail("判别 C 含空格 rmdir", R[3]["line"])
            if R[4]["rc"] == -2:
                ok("unlink 缺失文件 → ENOENT（错误串细化映射）")
            else:
                fail("unlink 缺失文件", R[4]["line"] + "（期望 rc=-2）")

            # ---- 6. truncate：0 支持、非 0 明确拒绝 ----
            Path(REMOTE, "nsp_tr.txt").write_text("0123456789")
            R = batch(drv, [
                f"truncate {VP}/nsp_tr.txt 0",
                f"getattr {VP}/nsp_tr.txt",
                f"truncate {VP}/nsp_tr.txt 5",
            ])
            if R[0]["rc"] == 0 and (Path(REMOTE) / "nsp_tr.txt").stat().st_size == 0:
                ok("truncate 0：远端截断为 0")
            else:
                fail("truncate 0", R[0]["line"])
            if R[1]["rc"] == 0 and int(R[1]["size"]) == 0:
                ok("truncate 后 stat size == 0")
            else:
                fail("truncate 后 stat", R[1]["line"])
            if R[2]["rc"] == -5:
                ok("非 0 truncate → -EIO（能力边界明确，不静默假成功）")
            else:
                fail("非 0 truncate", R[2]["line"] + "（期望 rc=-5）")

            # ---- 7. 中文名（URL 编码 → 服务端原始字节） ----
            cn = f"{VP}/nsp_中文名.txt"
            R = batch(drv, [f'write "{cn}" ZH-CN verify "{REMOTE}/nsp_中文名.txt"',
                            f'pread "{cn}" 0 16',
                            f'unlink "{cn}"'])
            if R[0]["rc"] == 0 and R[0].get("remote") == "ZH-CN":
                ok("中文文件名：写入成功（百分号编码还原）")
            else:
                fail("中文文件名写入", R[0]["line"])
            if R[1]["rc"] == 0 and R[1].get("data") == "ZH-CN":
                ok("中文文件名：读取成功")
            else:
                fail("中文文件名读取", R[1]["line"])
            if R[2]["rc"] == 0 and not (Path(REMOTE) / "nsp_中文名.txt").exists():
                ok("中文文件名：删除成功")
            else:
                fail("中文文件名删除", R[2]["line"])

            # ---- 8. 大目录分页（V5 offset 语义在 SFTP 上同样成立） ----
            big = Path(REMOTE) / "nsp_bigdir"
            shutil.rmtree(big, ignore_errors=True)
            big.mkdir()
            want = {f"f{i:04d}" for i in range(120)}
            for n in want:
                (big / n).write_bytes(b"x")
            R = batch(drv, [f"readdir {VP}/nsp_bigdir"])
            got = set(R[0].get("names", "").split(",")) if R[0].get("names") else set()
            if R[0]["rc"] == 120 and got == want:
                ok("大目录 120 条一次列全（SFTP LIST 解析 + 分页）")
            else:
                fail("大目录分页", f"rc={R[0]['rc']} 条目={len(got)}/120")

        # ---- 9. FUSE 端到端（无 /dev/fuse 时自动跳过）----
        fuse_phase()

    finally:
        stop_sshd(sshd)
        shutil.rmtree(BASE, ignore_errors=True)

    print("\n═══════════════════════════════════════")
    print(f"[{time.strftime('%H:%M:%S')}] 测试完成 | ✅ {PASS} 通过 | ❌ {FAIL} 失败 | 共 {PASS+FAIL}")
    if ERRS:
        for d, dt in ERRS:
            print(f"  失败: {d}: {dt}")
        sys.exit(1)

if __name__ == "__main__":
    main()
