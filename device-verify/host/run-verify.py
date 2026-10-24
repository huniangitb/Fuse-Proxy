#!/usr/bin/env python3
"""设备端全链路验证编排器（Fuse-Proxy 模块，v1 逐应用挂载）

安全模型
--------
1. 挂载方式固定 v1：验证配置只点名 6 个探针包，生产应用完全不在注入范围。
2. 配置隔离：验证使用 device-verify/build 交叉构建的验证版二进制，其编译期
   NSP_CONFIG_DIR=/data/local/tmp/nsp_verify/config；生产配置
   /data/Namespace-Proxy 全程只读（前后 sha256 对比断言）。
3. 宿主服务隔离：FTP/SFTP 服务器都跑在临时目录 + 127.0.0.1 + 临时密钥，
   经 adb reverse 映射到设备回环，不暴露局域网，也不碰宿主已有的 vsftpd/sshd。
4. 设备侧写操作只经 device/verify-device.sh（路径固定 /data/local/tmp/nsp_verify）；
   编排器本身只做只读查询、adb install/reverse/logcat 与受控脚本调用。
5. 任何一步失败都会在 finally 里停验证实例、清验证目录、重启生产服务。

覆盖
----
- ftp / sftp：探针启动即在虚拟前缀写文件，宿主核对后端落盘 + 真实存储零侧漏。
- iso：SANDBOX ON，探针写 Download/Pictures，核对真实共享目录无文件、
  文件落在 <STORAGE_BASE>/<uid>/Android/data/<pkg>/sandbox/ 下。
- hide：两阶段——先由探针创建 canary，热重载配置加 HIDE，再启动必须 ENOENT
  且真实文件仍在。
- plain：对照组，普通外部目录读写不受影响。
- race：刻意不等待就绪，立即反复写 Download（SANDBOX ON）与 HIDE 路径，量出 v1
  的未覆盖窗口与「就绪前写入落真实存储」的侧漏次数（默认只告警，--strict-race 计失败）。

退出码：0 全过 / 1 有失败 / 77 环境不满足跳过。
"""
import argparse
import getpass
import hashlib
import os
import re
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
DV = REPO / "device-verify"
DIST = DV / "dist"
ADB_SH = REPO / "scripts" / "adb-sh.sh"
DEV_SCRIPT = DV / "device" / "verify-device.sh"

VR = "/data/local/tmp/nsp_verify"
CFG = VR + "/config"
BIN = VR + "/bin"
STAGE = VR + "/staging"
DEV_SCRIPT_REMOTE = "/data/local/tmp/nsp_verify.sh"

PROBE_ACT = "nsp.probe.ProbeActivity"
CASES = ("ftp", "sftp", "iso", "plain", "hide")
# 竞态探针：刻意不等待 FUSE 就绪，用于测量 v1「补挂载」与「应用首写」的先后。
# 单独成组：它没有 ready 步，断言口径与其余 5 个功能探针不同。
RACE = "race"
RACE_ITERATIONS = 3
SDCARD = "/sdcard"
REAL_ROOT = "/data/media/0"
VERIFY_ROOT_REAL = REAL_ROOT + "/nsp_verify"


class VerifyError(RuntimeError):
    pass


def pkg(case):
    return "nsp.probe." + case


def run(cmd, *, check=True, env=None, input=None):
    p = subprocess.run(cmd, text=True, capture_output=True, env=env, input=input)
    if check and p.returncode != 0:
        raise VerifyError(
            "命令失败(%d): %s\n--- stdout ---\n%s\n--- stderr ---\n%s"
            % (p.returncode, " ".join(str(c) for c in cmd), p.stdout[-4000:], p.stderr[-4000:])
        )
    return p


def parse_kv(text):
    out = {}
    for line in text.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def port_free(port, host="127.0.0.1"):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind((host, port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def wait_port(port, timeout=10.0, host="127.0.0.1"):
    end = time.time() + timeout
    while time.time() < end:
        s = socket.socket()
        s.settimeout(0.5)
        try:
            s.connect((host, port))
            return True
        except OSError:
            time.sleep(0.1)
        finally:
            s.close()
    return False


# ---------------------------------------------------------------- adb / device


class Adb:
    def __init__(self, serial=None, dry=False):
        self.base = ["adb"] + (["-s", serial] if serial else [])
        self.env = dict(os.environ)
        if serial:
            self.env["ANDROID_SERIAL"] = serial
        self.dry = dry

    def raw(self, *args, check=True):
        return run(self.base + list(args), check=check, env=self.env)

    def shell(self, cmd, check=True):
        return run(self.base + ["shell", cmd], check=check, env=self.env)

    def sh_root(self, action, *args, check=True):
        inner = "sh %s %s" % (DEV_SCRIPT_REMOTE, action)
        for a in args:
            inner += " " + shlex.quote(a)
        if self.dry:
            print("[dry] adb-sh: su -c %r" % inner)
            return subprocess.CompletedProcess([], 0, "", "")
        return run([str(ADB_SH), "su -c '%s'" % inner], check=check, env=self.env)

    def push(self, local, remote):
        if self.dry:
            print("[dry] adb push %s %s" % (local, remote))
            return
        run([str(ADB_SH), "push", str(local), remote], env=self.env)

    def install(self, apk):
        if self.dry:
            print("[dry] adb install -r -g %s" % apk)
            return
        self.raw("install", "-r", "-g", str(apk))

    def uninstall(self, package):
        if self.dry:
            print("[dry] adb uninstall %s" % package)
            return
        self.raw("uninstall", package, check=False)

    def reverse_add(self, port):
        if self.dry:
            print("[dry] adb reverse tcp:%d tcp:%d" % (port, port))
            return
        self.raw("reverse", "tcp:%d" % port, "tcp:%d" % port)

    def reverse_del(self, port):
        if self.dry:
            print("[dry] adb reverse --remove tcp:%d" % port)
            return
        self.raw("reverse", "--remove", "tcp:%d" % port, check=False)

    def logcat_clear(self):
        if self.dry:
            return
        self.raw("logcat", "-c", check=False)

    def logcat_dump(self):
        if self.dry:
            return ""
        p = self.raw("logcat", "-d", "-v", "threadtime", "-s", "NSP_PROBE:I", check=False)
        return p.stdout


# ------------------------------------------------------------------- servers


class FtpServer:
    def __init__(self, base, port, pasv_ports):
        self.base = Path(base)
        self.port = port
        self.pasv = pasv_ports
        self.proc = None
        self.log = None
        self.root = self.base / "ftp_root"
        self.upload = self.root / "upload"

    def start(self):
        self.root.mkdir(parents=True, exist_ok=True)
        self.upload.mkdir(parents=True, exist_ok=True)
        os.chmod(self.root, 0o755)
        os.chmod(self.upload, 0o777)
        secure = self.base / "ftp_secure"
        secure.mkdir(exist_ok=True)
        os.chmod(secure, 0o755)
        conf = self.base / "vsftpd.conf"
        conf.write_text(
            "listen=YES\n"
            "listen_ipv6=NO\n"
            "listen_address=127.0.0.1\n"
            "listen_port=%d\n"
            "anonymous_enable=YES\n"
            "anon_root=%s\n"
            "write_enable=YES\n"
            "anon_upload_enable=YES\n"
            "anon_mkdir_write_enable=YES\n"
            "anon_other_write_enable=YES\n"
            "anon_world_readable_only=NO\n"
            "local_enable=NO\n"
            "pasv_enable=YES\n"
            "pasv_min_port=%d\n"
            "pasv_max_port=%d\n"
            "pasv_address=127.0.0.1\n"
            "secure_chroot_dir=%s\n"
            "run_as_launching_user=YES\n"
            "no_log_lock=YES\n"
            "seccomp_sandbox=NO\n"
            "background=NO\n"
            % (self.port, self.root, min(self.pasv), max(self.pasv), secure)
        )
        self.log = open(self.base / "vsftpd.log", "w")
        self.proc = subprocess.Popen(
            ["vsftpd", str(conf)], stdout=self.log, stderr=subprocess.STDOUT
        )
        if not wait_port(self.port, 8.0):
            raise VerifyError("FTP 服务器未就绪（端口 %d）：%s" % (self.port, self._tail()))
        return self

    def _tail(self):
        try:
            return (self.base / "vsftpd.log").read_text(errors="replace")[-800:]
        except OSError:
            return ""

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(3)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        if self.log:
            self.log.close()


class SftpServer:
    def __init__(self, base, port, user):
        self.base = Path(base)
        self.port = port
        self.user = user
        self.proc = None
        self.log = None
        self.root = self.base / "sftp"
        self.upload = self.root / "upload"
        self.client_key = self.base / "client_rsa"
        self.known_hosts = self.base / "known_hosts"

    def start(self):
        for d in (self.root, self.upload, self.base / "sshd"):
            d.mkdir(parents=True, exist_ok=True)
        os.chmod(self.root, 0o755)
        os.chmod(self.upload, 0o777)
        host_key = self.base / "sshd" / "host_rsa"
        run(["ssh-keygen", "-t", "rsa", "-b", "3072", "-f", str(host_key), "-N", "", "-q"])
        # 客户端私钥必须是 PEM（PKCS#1）：设备侧 libssh2 以 mbedTLS 为后端，
        # 不解析 OpenSSH 新版私钥格式（BEGIN OPENSSH PRIVATE KEY）。
        run(["ssh-keygen", "-t", "rsa", "-b", "3072", "-m", "PEM", "-f", str(self.client_key),
             "-N", "", "-q"])
        auth = self.base / "sshd" / "authorized_keys"
        shutil.copy(str(self.client_key) + ".pub", auth)
        os.chmod(auth, 0o600)
        conf = self.base / "sshd" / "sshd_config"
        conf.write_text(
            "Port %d\n"
            "ListenAddress 127.0.0.1\n"
            "HostKey %s\n"
            "PidFile %s\n"
            "AuthorizedKeysFile %s\n"
            "PasswordAuthentication no\n"
            "KbdInteractiveAuthentication no\n"
            "PubkeyAuthentication yes\n"
            "UsePAM no\n"
            "StrictModes no\n"
            "PermitRootLogin no\n"
            "Subsystem sftp /usr/lib/ssh/sftp-server\n"
            "LogLevel VERBOSE\n"
            % (self.port, host_key, self.base / "sshd" / "sshd.pid", auth)
        )
        self.log = open(self.base / "sshd.log", "w")
        self.proc = subprocess.Popen(
            ["/usr/sbin/sshd", "-f", str(conf), "-D", "-e"],
            stdout=self.log,
            stderr=subprocess.STDOUT,
        )
        if not wait_port(self.port, 10.0):
            raise VerifyError("SFTP 服务器未就绪（端口 %d）：%s" % (self.port, self._tail()))
        ks = run(["ssh-keyscan", "-p", str(self.port), "127.0.0.1"], check=False)
        key_lines = [ln for ln in ks.stdout.splitlines() if ln.strip() and not ln.startswith("#")]
        if not key_lines:
            raise VerifyError("ssh-keyscan 未取到主机密钥")
        self.known_hosts.write_text(chr(10).join(key_lines) + chr(10))
        return self

    def _tail(self):
        try:
            return (self.base / "sshd.log").read_text(errors="replace")[-800:]
        except OSError:
            return ""

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(3)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        if self.log:
            self.log.close()


# ------------------------------------------------------------------- configs


def render_injector_conf(phase):
    lines = [
        "[GLOBAL]",
        "",
        "[nsp.probe.ftp]",
        "FTP /ftp_probe ftp_probe",
        "",
        "[nsp.probe.sftp]",
        "FTP /sftp_probe sftp_probe",
        "",
        "[nsp.probe.iso]",
        "SANDBOX ON",
        "",
        "[nsp.probe.plain]",
        "HIDE /nsp_verify/plain_noop",
        "",
        "[nsp.probe.hide]",
        "HIDE /nsp_verify/hide_noop",
    ]
    if phase == "B":
        # 必须落在 [nsp.probe.hide] 段内：追加到列表末尾会漂到后面的段里，
        # 让 hide 探针拿不到 HIDE 规则（实测阶段 B 全部断言失败）。
        lines.append("HIDE /nsp_verify/hide")
    lines += [
        "",
        # 竞态探针：a 族写 Download（SANDBOX ON ⇒ 挂载后落本应用沙盒），
        # b 族写 /nsp_race_b（HIDE ⇒ 挂载后必 ENOENT，未挂载则父目录真实存在）。
        "[nsp.probe.race]",
        "SANDBOX ON",
        "HIDE /nsp_race_b",
    ]
    lines.append("")
    return "\n".join(lines)


def render_module_conf(ftp_port, sftp_port, sftp_root):
    return (
        "[ftp_probe]\n"
        "host = 127.0.0.1\n"
        "port = %d\n"
        "user = anonymous\n"
        "password =\n"
        "remote_dir = /upload\n"
        "\n"
        "[sftp_probe]\n"
        "proto = sftp\n"
        "host = 127.0.0.1\n"
        "port = %d\n"
        "user = %s\n"
        "key_file = %s/id_rsa\n"
        "known_hosts = %s/known_hosts\n"
        "host_key_check = on\n"
        "remote_dir = %s\n"
        % (ftp_port, sftp_port, getpass.getuser(), CFG, CFG, sftp_root)
    )


# ------------------------------------------------------------------- probes


def parse_probe_log(text):
    events = []
    for line in text.splitlines():
        idx = line.find("NSP_PROBE:")
        if idx < 0:
            continue
        payload = line[idx + len("NSP_PROBE:"):].strip()
        kv = {}
        for part in payload.split("|"):
            if "=" in part:
                k, v = part.split("=", 1)
                kv[k.strip()] = v.strip()
        if kv.get("case"):
            events.append(kv)
    return events


def events_for(events, case):
    return [e for e in events if e.get("case") == case]


def step_ok(events, case, step):
    for e in events_for(events, case):
        if e.get("step") == step and e.get("ok") == "1":
            return True
    return False


class Checker:
    def __init__(self, quiet=False):
        self.pass_n = 0
        self.fail_n = 0
        self.failures = []
        self.quiet = quiet

    def check(self, name, cond, detail=""):
        if cond:
            self.pass_n += 1
            if not self.quiet:
                print("  ✅ " + name)
        else:
            self.fail_n += 1
            self.failures.append((name, detail))
            if not self.quiet:
                print("  ❌ %s%s" % (name, (": " + detail) if detail else ""))


# --------------------------------------------------------------------- main


def preflight(adb, checker):
    adb.raw("get-state")
    api = int(adb.shell("getprop ro.build.version.sdk").stdout.strip() or 0)
    checker.check("设备 API >= 31（当前 %d）" % api, api >= 31)
    adb.push(DEV_SCRIPT, DEV_SCRIPT_REMOTE)
    out = adb.sh_root("preflight").stdout
    facts = parse_kv(out)
    checker.check("root 可用（uid=0）", facts.get("uid") == "0", out[-400:])
    checker.check("模块已安装", facts.get("module") == "1")
    checker.check("Zygisk 64 位模块存在", facts.get("zygisk64") == "1")
    checker.check("Zygisk 32 位模块存在", facts.get("zygisk32") == "1")
    checker.check("/dev/fuse 存在", facts.get("dev_fuse") == "1")
    checker.check("生产 service.sh 存在", facts.get("prod_service") == "1")
    if facts.get("api"):
        checker.check("设备 API 与 getprop 一致", facts["api"] == str(api), facts["api"])
    return facts


def stage_files(adb, ftp, sftp, phase):
    adb.sh_root("prepare-dirs")
    bins = ["injector", "fuse_daemon", "log_monitor", "rule_server"]
    for b in bins:
        adb.push(DIST / "bin" / b, "%s/bin/%s" % (STAGE, b))
    adb.push(DIST / "bin" / "ftp_module.so", "%s/modules/ftp_module/ftp_module.so" % STAGE)
    adb.push(REPO / "src/modules/ftp/ftp_module.rules", "%s/modules/ftp_module/ftp_module.rules" % STAGE)
    if sftp is not None:
        adb.push(sftp.client_key, "%s/id_rsa" % STAGE)
        adb.push(Path(str(sftp.client_key) + ".pub"), "%s/id_rsa.pub" % STAGE)
        adb.push(sftp.known_hosts, "%s/known_hosts" % STAGE)
    tmp = Path(tempfile.mkdtemp(prefix="nsp_cfg."))
    try:
        inj = tmp / "injector.conf"
        inj.write_text(render_injector_conf(phase))
        adb.push(inj, "%s/injector.conf" % STAGE)
        mod = tmp / "ftp_module.conf"
        mod.write_text(render_module_conf(ftp.port, sftp.port, str(sftp.upload)))
        adb.push(mod, "%s/modules/ftp_module/ftp_module.conf" % STAGE)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    adb.sh_root("prepare")


def push_config(adb, phase):
    tmp = Path(tempfile.mkdtemp(prefix="nsp_cfg."))
    try:
        inj = tmp / "injector.conf"
        inj.write_text(render_injector_conf(phase))
        adb.push(inj, "%s/injector.conf" % STAGE)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    adb.sh_root("reload-config")


def wait_done(adb, case, timeout):
    """轮询 logcat 直到探针发出 done，返回最后一份日志。"""
    logs = ""
    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(0.5)
        logs = adb.logcat_dump()
        if any(e.get("case") == case and e.get("step") == "done"
               for e in parse_probe_log(logs)):
            return logs, True
    return logs, False


def launch_probe(adb, case, wait=3.0, logdir=None, tag="", timeout=25.0, retries=1):
    """拉起探针并等 done；未收尾则重试一次。

    屏幕休眠会让进程被系统冻结（isFrozen=true），探针停在中途既不发日志也不退出。
    设备脚本的 launch 已先唤醒解锁，这里再兜一层重试，避免把系统调度误判成模块缺陷。
    """
    logs = ""
    out = None
    for attempt in range(retries + 1):
        adb.logcat_clear()
        out = adb.sh_root("launch", pkg(case)).stdout
        logs, done = wait_done(adb, case, timeout)
        if done:
            break
        if attempt < retries:
            print("  ⚠ %s 未在 %.0fs 内收尾（进程可能被冻结），重试一次" % (pkg(case), timeout))
    if logdir is not None:
        try:
            (logdir / ("%s%s.log" % (tag, case))).write_text(logs)
        except OSError:
            pass
    return out, logs


def device_file(adb, path):
    out = adb.sh_root("check-file", path).stdout
    m = re.search(r"EXISTS=(\d+)\s+SIZE=(\S+)", out)
    if not m:
        return False, None
    return m.group(1) == "1", m.group(2)


def main():
    ap = argparse.ArgumentParser(description="Fuse-Proxy 设备端全链路验证（v1 + 隔离配置）")
    ap.add_argument("--serial", default=os.environ.get("ANDROID_SERIAL"), help="adb 序列号")
    ap.add_argument("--skip-build", action="store_true", help="复用 device-verify/dist 已有产物")
    ap.add_argument("--keep", action="store_true", help="保留临时目录与设备侧验证目录（排障用）")
    ap.add_argument("--keep-apks", action="store_true", help="验证后不卸载探针 APK")
    ap.add_argument("--dry-run", action="store_true", help="只打印计划与配置，不接触设备")
    ap.add_argument("--self-test", action="store_true", help="离线自检（配置渲染/日志解析/断言）")
    ap.add_argument("--ftp-port", type=int, default=2121)
    ap.add_argument("--sftp-port", type=int, default=2222)
    ap.add_argument("--pasv-base", type=int, default=30200)
    ap.add_argument("--wait", type=float, default=3.0, help="每次启动探针后等待秒数")
    ap.add_argument("--strict-race", action="store_true",
                    help="竞态探针的「就绪前侧漏」计为失败（默认只告警：v1 已知覆盖窗口）")
    args = ap.parse_args()

    if args.self_test:
        return self_test()
    if args.dry_run:
        print("=== injector.conf (phase A) ===")
        print(render_injector_conf("A"))
        print("=== injector.conf (phase B) ===")
        print(render_injector_conf("B"))
        print("=== ftp_module.conf ===")
        print(render_module_conf(args.ftp_port, args.sftp_port, "<sftp_upload_dir>"))
        print("=== 计划 ===")
        print("构建: device-verify/build/build-verify-binaries.sh && device-verify/probes/build-probes.sh")
        print("设备脚本: %s -> %s" % (DEV_SCRIPT, DEV_SCRIPT_REMOTE))
        print("动作: prepare-dirs -> push -> prepare -> install APKs -> stop-prod -> start-verify")
        print("       launch ftp/sftp/iso/plain/hide -> race x%d（不等待就绪）" % RACE_ITERATIONS)
        print("       -> reload-config -> launch hide -> 断言 -> 清理")
        return 0

    if not ADB_SH.exists():
        print("缺少 %s" % ADB_SH, file=sys.stderr)
        return 77

    adb = Adb(args.serial)
    try:
        adb.raw("get-state")
    except VerifyError as e:
        print("跳过：未检测到可用设备（%s）" % str(e).splitlines()[0], file=sys.stderr)
        return 77

    if not args.skip_build:
        print("== 构建验证产物 ==")
        for script in (DV / "build" / "build-verify-binaries.sh", DV / "probes" / "build-probes.sh"):
            if not script.exists():
                print("缺少构建脚本 %s（先完成构建或加 --skip-build）" % script, file=sys.stderr)
                return 1
            run([str(script)])

    required = [DIST / "bin" / b for b in ("injector", "fuse_daemon", "log_monitor", "rule_server", "ftp_module.so")]
    required += [DIST / "apks" / ("nsp.probe.%s.apk" % c) for c in CASES + (RACE,)]
    missing = [str(p) for p in required if not p.exists()]
    if missing:
        print("缺少验证产物：\n  " + "\n  ".join(missing), file=sys.stderr)
        return 1

    for port in [args.ftp_port, args.sftp_port] + list(range(args.pasv_base, args.pasv_base + 10)):
        if not port_free(port):
            print("宿主端口 %d 已被占用（可用 --ftp-port/--sftp-port/--pasv-base 调整）" % port, file=sys.stderr)
            return 1

    base = Path(tempfile.mkdtemp(prefix="nsp_dev_verify."))
    pasv = list(range(args.pasv_base, args.pasv_base + 10))
    ftp = FtpServer(base, args.ftp_port, pasv)
    sftp = SftpServer(base, args.sftp_port, getpass.getuser())
    checker = Checker()
    prepared = False
    prod_stop_attempted = False
    verify_started = False
    apks_installed = []
    reverses = []
    races = []
    awake = {}
    facts = {}
    events = []
    try:
        print("== 前置检查 ==")
        facts = preflight(adb, checker)
        if checker.fail_n:
            raise VerifyError("前置检查未通过")

        print("== 启动宿主隔离服务器 ==")
        ftp.start()
        sftp.start()
        print("  FTP  127.0.0.1:%d (root=%s)" % (ftp.port, ftp.root))
        print("  SFTP 127.0.0.1:%d (root=%s)" % (sftp.port, sftp.root))

        print("== adb reverse ==")
        for port in [ftp.port, sftp.port] + pasv:
            adb.reverse_add(port)
            reverses.append(port)

        print("== 设备准备（隔离配置根 %s）==" % CFG)
        stage_files(adb, ftp, sftp, "A")
        adb.sh_root("clean-fixtures")
        adb.sh_root("make-hide-fixture")
        prepared = True
        for case in CASES + (RACE,):
            apk = DIST / "apks" / ("nsp.probe.%s.apk" % case)
            adb.uninstall(pkg(case))
            adb.install(apk)
            adb.sh_root("prepare-app-dirs", pkg(case))
            apks_installed.append(pkg(case))

        print("== 保持唤醒（避免探针进程被系统冻结）==")
        awake = {
            "timeout": adb.shell("settings get system screen_off_timeout").stdout.strip(),
            "stayon": adb.shell("settings get global stay_on_while_plugged_in").stdout.strip(),
        }
        adb.sh_root("keep-awake", "1800000", "7")
        print("  原 screen_off_timeout=%s stay_on_while_plugged_in=%s"
              % (awake["timeout"], awake["stayon"]))

        print("== 停生产服务 / 启验证实例（v1）==")
        prod_stop_attempted = True
        adb.sh_root("stop-prod")
        adb.sh_root("start-verify")
        verify_started = True

        logdir = base / "logs"
        logdir.mkdir(parents=True, exist_ok=True)
        phase_a_events = []
        print("== 阶段 A：拉起探针 ==")
        for case in CASES:
            out, logs = launch_probe(adb, case, args.wait, logdir, "A-")
            phase_a_events.extend(parse_probe_log(logs))
            print("  - %s" % pkg(case))

        print("== 竞态窗口：不等待就绪的立即写入（%d 轮冷启动）==" % RACE_ITERATIONS)
        races = []
        for n in range(RACE_ITERATIONS):
            logs = ""
            for attempt in range(2):
                adb.sh_root("force-stop", pkg(RACE))
                adb.sh_root("race-fixture", pkg(RACE))
                adb.logcat_clear()
                adb.sh_root("launch", pkg(RACE))
                logs, done = wait_done(adb, RACE, 30.0)
                if done:
                    break
                if attempt == 0:
                    print("  ⚠ race#%d 未收尾（进程可能被冻结），重试一次" % (n + 1))
            scan = parse_kv(adb.sh_root("race-scan", pkg(RACE)).stdout)
            races.append({"events": parse_probe_log(logs), "scan": scan})
            try:
                (logdir / ("race-%d.log" % (n + 1))).write_text(logs)
            except OSError:
                pass
            print("  - race#%d 采样完成" % (n + 1))

        print("== 阶段 B：换配置重启验证实例后重跑 hide 探针 ==")
        for case in CASES:
            adb.sh_root("force-stop", pkg(case))
        adb.sh_root("stop-verify")
        push_config(adb, "B")
        adb.sh_root("start-verify")
        out, logs = launch_probe(adb, "hide", args.wait, logdir, "B-")
        phase_b_events = parse_probe_log(logs)
        events = phase_a_events + phase_b_events

        try:
            (logdir / "device-dump.txt").write_text(adb.sh_root("dump-logs", check=False).stdout)
        except Exception:
            pass

        print("== 断言 ==")
        assert_all(adb, checker, phase_a_events, phase_b_events, ftp, sftp)
        assert_race(checker, races, strict_leak=args.strict_race)
        if races:
            print("== 竞态测量小结（v1 补挂载 vs 应用首写）==")
            for n, r in enumerate(races):
                st = race_stats(r["events"], r["scan"])
                pre, post = st["pre"], st["post"]
                leaked = sorted(st["real_dl"] & set(str(x["i"]) for x in pre), key=int)
                outcomes = {}
                for x in pre:
                    outcomes[x["a"]] = outcomes.get(x["a"], 0) + 1
                print("  race#%d 首次就绪 %sms | %s | 就绪前 %d 次 %s"
                      " | 侧漏 %d 次%s | 就绪后 %d 次全部落沙盒"
                      % (n + 1, st["first_fuse_ms"], race_window_text(pre), len(pre),
                         outcomes or "-", len(leaked),
                         (" %s" % leaked) if leaked else "", len(post)))
        if checker.fail_n:
            print("== 探针事件明细（排障）==")
            for e in events:
                print("  %s" % "|".join("%s=%s" % (k, v) for k, v in e.items()))
    except VerifyError as e:
        print("验证中止：%s" % e, file=sys.stderr)
        checker.check("流程无异常中止", False, str(e)[:300])
    finally:
        print("== 清理与恢复 ==")
        if prod_stop_attempted:
            if verify_started:
                adb.sh_root("stop-verify", check=False)
            adb.sh_root("cleanup", check=False)
            adb.sh_root("start-prod", check=False)

        # 生产配置零改动 + 服务恢复断言（必须早于设备脚本删除）
        try:
            after = parse_kv(adb.sh_root("preflight", check=False).stdout)
            before_sha = facts.get("prod_cfg_sha") or "-"
            after_sha = after.get("prod_cfg_sha") or "-"
            checker.check("生产配置未被修改（sha256 前后一致）", before_sha == after_sha,
                          "%s -> %s" % (before_sha, after_sha))
            if prod_stop_attempted:
                checker.check("生产服务已恢复（injector 运行中）", bool(after.get("prod_injector")))
        except Exception as e:  # 清理阶段不因断言异常再次抛出
            checker.check("生产服务恢复检查", False, str(e)[:200])

        if awake.get("timeout") and awake.get("stayon"):
            adb.sh_root("restore-awake", awake["timeout"], awake["stayon"], check=False)

        if not args.keep:
            adb.shell("rm -f %s" % DEV_SCRIPT_REMOTE, check=False)
        for port in reverses:
            adb.reverse_del(port)
        ftp.stop()
        sftp.stop()
        if not args.keep_apks:
            for p in apks_installed:
                adb.uninstall(p)
        if not args.keep:
            shutil.rmtree(base, ignore_errors=True)
        else:
            print("保留宿主临时目录：%s" % base)

    print()
    print("通过 %d，失败 %d" % (checker.pass_n, checker.fail_n))
    if checker.failures:
        for name, detail in checker.failures:
            print("  - %s%s" % (name, (": " + detail) if detail else ""))
        return 1
    return 0


def wait_file(path, timeout=10.0):
    end = time.time() + timeout
    while time.time() < end:
        if path.is_file():
            return True
        time.sleep(0.2)
    return False


def ready_ms(events, case):
    for e in events_for(events, case):
        if e.get("step") == "ready":
            if e.get("ok") != "1":
                return None
            m = re.search(r"ms=(\d+)", e.get("detail") or "")
            return int(m.group(1)) if m else -1
    return None


def assert_all(adb, checker, phase_a, phase_b, ftp, sftp):
    # ---- 注入就绪：v1 在 ColorOS 上由注入器在进程启动后重试完成，探针等待 FUSE 视图出现
    for case in CASES:
        ms = ready_ms(phase_a, case)
        checker.check("%s 探针 FUSE 视图就绪" % case, ms is not None,
                      "未看到 ready 行（注入未完成？）" if ms is None else "ms=%s" % ms)
        if ms is not None and ms >= 0:
            checker.check("%s 注入就绪耗时 <= 12000ms" % case, ms <= 12000, "实际 %dms" % ms)
        checker.check("%s 探针正常收尾" % case, step_ok(phase_a, case, "done"))
    checker.check("hide(阶段B) FUSE 视图就绪", ready_ms(phase_b, "hide") is not None)

    # ---- ftp / sftp：后端落盘 + 真实存储零侧漏
    for case in ("ftp", "sftp"):
        for step in ("write", "read", "list", "canary"):
            checker.check("%s 探针 %s 成功" % (case, step), step_ok(phase_a, case, step))
        remote = ftp.upload / ("probe_%s.txt" % case) if case == "ftp" else sftp.upload / ("probe_%s.txt" % case)
        ok = wait_file(remote)
        checker.check("%s 文件已落到宿主后端" % case, ok, str(remote))
        if ok:
            body = remote.read_text(errors="replace")
            checker.check("%s 后端内容正确" % case, body.startswith("NSP_PROBE:nsp.probe.%s:" % case), body[:120])
        exists, size = device_file(adb, "%s/%s_probe/probe_%s.txt" % (REAL_ROOT, case, case))
        checker.check("%s 未侧漏到真实存储" % case, not exists, "exists=%s size=%s" % (exists, size))

    # ---- iso：SANDBOX 隔离（真实共享目录零写入 + 文件落沙盒）
    for step in ("download", "pictures"):
        checker.check("iso 探针 %s 成功" % step, step_ok(phase_a, "iso", step))
    uid_out = adb.sh_root("get-uid", pkg("iso")).stdout
    uid = parse_kv(uid_out).get("UID")
    checker.check("取得 iso 探针 uid", bool(uid), uid_out.strip())
    exists, size = device_file(adb, REAL_ROOT + "/Download/nsp_probe_sandbox.txt")
    checker.check("iso 未写入真实 Download", not exists, "exists=%s size=%s" % (exists, size))
    exists, size = device_file(adb, REAL_ROOT + "/Pictures/nsp_probe_sandbox.jpg")
    checker.check("iso 未写入真实 Pictures", not exists, "exists=%s size=%s" % (exists, size))
    if uid:
        sb = "%s/Android/data/%s/sandbox/Download/nsp_probe_sandbox.txt" % (REAL_ROOT, pkg("iso"))
        exists, size = device_file(adb, sb)
        checker.check("iso 文件落在沙盒 Download", exists, sb)
        if exists:
            body = adb.sh_root("read-file", sb, check=False).stdout
            checker.check("iso 沙盒 Download 内容正确", body.startswith("NSP_PROBE_ISO_DOWNLOAD:"), body[:120])
        sb2 = "%s/Android/data/%s/sandbox/Pictures/nsp_probe_sandbox.jpg" % (REAL_ROOT, pkg("iso"))
        exists2, size2 = device_file(adb, sb2)
        checker.check("iso 文件落在沙盒 Pictures", exists2, sb2)

    # ---- plain：对照组（普通外部目录读写不受影响）
    for step in ("write", "read"):
        checker.check("plain 探针 %s 成功" % step, step_ok(phase_a, "plain", step))
    exists, size = device_file(adb, REAL_ROOT + "/Android/data/%s/files/plain.txt" % pkg("plain"))
    checker.check("plain 文件在真实外部目录可读", exists, "exists=%s size=%s" % (exists, size))

    # ---- hide：两阶段（阶段 A 夹具可见；阶段 B 热重载 HIDE 后 stat/写均 ENOENT）
    checker.check("hide 阶段 A 夹具可见且内容正确", step_ok(phase_a, "hide", "phase_a"))
    checker.check("hide 阶段 B stat 返回 ENOENT", step_ok(phase_b, "hide", "phase_b"))
    checker.check("hide 阶段 B 写入返回 ENOENT", step_ok(phase_b, "hide", "write_denied"))
    exists, size = device_file(adb, REAL_ROOT + "/nsp_verify/hide/secret.txt")
    checker.check("hide 夹具真实文件仍在", exists, "exists=%s size=%s" % (exists, size))
    lists_a = [e for e in events_for(phase_a, "hide") if e.get("step") == "list"]
    entries_a = (lists_a[0].get("detail") or "") if lists_a else ""
    checker.check("hide 阶段 A 列举含 hide 目录", "hide" in entries_a.split(","), entries_a)
    lists_b = [e for e in events_for(phase_b, "hide") if e.get("step") == "list"]
    entries_b = (lists_b[0].get("detail") or "") if lists_b else ""
    checker.check("hide 阶段 B 列举不含 hide 目录", "hide" not in entries_b.split(","), entries_b)


def race_stats(events, scan):
    """把一轮 race 探针的 attempt 事件 + 落点扫描整理成可断言的统计。"""
    attempts = []
    for e in events_for(events, RACE):
        if e.get("step") != "attempt":
            continue
        d = e.get("detail") or ""
        mi = re.search(r"(?:^|\s)i=(\d+)", d)
        mm = re.search(r"(?:^|\s)ms=(\d+)", d)
        mf = re.search(r"(?:^|\s)fuse=([01])", d)
        ma = re.search(r"(?:^|\s)a=(\S+)", d)
        mb = re.search(r"(?:^|\s)b=(\S+)", d)
        if not (mi and mm and mf and ma and mb):
            continue
        attempts.append({
            "i": int(mi.group(1)),
            "ms": int(mm.group(1)),
            "fuse": int(mf.group(1)),
            "a": ma.group(1),
            "b": mb.group(1),
        })

    def ids(key):
        raw = (scan.get(key) or "").strip()
        if raw in ("", "-"):
            return set()
        return set(x for x in raw.split(",") if x)

    first_fuse = None
    for e in events_for(events, RACE):
        if e.get("step") == "summary":
            m = re.search(r"first_fuse_ms=(-?\d+)", e.get("detail") or "")
            if m:
                first_fuse = int(m.group(1))
    return {
        "attempts": attempts,
        "pre": [x for x in attempts if x["fuse"] == 0],
        "post": [x for x in attempts if x["fuse"] == 1],
        "real_dl": ids("REAL_DL"),
        "sb_dl": ids("SB_DL"),
        "real_hid": ids("REAL_HID"),
        "first_fuse_ms": first_fuse,
    }


def race_window_text(pre):
    """未覆盖窗口的可读描述：没有就绪前样本 = 首写前已就绪（v1 抢到了）。"""
    if not pre:
        return "未覆盖窗口=无（首写前已就绪）"
    return "未覆盖窗口 ms=[0,%d]" % max(x["ms"] for x in pre)


def assert_race(checker, races, verbose=True, strict_leak=True):
    """竞态探针断言：就绪后的写入必须被 FUSE 接管；就绪前的写入不得落沙盒/侧漏。

    就绪前（v1 尚未补挂载）的写入本来就落在真实视图，这是被测事实，故只断言
    「不得产生侧漏」与「不得被误判成 FUSE 结果」；就绪后才要求 100% 被接管。
    """
    for n, r in enumerate(races):
        tag = "race#%d" % (n + 1)
        st = race_stats(r["events"], r["scan"])
        att = st["attempts"]
        checker.check("%s 探针正常收尾" % tag, step_ok(r["events"], RACE, "done"))
        checker.check("%s 有采样尝试" % tag, len(att) > 0, "attempts=%d" % len(att))
        if not att:
            continue
        pre, post = st["pre"], st["post"]
        real_dl, sb_dl, real_hid = st["real_dl"], st["sb_dl"], st["real_hid"]
        post_ids = set(str(x["i"]) for x in post)
        pre_ids = set(str(x["i"]) for x in pre)

        checker.check("%s 采样到就绪后的写入" % tag, bool(post),
                      "first_fuse_ms=%s attempts=%d" % (st["first_fuse_ms"], len(att)))
        if post:
            checker.check("%s 就绪后写入全部成功" % tag,
                          all(x["a"] == "ok" for x in post),
                          "post=%s" % [(x["i"], x["a"]) for x in post])
            checker.check("%s 就绪后写入全部落沙盒" % tag, post_ids <= sb_dl,
                          "sb=%s post=%s" % (sorted(sb_dl, key=int), sorted(post_ids, key=int)))
            checker.check("%s 就绪后真实 Download 无文件" % tag, not (real_dl & post_ids),
                          "real_dl=%s" % sorted(real_dl, key=int))
            checker.check("%s 就绪后 HIDE 生效（b=ENOENT）" % tag,
                          all(x["b"] == "ENOENT" for x in post),
                          "post=%s" % [(x["i"], x["b"]) for x in post])

        checker.check("%s 就绪前写入未落沙盒" % tag, not (sb_dl & pre_ids),
                      "pre=%s sb=%s" % (sorted(pre_ids, key=int), sorted(sb_dl, key=int)))
        checker.check("%s 就绪前 HIDE 目录未被写入" % tag, not (real_hid & pre_ids),
                      "real_hid=%s" % sorted(real_hid, key=int))
        leaked = sorted(real_dl & pre_ids, key=int)
        if strict_leak:
            checker.check("%s 无侧漏（就绪前写入未落真实 Download）" % tag, not leaked,
                          "泄漏样本=%s" % leaked)
        elif leaked:
            # v1 在补挂载完成前的写入本来就没被接管：默认只告警（--strict-race 才计失败）。
            print("  ⚠ %s 就绪前写入侧漏 %d 次（样本=%s）——默认只告警，--strict-race 计失败"
                  % (tag, len(leaked), leaked))
        flags = [x["fuse"] for x in att]
        checker.check("%s fuse 标志单调（就绪后不回退）" % tag, flags == sorted(flags),
                      "flags=%s" % flags)

        if verbose:
            outcomes = {}
            for x in pre:
                outcomes[x["a"]] = outcomes.get(x["a"], 0) + 1
            print("  ℹ %s 首次就绪 ms=%s；采样 %d（就绪前 %d / 就绪后 %d）；%s；"
                  "就绪前结果=%s；真实Download=%s 沙盒=%s 真实HIDE=%s"
                  % (tag, st["first_fuse_ms"], len(att), len(pre), len(post),
                     race_window_text(pre), outcomes or "-", sorted(real_dl, key=int),
                     sorted(sb_dl, key=int), sorted(real_hid, key=int)))


def self_test():
    ok = True

    def ck(name, cond, detail=""):
        nonlocal ok
        print(("  ✅ " if cond else "  ❌ ") + name + ((": " + detail) if (detail and not cond) else ""))
        ok = ok and cond

    conf_a = render_injector_conf("A")
    conf_b = render_injector_conf("B")
    ck("phase A 不含 HIDE canary", "canary.txt" not in conf_a)
    ck("phase B 含 HIDE 夹具规则", "HIDE /nsp_verify/hide" in conf_b)
    ck("五个探针段齐全", all(("[nsp.probe.%s]" % c) in conf_a for c in CASES))
    ck("竞态探针段含 SANDBOX + HIDE",
       "[nsp.probe.race]" in conf_a and "SANDBOX ON" in conf_a and "HIDE /nsp_race_b" in conf_a)
    ck("FTP 规则存在（前缀须等于模块段名）", "FTP /ftp_probe ftp_probe" in conf_a)
    ck("SANDBOX 规则存在", "SANDBOX ON" in conf_a)
    mod = render_module_conf(2121, 2222, "/tmp/x/upload")
    ck("模块配置含 ftp/sftp 段", "[ftp_probe]" in mod and "[sftp_probe]" in mod)
    ck("模块配置 proto=sftp", "proto = sftp" in mod)

    log = (
        "10-24 00:00:01.000  1234  1234 I NSP_PROBE: case=ftp|step=write|ok=1|detail=/x\n"
        "10-24 00:00:01.001  1234  1234 I NSP_PROBE: case=ftp|step=read|ok=1\n"
        "10-24 00:00:01.002  1234  1234 I NSP_PROBE: case=hide|step=phase_b|ok=1|detail=enoent\n"
        "garbage line\n"
    )
    ev = parse_probe_log(log)
    ck("日志解析条数", len(ev) == 3, str(len(ev)))
    ck("step_ok 命中", step_ok(ev, "ftp", "write"))
    ck("step_ok 未命中错误 ok", not step_ok(ev, "ftp", "list"))
    ck("hide phase_b 识别", step_ok(ev, "hide", "phase_b"))

    checker = Checker()
    import contextlib
    import io
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        checker.check("合成通过", True)
        checker.check("合成失败", False, "x")
    ck("Checker 计数", checker.pass_n == 1 and checker.fail_n == 1)
    ck("Checker 失败明细", checker.failures == [("合成失败", "x")])

    race_log = (
        "I NSP_PROBE: case=race|step=attempt|ok=1|detail=i=0 ms=5 fuse=0 a=EACCES b=EACCES\n"
        "I NSP_PROBE: case=race|step=attempt|ok=1|detail=i=1 ms=120 fuse=1 a=ok b=ENOENT\n"
        "I NSP_PROBE: case=race|step=attempt|ok=1|detail=i=2 ms=140 fuse=1 a=ok b=ENOENT\n"
        "I NSP_PROBE: case=race|step=summary|ok=1|detail=attempts=3 first_fuse_ms=120\n"
        "I NSP_PROBE: case=race|step=done|ok=1|detail=steps=1\n"
    )
    race_ev = parse_probe_log(race_log)
    st = race_stats(race_ev, {"REAL_DL": "-", "SB_DL": "1,2", "REAL_HID": "-"})
    ck("race attempt 解析", len(st["attempts"]) == 3 and st["first_fuse_ms"] == 120,
       "attempts=%d first=%s" % (len(st["attempts"]), st["first_fuse_ms"]))
    ck("race 就绪前/后分组", len(st["pre"]) == 1 and len(st["post"]) == 2,
       "pre=%d post=%d" % (len(st["pre"]), len(st["post"])))

    clean = Checker(quiet=True)
    assert_race(clean, [{"events": race_ev,
                         "scan": {"REAL_DL": "-", "SB_DL": "1,2", "REAL_HID": "-"}}],
                verbose=False)
    ck("race 干净样本零失败", clean.fail_n == 0, "fail_n=%d" % clean.fail_n)

    leaky = Checker(quiet=True)
    assert_race(leaky, [{"events": race_ev,
                         "scan": {"REAL_DL": "0", "SB_DL": "1,2", "REAL_HID": "-"}}],
                verbose=False)
    ck("race 侧漏样本被判失败", leaky.fail_n >= 1, "fail_n=%d" % leaky.fail_n)

    # 反向判别：把就绪前的样本谎报成落沙盒，必须被「就绪前写入未落沙盒」抓住
    fake = Checker(quiet=True)
    assert_race(fake, [{"events": race_ev,
                        "scan": {"REAL_DL": "-", "SB_DL": "0,1,2", "REAL_HID": "-"}}],
                verbose=False)
    ck("race 就绪前落沙盒被判失败", fake.fail_n >= 1, "fail_n=%d" % fake.fail_n)

    # 默认（非 strict）：同一侧漏样本只告警、不计失败
    lax = Checker(quiet=True)
    assert_race(lax, [{"events": race_ev,
                       "scan": {"REAL_DL": "0", "SB_DL": "1,2", "REAL_HID": "-"}}],
                verbose=False, strict_leak=False)
    ck("race 非 strict 下侧漏不计失败", lax.fail_n == 0, "fail_n=%d" % lax.fail_n)

    print("自检%s" % ("通过" if ok else "失败"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
