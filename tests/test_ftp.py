#!/usr/bin/env python3
"""FTP 模块端到端测试 — ftp_module(FTP-FUSE) + 内建引擎变量 + REDIRECT。

链路：
  ftp.conf([云盘]) → ftp_module 挂载 storage/0/云盘（FTP-FUSE）
  injector.conf: FTP_云盘=云盘; REDIRECT /云盘 $FTP_云盘
  fuse_daemon：/0/云盘/xxx → storage/0/云盘/xxx → FTP 服务器（vsftpd 匿名）

覆盖：列目录 / 读现有文件 / 创建写入 / 读回 / mkdir / rename / unlink / rmdir，
并直接核对 vsftpd 匿名根（/home/bdy/ftp）验证 FTP 服务器实际变化。
V5 分页回归：700 文件大目录一次列全（旧 512 整批上限会静默丢尾）。
"""
import subprocess, os, sys, time, shutil, errno, ctypes
from pathlib import Path

MNT      = "/tmp/fuse_ftp_test/mnt"
STORAGE  = "/tmp/fuse_ftp_test/storage"
FTP_BASE = "/tmp/fuse_ftp_test/storage/0"     # ftp_module --mount-base
FTP_ROOT = "/home/bdy/ftp"                     # vsftpd anon_root（chroot 根，须对 ftp 用户不可写）
FTP_UPLOAD = f"{FTP_ROOT}/upload"              # 匿名可写区（777），ftp.conf remote_dir=/upload
MODDIR   = "/tmp/fuse_ftp_test/modules"
CONF_FTP = "/tmp/Namespace-Proxy/ftp.conf"   # 与规则配置同目录（ftp_module init 经 get_rules_path 推导）
CONF     = "/tmp/Namespace-Proxy/injector.conf"
SERVER   = "云盘"
REPO     = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DAEMON   = os.environ.get("FUSE_DAEMON") or f"{REPO}/build_gnu/fuse_daemon"
FTP_MOD_SO = os.environ.get("FTP_MODULE_SO") or f"{REPO}/build_gnu/ftp_module.so"

PASS = 0; FAIL = 0; ERRS = []
def ok(d): global PASS; PASS += 1; print(f"  ✅ {d}")
def fail(d, dt=""): global FAIL; FAIL += 1; print(f"  ❌ {d}: {dt}"); ERRS.append((d, dt))

def setup():
    shutil.rmtree("/tmp/fuse_ftp_test", ignore_errors=True)
    subprocess.run(["fusermount3", "-u", MNT], capture_output=True)
    os.makedirs(f"{STORAGE}/0", exist_ok=True)
    os.makedirs(MNT, exist_ok=True)
    os.makedirs("/tmp/Namespace-Proxy", exist_ok=True)
    os.makedirs(f"{MODDIR}/ftp_module", exist_ok=True)
    if os.path.exists(FTP_MOD_SO):
        shutil.copy(FTP_MOD_SO, f"{MODDIR}/ftp_module/ftp_module.so")
    else:
        print("  ⚠ ftp_module.so 未找到")
    # vsftpd 匿名 chroot 到 anon_root：根目录须对 ftp 用户不可写（否则
    # "refusing to run with writable root inside chroot()" 拒绝服务）；
    # 可写区用其下的 upload 子目录（777），ftp.conf 的 remote_dir=/upload
    if os.path.isdir(FTP_ROOT):
        os.chmod(FTP_ROOT, 0o755)
    os.makedirs(FTP_UPLOAD, exist_ok=True)
    os.chmod(FTP_UPLOAD, 0o777)
    with open(CONF_FTP, "w") as fh:
        fh.write(f"""
[{SERVER}]
host = 127.0.0.1
port = 21
user = anonymous
password =
remote_dir = /upload
""".strip())

def wait_ftp_ready(timeout=10.0):
    """等待 fuse_daemon 加载 ftp_module.so：/0/云盘 经框架后端分派可访问
       （后端方式无独立挂载点，须经 FUSE 虚拟路径探测）"""
    probe = Path(MNT) / "0" / SERVER
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if probe.is_dir(): return True
        except Exception:
            pass
        time.sleep(0.3)
    return False

def start_fuse():
    # FTP 规则：`FTP <虚拟前缀> <段名>` 写在 [GLOBAL]（全局生效）。
    # /0/云盘 剥离 /0/ 后命中规则 → 框架分派给 ftp_module（段名=SERVER）
    # HIDE 规则供 A4 用例：后端列举必须与本地列举同一可见性过滤（旧实现后端
    # 零过滤 → HIDE 条目在列表里可见而 stat ENOENT，既是反向形态也是名字泄露）
    with open(CONF, "w") as fh:
        fh.write(f"[GLOBAL]\nFTP /{SERVER} {SERVER}\nHIDE /{SERVER}/nsp_hide_secret.txt\n")
    p = subprocess.Popen([DAEMON, "--root="+STORAGE, "--rules="+CONF,
                          "--modules-dir="+MODDIR, "-f", MNT, "info"],
                         stdout=open("/tmp/fuse_ftp_test/fuse.log", "w"),
                         stderr=subprocess.STDOUT)
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            if os.listdir(MNT): return p
        except: pass
        if p.poll() is not None: return None
        time.sleep(0.3)
    return p

def stop_fuse(p):
    if p:
        p.terminate()
        try: p.wait(3)
        except: p.kill()
    subprocess.run(["fusermount3", "-u", MNT], capture_output=True)

def _renameat2(old, new, flags):
    """经 libc 调 renameat2（glibc ≥2.28）。成功返回 0；失败抛 OSError；
    libc 无该符号时返回 None（调用方跳过）。"""
    try:
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        fn = libc.renameat2
    except (OSError, AttributeError):
        return None
    fn.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    fn.restype = ctypes.c_int
    r = fn(-100, os.fsencode(old), -100, os.fsencode(new), ctypes.c_uint(flags))
    if r != 0:
        e = ctypes.get_errno()
        raise OSError(e, os.strerror(e))
    return 0


def wait_ftp_content(rel, want, timeout=6.0):
    """轮询等待 FTP 上传区文件内容（FUSE release 的 STOR 上传异步完成）"""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            p = Path(FTP_UPLOAD) / rel
            if p.exists() and p.read_text(errors="replace").strip() == want:
                return True
        except Exception:
            pass
        time.sleep(0.2)
    return False

def main():
    global PASS, FAIL
    print("前置：vsftpd 匿名服务（127.0.0.1:21）须已运行，匿名根 " + FTP_ROOT)
    setup()

    p = start_fuse()
    if not p:
        print("  ❌ fuse_daemon 启动失败"); sys.exit(1)
    print("  ✅ fuse_daemon 已挂载")

    # ftp_module.so 由 fuse_daemon 进程 dlopen 加载，注册后端前缀
    # （/tmp/fuse_ftp_test/storage/0/云盘）；路径经框架命中后端分派，
    # 不再存在独立 FUSE 挂载点
    if not wait_ftp_ready():
        stop_fuse(p)
        print(f"  ❌ FTP 后端未就绪: /0/{SERVER}（检查 ftp.conf / ftp_module.so / fuse.log）")
        sys.exit(1)
    print(f"  ✅ FTP 后端已注册（fuse_daemon 进程内）")

    # 预置一个已知文件到 FTP 根（供读取比对）
    orig = "compute_bench_origin.txt"
    (Path(FTP_UPLOAD)/orig).write_text("ftp-original-content")
    known_file = "compute_bench.cpp"
    # A4 探针：必须在**首次列举之前**落盘（LIST 有 TTL 缓存，事后新增要等
    # 空闲超时才可见）；名字用 nsp_ 前缀，收尾统一清扫
    a4_vis, a4_sec = "nsp_hide_visible.txt", "nsp_hide_secret.txt"
    (Path(FTP_UPLOAD)/a4_vis).write_text("VISIBLE")
    (Path(FTP_UPLOAD)/a4_sec).write_text("SECRET")

    m = Path(MNT)
    try:
        # 1. 列目录：/0/云盘/ 显示 FTP 根内容
        try:
            items = sorted(os.listdir(m/"0"/SERVER))
            print(f"  [列表] /0/云盘/ → {items[:6]}{'...' if len(items)>6 else ''}")
            ok("列目录（FTP 根内容可见）") if known_file in items or orig in items else fail("列目录", f"缺 {known_file}")
        except Exception as e: fail("列目录", str(e))

        # 1b. 多用户：/1/云盘、/2/云盘 剥离 user_id 后同样命中 FTP 段名
        try:
            items1 = sorted(os.listdir(m/"1"/SERVER))
            ok("多用户:user1(/1/云盘)列目录一致") if items1 == items else fail("多用户:user1列目录", f"{items1}")
            got1 = (m/"2"/SERVER/orig).read_text().strip()
            ok("多用户:user2(/2/云盘)读文件一致") if got1 == "ftp-original-content" else fail("多用户:user2读文件", f"got='{got1}'")
        except Exception as e: fail("多用户FTP命中", str(e))

        # 2. 读现有 FTP 文件
        try:
            got = (m/"0"/SERVER/orig).read_text().strip()
            ok("读取现有 FTP 文件") if got == "ftp-original-content" else fail("读文件", f"got='{got}'")
        except Exception as e: fail("读文件", str(e))

        # 3. 创建 + 写入 → FTP 根出现
        newf = "nsp_test_write.txt"
        try:
            (m/"0"/SERVER/newf).write_text("hello from fuse-ftp")
            ok("写入新文件（FTP 出现）") if (Path(FTP_UPLOAD)/newf).exists() else fail("写文件", "FTP 根未见")
            ok("内容正确") if wait_ftp_content(newf, "hello from fuse-ftp") else fail("写内容", "FTP 内容未同步")
        except Exception as e: fail("写文件", str(e))

        # 3b. FLUSH 之后继续写（dup + close 触发 FLUSH）→ 后续数据必须落远端
        #     FUSE 的 FLUSH 在每次 close(2) 触发（dup/fork 可多次），第一次 FLUSH
        #     之后存活的 fd 仍可写，那些数据必须由后续 FLUSH/RELEASE 续传。旧实现
        #     第二次 FLUSH 被 uploaded 早退挡掉，远端只留前半段（静默丢数据）
        dupf = "nsp_test_flush_then_write.txt"
        try:
            fd = os.open(str(m/"0"/SERVER/dupf), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
            try:
                os.write(fd, b"AAAA")
                fd2 = os.dup(fd)
                os.close(fd2)           # 触发 FLUSH：前半段落远端
                os.write(fd, b"BBBB")   # FLUSH 之后继续写
            finally:
                os.close(fd)            # 触发 FLUSH + RELEASE：后半段必须补传
            if wait_ftp_content(dupf, "AAAABBBB"):
                ok("FLUSH 后续写（dup/close）：远端内容完整")
            else:
                # 变量名不得用 p——p 是 main 里的 fuse_daemon 进程句柄，
                # 遮蔽后 finally 的 stop_fuse(p) 会炸在 PosixPath 上（掩盖真错误）
                fp = Path(FTP_UPLOAD) / dupf
                got = fp.read_text(errors="replace") if fp.exists() else "<文件不存在>"
                fail("FLUSH 后续写", f"远端={got!r}（期望 'AAAABBBB'）")
        except Exception as e: fail("FLUSH 后续写", str(e))

        # 3c. fsync 必须把数据交给后端（不得依赖 close/FLUSH 兜底）
        #     旧实现 vfs_fsync 对后端句柄直接返回 0，数据仍留在模块缓冲里——依赖
        #     fsync 持久化的调用方（SQLite synchronous=FULL、编辑器保存）会拿到
        #     「成功」而远端无数据。判别方式：write + fsync 之后、**close 之前**
        #     就核对远端内容已出现（旧实现此处必为「文件不存在」或空）。
        syncf = "nsp_test_fsync.txt"
        try:
            fd = os.open(str(m/"0"/SERVER/syncf), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
            try:
                os.write(fd, b"SYNCED-DATA")
                os.fsync(fd)                      # 关键：此刻数据应已落远端
                fp = Path(FTP_UPLOAD) / syncf     # 勿用 p（会遮蔽进程句柄）
                got = fp.read_text(errors="replace") if fp.exists() else "<文件不存在>"
                if got == "SYNCED-DATA":
                    ok("fsync 后远端已有数据（close 之前）")
                else:
                    fail("fsync 落远端", f"远端={got!r}（期望 'SYNCED-DATA'，close 之前）")
            finally:
                os.close(fd)
        except Exception as e: fail("fsync 落远端", str(e))

        # 3d. 写模式必须回灌远端已有内容（A8 判别）
        #     旧实现 open(写模式) 只 mkstemp 一个**空** tmp，从不下载远端内容，
        #     上传按 tmp 长度全量 STOR 覆盖——open(O_RDWR)+pwrite(尾部) 会把远端
        #     前段替换成 NUL 空洞，原内容全丢（SQLite 就地写 / 编辑器保存必现）。
        #     判别：远端预置非空文件 → O_RDWR 打开先 pread（应读到远端内容）→
        #     在尾部 pwrite → close → 远端**前段必须仍在**。探针名选套件不碰的。
        #     注意探针须 0666：匿名 ftp 用户要能覆盖/追加（bdy:0644 的文件对它只读，
        #     会把环境权限问题伪装成产品缺陷）。
        bf = "nsp_a8_backfill.txt"
        prefix = "REMOTE-PREFIX-DATA"
        try:
            bpath = Path(FTP_UPLOAD) / bf
            bpath.write_text(prefix)
            os.chmod(bpath, 0o666)
            fd = os.open(str(m/"0"/SERVER/bf), os.O_RDWR)
            try:
                got0 = os.pread(fd, len(prefix), 0).decode(errors="replace")
                if got0 == prefix:
                    ok("O_RDWR 打开后 pread 读到远端已有内容（回灌生效）")
                else:
                    fail("O_RDWR pread 远端内容", f"got={got0!r}（期望 {prefix!r}）")
                os.pwrite(fd, b"TAIL", len(prefix))
            finally:
                os.close(fd)
            if wait_ftp_content(bf, prefix + "TAIL"):
                ok("O_RDWR 尾部改写后远端前段仍在（不丢全文）")
            else:
                fp = Path(FTP_UPLOAD) / bf
                got = fp.read_text(errors="replace") if fp.exists() else "<文件不存在>"
                fail("O_RDWR 就地改写", f"远端={got!r}（期望 {prefix + 'TAIL'!r}，前段丢失即旧实现）")
        except Exception as e:
            fail("写模式回灌远端内容", str(e))
        finally:
            try:
                (Path(FTP_UPLOAD) / bf).unlink()
            except Exception:
                pass

        # 3e. 后端列举必须与本地列举同一可见性过滤（A4 判别）
        #     旧实现 vfs_readdir_backend 对后端条目**零 probe 过滤** → HIDE 的
        #     条目在列举里可见（名字泄露）而直接访问 ENOENT——正是
        #     architecture.md §4.4 明令修掉的「列表可见但打开 ENOENT」反向形态。
        try:
            items = os.listdir(m/"0"/SERVER)
            if a4_vis in items and a4_sec not in items:
                ok("后端列举过滤 HIDE 条目（可见项在、隐藏项不在）")
            else:
                fail("后端列举过滤 HIDE",
                     f"visible={a4_vis in items} secret={a4_sec in items}（旧实现后端不过滤）")
            try:
                (m/"0"/SERVER/a4_sec).stat()
                fail("HIDE 条目直接访问", "未报错（应 ENOENT）")
            except FileNotFoundError:
                ok("HIDE 条目直接访问 → ENOENT（与列举一致）")
        except Exception as e:
            fail("后端列举过滤 HIDE", str(e))

        # 3f. 点文件不得被丢弃（A15）：本机 vsftpd 默认 `force_dot_files=NO`，
        #     LIST 根本不回点条目，故端到端不可观测——A15 的判别性用例落在
        #     tests/test_ftp_truncate_list.py（直编后端 + 合成 LIST 正文）。
        # 4. 读回（经 fuse）
        try:
            got = (m/"0"/SERVER/newf).read_text().strip()
            ok("读回写入内容") if got == "hello from fuse-ftp" else fail("读回", f"got='{got}'")
        except Exception as e: fail("读回", str(e))

        # 5. mkdir → FTP 出现目录
        d1 = "nsp_test_dir"
        try:
            (m/"0"/SERVER/d1).mkdir()
            ok("mkdir（FTP 出现目录）") if (Path(FTP_UPLOAD)/d1).is_dir() else fail("mkdir", "FTP 未见目录")
        except Exception as e: fail("mkdir", str(e))

        # 6. rename（经 fuse）→ FTP 验证
        try:
            (m/"0"/SERVER/newf).rename(m/"0"/SERVER/"nsp_renamed.txt")
            ok("rename（FTP 验证）") if (Path(FTP_UPLOAD)/"nsp_renamed.txt").exists() and not (Path(FTP_UPLOAD)/newf).exists() else fail("rename", "FTP 侧不一致")
        except Exception as e: fail("rename", str(e))

        # 6b. 后端 rename 不接受 flags（A1）：带 flags 必须明确拒绝，不得静默降级。
        #     旧实现忽略 flags 直接调 backend_rename——NOREPLACE 目标不存在时"看起来
        #     成功"但语义未被保证，EXCHANGE 更会退化成单向移动（丢源/覆盖目标）。
        fa, fb = "nsp_a1_flags_src.txt", "nsp_a1_flags_dst.txt"
        try:
            (Path(FTP_UPLOAD) / fb).unlink(missing_ok=True)
            (Path(FTP_UPLOAD) / fa).write_text("FLAGSRC")
            r = _renameat2(str(m/"0"/SERVER/fa), str(m/"0"/SERVER/fb), 1)  # RENAME_NOREPLACE
            if r is None:
                print("  (跳过 后端 rename flags：libc 无 renameat2)")
            else:
                fail("后端 rename 带 flags 应被拒绝", "未报错（旧实现忽略 flags 直接改名）")
        except OSError as e:
            if e.errno == errno.EINVAL:
                ok("后端 rename 带 flags → EINVAL（明确拒绝，不静默降级）")
            else:
                fail("后端 rename 带 flags errno",
                     f"期望 EINVAL 实得 {e.errno}({os.strerror(e.errno)})")
        finally:
            for stale in (fa, fb):
                try:
                    (Path(FTP_UPLOAD) / stale).unlink()
                except Exception:
                    pass

        # 7. unlink → FTP 消失
        try:
            (m/"0"/SERVER/"nsp_renamed.txt").unlink()
            ok("unlink（FTP 删除）") if not (Path(FTP_UPLOAD)/"nsp_renamed.txt").exists() else fail("unlink", "FTP 侧仍存在")
        except Exception as e: fail("unlink", str(e))

        # 8. rmdir → FTP 消失
        try:
            (m/"0"/SERVER/d1).rmdir()
            ok("rmdir（FTP 删除目录）") if not (Path(FTP_UPLOAD)/d1).exists() else fail("rmdir", "FTP 目录仍存在")
        except Exception as e: fail("rmdir", str(e))

        # 9. 非 FTP 路径不受影响（普通存储直通）
        try:
            (Path(STORAGE)/"0/normal.txt").write_text("local")
            got = (m/"0/normal.txt").read_text().strip()
            ok("普通路径直通") if got == "local" else fail("普通路径", f"got='{got}'")
        except Exception as e: fail("普通路径", str(e))

        # 10. 随机读写测试（参考 CurlFtpFS：REST+RETR 随机偏移）
        try:
            import random
            big = "nsp_random_test.bin"
            # 写入 1MB 随机数据（经 FUSE 写模式 → 临时文件 → STOR 上传）
            data = bytes(random.randint(0,255) for _ in range(1024*1024))
            (m/"0"/SERVER/big).write_bytes(data)
            # 随机偏移 pread 校验 20 次（分段流式：每次 read 独立 RETR 连接）
            fd = os.open(str(m/"0"/SERVER/big), os.O_RDONLY)
            for i in range(20):
                off = random.randint(0, len(data)-1)
                sz = min(random.randint(1, 65536), len(data)-off)
                got = os.pread(fd, sz, off)
                if got != data[off:off+sz]:
                    os.close(fd); raise AssertionError(f"随机读 #{i} 偏移 {off} 大小 {sz} 不匹配")
            os.close(fd)
            # 清理
            (m/"0"/SERVER/big).unlink()
            ok("随机读写 20 次偏移校验通过")
        except Exception as e:
            # 清理残留
            for fp in [m/"0"/SERVER/big]: 
                if fp.exists(): fp.unlink()
            fail("随机读写", str(e))

        # 11. 缺失路径探测不计入内部熔断（熔断防误杀）：16 个**不同**缺失
        #     路径连续探测须全为 ENOENT；若误计失败，第 8 次即进静默，随后
        #     真实文件会在探测窗口内被快速失败（应用会把完好文件当消失）
        try:
            for i in range(16):
                try:
                    (m/"0"/SERVER/f"nsp_missing_{i}.txt").stat()
                    raise AssertionError(f"缺失路径 nsp_missing_{i} 竟然存在")
                except FileNotFoundError:
                    pass
            got = (m/"0"/SERVER/orig).read_text().strip()
            ok("缺失路径 16 连发不入内部熔断（真实文件仍可读，无误杀）") if \
                got == "ftp-original-content" else fail("熔断误杀", f"got='{got}'")
        except Exception as e:
            fail("缺失路径不入内部熔断（防误杀）", str(e))

        # 11b. LIST 缓存有界 TTL：**绕过代理**直接在 FTP 服务器上新增的文件，
        #      空闲超过 TTL 后再列必须可见。旧实现按路径永久复用缓存 → 外部改动
        #      永远看不到（同一目录反复列）。夹具必须先清目录：上传区跨次运行
        #      不清理，残留文件会让首次列举就"包含"待验证的名字（用例退化为恒真）。
        try:
            extdir = "nsp_ttl_dir"
            d = Path(FTP_UPLOAD)/extdir
            shutil.rmtree(d, ignore_errors=True)
            d.mkdir(parents=True)
            (d/"before.txt").write_text("x")
            first = sorted(os.listdir(m/"0"/SERVER/extdir))
            _ = os.listdir(m/"0"/SERVER/extdir)  # TTL 内第二次：仍走缓存（滑动续期）
            (d/"added_ext.txt").write_text("y")  # 外部新增（不经代理 → 不触发失效）
            time.sleep(6)  # > FTP_LIST_CACHE_TTL(5s)
            after = sorted(os.listdir(m/"0"/SERVER/extdir))
            if first == ["before.txt"] and "added_ext.txt" in after:
                ok("LIST 缓存有界 TTL：外部新增在空闲超时后可见")
            else:
                fail("LIST 缓存 TTL", f"first={first} after={after}")
        except Exception as e:
            fail("LIST 缓存 TTL", str(e))

        # 11c. truncate 后 size 不得被旧 LIST 缓存回灌：先列一次父目录把缓存装上，
        #      再截断（旧实现只清 stat、不清 LIST），随后再列——命中旧 LIST 会把
        #      截断前的 size 预填回 stat。最后等内核 attr 缓存（attr_timeout=1s）过期
        #      再 stat，确保读到的是模块侧的值。
        #      注：本端到端用例是**一致性检查**——FUSE 侧另有内核 attr 缓存等层，
        #      本机复现不出「旧 size 回灌」；判别该修复的确定性回归是
        #      test_ftp_truncate_list.py（直编后端 + 桩 mux/curl）。
        try:
            tfile = "nsp_truncate_size.txt"
            (m/"0"/SERVER/tfile).write_text("0123456789")
            _ = os.listdir(m/"0"/SERVER)
            time.sleep(1.2)
            os.truncate(m/"0"/SERVER/tfile, 0)
            _ = os.listdir(m/"0"/SERVER)
            time.sleep(1.2)
            sz3 = os.stat(m/"0"/SERVER/tfile).st_size
            if sz3 == 0:
                ok("truncate 清 LIST：截断后 size 不被旧缓存回灌")
            else:
                fail("truncate 清 LIST", f"截断后 size={sz3}（期望 0；旧 LIST 缓存回灌了旧值）")
        except Exception as e:
            fail("truncate 清 LIST", str(e))

        # 12. V5 分页：700 文件大目录一次列全（3 页 × 256；旧 512 整批
        #     上限会静默丢尾）。文件直写 FTP 根（免 700 次 STOR），只测读链路。
        try:
            bigd = "nsp_bigdir"
            (Path(FTP_UPLOAD)/bigd).mkdir(exist_ok=True)
            want = {f"f{i:04d}" for i in range(700)}
            for n in want:
                (Path(FTP_UPLOAD)/bigd/n).write_bytes(b"x")
            raw = os.listdir(m/"0"/SERVER/bigd)
            items = set(raw)
            ok("大目录 700 文件一次列全（V5 分页）") if items == want and len(raw) == 700 else fail(
                "大目录分页", f" 列出 {len(items)}/700（丢尾则为旧 512 上限复发）")
        except Exception as e:
            fail("大目录分页", str(e))
        finally:
            shutil.rmtree(Path(FTP_UPLOAD)/"nsp_bigdir", ignore_errors=True)

    finally:
        stop_fuse(p)   # fuse_daemon 退出 → 模块 exit 清理后端
        # 清理测试残留：本套件的工件统一用 nsp_ 前缀，按前缀整体清扫。
        # 此前只逐个手删（且只删了 orig），漏掉 nsp_ttl_probe /
        # nsp_truncate_size.txt / nsp_test_flush_then_write.txt 等，于是在
        # **真实** FTP 树上持续累积——upload/ 同时是用户的投递目录，不能留垃圾。
        for n in os.listdir(FTP_UPLOAD):
            if not (n.startswith("nsp_") or n.startswith(".nsp_")):
                continue
            fp = Path(FTP_UPLOAD) / n
            if fp.is_dir():
                shutil.rmtree(fp, ignore_errors=True)
            else:
                try:
                    fp.unlink()
                except OSError:
                    pass

    print(f"\n═══════════════════════════════════════")
    print(f"[{time.strftime('%H:%M:%S')}] 测试完成 | ✅ {PASS} 通过 | ❌ {FAIL} 失败 | 共 {PASS+FAIL}")
    if ERRS:
        for d, dt in ERRS: print(f"  失败: {d}: {dt}")
        sys.exit(1)

if __name__ == "__main__":
    main()
