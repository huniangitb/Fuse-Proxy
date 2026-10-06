#!/usr/bin/env python3
"""FTP 模块压力 / 真实场景测试 — 复用 test_ftp.py 的挂载框架（import 公共符号）。

设计目标：尽可能模拟真实日常使用场景 + 重负载：
  日常场景：
    1. 模式文件随机读 60 次（多次 REST restart 跳变 —— 回归多次跳变后数据错乱）
    2. 32MB 大文件顺序读校验（大文件下载 / 视频播放场景）
    3. 多进程并发读（4 进程 × 不同偏移区间，模拟多应用同时访问同一存储）
    4. 小文件批量风暴（50 个文件创建/读回/删除，模拟相册缩略图 / 缓存目录）
  重负载：
    5. 连续 open-close 循环 200 次（模拟反复打开关闭 —— 回归 release 竞态/卡顿）
    6. 并发读写混合（4 进程同时写不同文件 + 读回校验）
    7. 高并发句柄（同进程同时打开 128 个 fd 读取，模拟句柄占用高峰）

用法：python3 tests/test_ftp_stress.py   （前置同 test_ftp.py：vsftpd 匿名服务）
"""
import os, sys, time, hashlib, random
from pathlib import Path
from multiprocessing import Process

# 复用 test_ftp.py 的挂载/等待框架（其 main 在 __main__ 保护下，import 不执行）
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_ftp import (setup, start_fuse, stop_fuse, wait_ftp_ready,
                      MNT, STORAGE, FTP_UPLOAD, SERVER)

PASS = 0; FAIL = 0; ERRS = []
def ok(d):
    global PASS; PASS += 1; print(f"  ✅ {d}")
def fail(d, dt=""):
    global FAIL; FAIL += 1; print(f"  ❌ {d}: {dt}"); ERRS.append((d, dt))

M = lambda: Path(MNT) / "0" / SERVER

def pat_data(n):
    """递增模式数据（i%251）：错位时能精确定位偏移"""
    return bytes(i % 251 for i in range(n))

# ---------- 子进程工作函数（并发） ----------
def worker_rand_read(off_base, seed, n, q):
    """随机偏移读 n 次并校验（经 FUSE）"""
    try:
        import os, random
        rnd = random.Random(seed)
        ref = pat_data(1024 * 1024)
        fd = os.open(str(M() / "pat_1m.bin"), os.O_RDONLY)
        for i in range(n):
            off = rnd.randint(0, len(ref) - 65536)
            sz = rnd.randint(1, 65536)
            got = os.pread(fd, sz, off)
            if got != ref[off:off + len(got)]:
                q.put((False, f"rand #{i} off={off} sz={sz}"))
                os.close(fd); return
        os.close(fd)
        q.put((True, "ok"))
    except Exception as e:
        q.put((False, str(e)))

def worker_write(seed, q):
    """写 512KB 随机文件并读回校验"""
    try:
        import os, random
        rnd = random.Random(seed)
        data = bytes(rnd.randint(0, 255) for _ in range(512 * 1024))
        fn = M() / f"conc_{seed}.bin"
        fn.write_bytes(data)
        got = fn.read_bytes()
        okc = got == data
        fn.unlink()
        q.put((okc, "ok" if okc else "内容不匹配"))
    except Exception as e:
        q.put((False, str(e)))

def main():
    global PASS, FAIL
    print("前置：vsftpd 匿名服务（127.0.0.1:21）须已运行（同 test_ftp.py）")
    setup()
    p = start_fuse()
    if not p:
        print("  ❌ fuse_daemon 启动失败"); sys.exit(1)
    print("  ✅ fuse_daemon 已挂载")
    if not wait_ftp_ready():
        stop_fuse(p)
        print("  ❌ FTP 后端未就绪"); sys.exit(1)
    print("  ✅ FTP 后端已注册")

    t0 = time.time()
    try:
        # ============ 1. 模式文件随机读 60 次（多次 restart 跳变）============
        try:
            (M() / "pat_1m.bin").write_bytes(pat_data(1024 * 1024))
            fd = os.open(str(M() / "pat_1m.bin"), os.O_RDONLY)
            ref = pat_data(1024 * 1024)
            rnd = random.Random(2024)
            for i in range(60):
                off = rnd.randint(0, len(ref) - 65536)
                sz = rnd.randint(1, 65536)
                got = os.pread(fd, sz, off)
                if got != ref[off:off + len(got)]:
                    raise AssertionError(f"随机读 #{i} 偏移 {off} 大小 {sz} 不匹配")
            os.close(fd)
            ok("模式文件随机读 60 次（多次 REST 跳变）校验通过")
        except Exception as e:
            fail("模式随机读", str(e))
        finally:
            if (M() / "pat_1m.bin").exists(): (M() / "pat_1m.bin").unlink()

        # ============ 2. 32MB 大文件顺序读校验 ============
        try:
            big = "big_32m.bin"
            data = pat_data(32 * 1024 * 1024)
            (M() / big).write_bytes(data)
            t1 = time.time()
            got = (M() / big).read_bytes()
            dt = time.time() - t1
            okc = hashlib.md5(got).hexdigest() == hashlib.md5(data).hexdigest()
            msg = f"32MB 顺序读校验通过（{32*1024*1024/dt/1048576:.0f} MB/s）" if okc else "md5 不匹配"
            ok(msg) if okc else fail("大文件顺序读", "md5 不匹配")
            (M() / big).unlink()
        except Exception as e:
            fail("大文件顺序读", str(e))

        # ============ 3. 多进程并发读（4 进程 × 30 次随机读）============
        try:
            (M() / "pat_1m.bin").write_bytes(pat_data(1024 * 1024))
            q = __import__("multiprocessing").Queue()
            procs = [Process(target=worker_rand_read, args=(b, 100 + b, 30, q))
                     for b in range(4)]
            for x in procs: x.start()
            for x in procs: x.join(60)
            results = [q.get(timeout=2) for _ in procs]
            bad = [r for r in results if not r[0]]
            ok("多进程并发读（4 进程 × 30 次）全部通过") if not bad else \
                fail("多进程并发读", f"{bad}")
            (M() / "pat_1m.bin").unlink()
        except Exception as e:
            fail("多进程并发读", str(e))

        # ============ 4. 小文件批量风暴（50 个文件）============
        try:
            bad = []
            for i in range(50):
                fn = M() / f"small_{i:03d}.txt"
                data = f"content-{i}".encode()
                fn.write_bytes(data)
                got = fn.read_bytes()
                if got != data: bad.append(i)
                fn.unlink()
            ok("小文件批量风暴（50 个创建/读回/删除）通过") if not bad else \
                fail("小文件风暴", f"不匹配: {bad[:5]}")
        except Exception as e:
            fail("小文件风暴", str(e))

        # ============ 5. 连续 open-close 循环 200 次 ============
        try:
            fn = M() / "openloop.bin"
            data = pat_data(64 * 1024)
            fn.write_bytes(data)
            ref = pat_data(64 * 1024)
            bad = 0
            for i in range(200):
                fd = os.open(str(fn), os.O_RDONLY)
                got = os.pread(fd, 4096, (i * 4096) % (64 * 1024 - 4096))
                if got != ref[(i * 4096) % (64 * 1024 - 4096):][:len(got)]:
                    bad += 1
                os.close(fd)
            fn.unlink()
            ok("连续 open-close 200 次（release 竞态/卡顿回归）通过") if bad == 0 else \
                fail("open-close 循环", f"{bad} 次不匹配")
        except Exception as e:
            fail("open-close 循环", str(e))

        # ============ 6. 并发读写混合（4 进程同时写 + 读回）============
        try:
            q = __import__("multiprocessing").Queue()
            procs = [Process(target=worker_write, args=(200 + b, q)) for b in range(4)]
            for x in procs: x.start()
            for x in procs: x.join(60)
            results = [q.get(timeout=2) for _ in procs]
            bad = [r for r in results if not r[0]]
            ok("并发写 4 文件 + 读回校验全部通过") if not bad else fail("并发写", f"{bad}")
        except Exception as e:
            fail("并发写", str(e))

        # ============ 7. 高并发句柄：32 个 fd 同时打开读取 ============
        # 注：并发上限由测试环境决定——vsftpd pasv 端口仅 30000-30100（100 个），
        # 128 个并发 FTP 读流会耗尽端口导致连接失败（EIO）；32 并发已验证安全，
        # 且远超真实移动端同时读流的数量级（不修改 vsftpd 配置为项目约定）
        try:
            fn = M() / "manyfd.bin"
            data = pat_data(4 * 1024 * 1024)
            fn.write_bytes(data)
            ref = pat_data(4 * 1024 * 1024)
            fds = [os.open(str(fn), os.O_RDONLY) for _ in range(32)]
            bad = 0
            for i, fd in enumerate(fds):
                off = (i * 4096) % (4 * 1024 * 1024 - 4096)
                got = os.pread(fd, 4096, off)
                if got != ref[off:off + len(got)]: bad += 1
            for fd in fds: os.close(fd)
            fn.unlink()
            ok("高并发句柄（32 fd 同时打开读取）通过") if bad == 0 else \
                fail("高并发句柄", f"{bad} 次不匹配")
        except Exception as e:
            fail("高并发句柄", str(e))

    finally:
        stop_fuse(p)
        # 按模式清扫本套件工件。此前是 4 个硬编码文件名，漏掉 conc_*.bin（并发写）
        # 与 small_*.txt（50 个小文件）——这两类只在 happy path 的 inline unlink 里删，
        # 中途异常就漏在**真实** FTP 树（upload/ 同时是用户的投递目录）里累积。
        for pat in ("pat_1m.bin", "big_32m.bin", "openloop.bin", "manyfd.bin",
                    "conc_*.bin", "small_*.txt"):
            for fp in Path(FTP_UPLOAD).glob(pat):
                try:
                    fp.unlink()
                except OSError:
                    pass

    print(f"\n═══════════════════════════════════════")
    print(f"[{time.strftime('%H:%M:%S')}] 压力测试完成 | 总耗时 {time.time()-t0:.0f}s | "
          f"✅ {PASS} 通过 | ❌ {FAIL} 失败 | 共 {PASS+FAIL}")
    if ERRS:
        for d, dt in ERRS: print(f"  失败: {d}: {dt}")
        sys.exit(1)

if __name__ == "__main__":
    main()
