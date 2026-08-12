#!/usr/bin/env python3
"""FUSE 全链路并发压力基准 — 挂载 fuse_daemon 后量化端到端瓶颈。

场景（均走完整 VFS_SETUP_CORE 热路径：uid seqlock → module 锁 → 规则锁 → trie）：
  1. 大目录 readdir：5000 文件目录 os.listdir 计时（readdir 条目级 probe 开销）
  2. stat 风暴：8 线程并发 os.stat 大目录条目（getattr 热路径并发）
  3. open/read/close 并发：8 线程 × 500 次 4KB 读（open 的 resolve + read 直通）
  4. 未命中规则路径 getattr：重复 stat 同一无规则路径（负路径热路径）

用法：python3 tests/stress_fuse.py
输出：各场景耗时与吞吐（与优化后对比）。
"""
import os, sys, time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_rules import setup, start, stop, CONF, STORAGE, MNT

BIGDIR_N = 5000
STAT_LOOPS = 2000
IO_THREADS = 8
IO_PER_THREAD = 500

def t(fmt, *a):
    print(f"  {fmt % a if a else fmt}")

def bench_readdir(m):
    """5000 文件目录 listdir：readdir 逐条目 probe（锁 + trie 重复下降）"""
    d = Path(STORAGE) / "0" / "bigdir"
    d.mkdir(parents=True, exist_ok=True)
    for i in range(BIGDIR_N):
        (d / f"f{i:05d}.txt").write_bytes(b"x")
    t0 = time.time()
    n = len(os.listdir(m / "0" / "bigdir"))
    dt = time.time() - t0
    t(f"大目录 readdir {BIGDIR_N} 条目: {dt:.3f}s ({n} 条目, {BIGDIR_N/dt:.0f} 条目/s)")
    for f in d.iterdir(): f.unlink()

def bench_stat(m):
    """8 线程并发 stat 大目录条目（getattr 并发热路径）"""
    d = Path(STORAGE) / "0" / "bigdir"
    d.mkdir(parents=True, exist_ok=True)
    names = [f"f{i:05d}.txt" for i in range(BIGDIR_N)]
    for n in names: (d / n).write_bytes(b"x")
    base = m / "0" / "bigdir"
    def worker(chunk):
        for n in chunk:
            os.stat(base / n)
    chunks = [names[i::IO_THREADS] for i in range(IO_THREADS)]
    t0 = time.time()
    with ThreadPoolExecutor(IO_THREADS) as ex:
        list(ex.map(worker, chunks))
    dt = time.time() - t0
    total = BIGDIR_N
    t(f"stat 风暴 {total} 次（{IO_THREADS} 线程）: {dt:.3f}s ({total/dt:.0f} stat/s)")
    for n in names: (d / n).unlink()

def bench_io(m):
    """8 线程 × 500 次 open/pread(4KB)/close 同一小文件（open resolve + read 直通）"""
    f = Path(STORAGE) / "0" / "io.bin"
    f.write_bytes(b"z" * 65536)
    fp = m / "0" / "io.bin"
    def worker(_):
        for _ in range(IO_PER_THREAD):
            fd = os.open(str(fp), os.O_RDONLY)
            os.pread(fd, 4096, 0)
            os.close(fd)
    t0 = time.time()
    with ThreadPoolExecutor(IO_THREADS) as ex:
        list(ex.map(worker, range(IO_THREADS)))
    dt = time.time() - t0
    n = IO_THREADS * IO_PER_THREAD
    t(f"open/read/close x{n}（{IO_THREADS} 线程）: {dt:.3f}s ({n/dt:.0f} ops/s)")
    f.unlink()

def bench_plain_getattr(m):
    """无规则路径重复 stat：getattr 全链路（未命中缓存，最短热路径）"""
    f = Path(STORAGE) / "0" / "plain.txt"
    f.write_bytes(b"x")
    fp = m / "0" / "plain.txt"
    t0 = time.time()
    for _ in range(STAT_LOOPS):
        os.stat(fp)
    dt = time.time() - t0
    t(f"无规则路径 stat x{STAT_LOOPS}: {dt:.3f}s ({STAT_LOOPS/dt:.0f} stat/s, 单次 {dt/STAT_LOOPS*1e6:.0f} us)")

def main():
    print("═══ FUSE 全链路压力基准 ═══")
    setup()
    p = start()
    if not p:
        print("  ❌ fuse_daemon 启动失败"); sys.exit(1)
    print("  ✅ 已挂载")
    m = Path(MNT)
    try:
        bench_plain_getattr(m)   # 先热一遍最短路径
        bench_readdir(m)
        bench_stat(m)
        bench_io(m)
    finally:
        stop(p)
    print("  ✅ 压力基准完成")

if __name__ == "__main__":
    main()
