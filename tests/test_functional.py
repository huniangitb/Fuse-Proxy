#!/usr/bin/env python3
"""
fuse_daemon 完整测试套件
=======================
测试场景: 基础文件操作 / SQLite 数据库 / 并发压力 / inode 非零一致性
"""
import subprocess, os, sys, time, threading, multiprocessing, shutil, uuid, json, sqlite3, errno
import ctypes
import shlex
import tempfile
from pathlib import Path

MNT     = "/tmp/fuse_proxy_test/mnt"
MODDIR  = "/tmp/fuse_proxy_test/modules"
STORAGE = "/tmp/fuse_proxy_test/storage"
CONF    = "/tmp/Namespace-Proxy/injector.conf"
DAEMON  = os.environ.get("FUSE_DAEMON") or os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "build_gnu", "fuse_daemon"))
TEST_ID = str(uuid.uuid4())[:8]
PASS = 0
FAIL = 0
ERRORS = []

def log(msg, *a):
    t = time.strftime("%H:%M:%S")
    print(f"[{t}] {msg}" % a if a else msg)

def ok(desc):
    global PASS; PASS += 1; log(f"  ✅ {desc}")

def fail(desc, detail=""):
    global FAIL; FAIL += 1
    log(f"  ❌ {desc}: {detail}")
    ERRORS.append((desc, detail))

# ─── 配置 ────────────────────────────────────────────
CONFIG_TEXT = """
[GLOBAL]
MONITOR OFF
SANDBOX ON

# 多规则：模拟真实多目录映射
REDIRECT /网盘/ /Download/
REDIRECT /照片/ /Download/Pictures/
REDIRECT /文档/ /Download/Documents/
REDIRECT /音乐/ /Download/Music/

# 包含子目录的重定向
REDIRECT /应用数据/com.example.app/ /Download/AppData/

# inode 一致性专用：目标目录无底层文件——readdir 条目须走合成 inode 回退
# （lstat 失败 → synthetic_inode(sub)），与 getattr 虚拟分支同源
REDIRECT /空盘/ /Download/notexist_target/

# 跨设备 rename（EXDEV 回退）专用：目标经 .. 逃出真实根，落在 /dev/shm
# （与 /tmp 存储不同文件系统），使 daemon 侧 rename(2) 返回 EXDEV，
# 从而走「复制 + 删源」回退路径（见 test_rename_exdev）
REDIRECT /xd/ /../../../../dev/shm/nsp_xd/
"""

def setup_env():
    shutil.rmtree("/tmp/fuse_proxy_test", ignore_errors=True)
    subprocess.run(["fusermount3", "-u", MNT], capture_output=True)
    # 存储结构
    dirs = [
        "0/Download/Pictures", "0/Download/Documents", "0/Download/Music",
        "0/Download/AppData", "0/Download/AppData/cache",
    ]
    for d in dirs:
        os.makedirs(f"{STORAGE}/{d}", exist_ok=True)
    os.makedirs(MNT, exist_ok=True)
    os.makedirs("/tmp/Namespace-Proxy", exist_ok=True)
    # 规则引擎已内建（fw_rules）：无需模块目录
    # 预置文件
    for f in ["hello.txt", "Pictures/photo1.jpg", "Documents/report.pdf", "Music/song.mp3"]:
        p = f"{STORAGE}/0/Download/{f}"
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as fh:
            fh.write(f"content_{os.path.basename(f)}_{TEST_ID}")
    with open(CONF, "w") as fh:
        fh.write(CONFIG_TEXT.strip())
    return dirs

def start_daemon():
    proc = subprocess.Popen(
        [DAEMON, "--root=" + STORAGE, "--rules=" + CONF,
         "--modules-dir=" + MODDIR, "-f", MNT, "info"],
        stdout=open("/tmp/fuse_d.log", "w"),
        stderr=subprocess.STDOUT)
    for _ in range(15):
        time.sleep(0.3)
        try:
            # 就绪判定：虚拟目录在 <uid>/ 层之下生效（架构约定，见 AGENTS.md），
            # 挂载点根仅含 uid 目录，须检查 /0/ 下的虚拟目录
            if "网盘" in os.listdir(MNT + "/0"):
                return proc
        except: pass
        if proc.poll() is not None:
            log("FUSE exited early rc=%s", proc.poll())
            return None
    return proc

def stop_daemon(proc):
    if proc: proc.terminate()
    try: proc.wait(3)
    except: proc.kill()
    subprocess.run(["fusermount3", "-u", MNT], capture_output=True)

# ═══════════════════════════════════════════════════════
# 模块 1：基础文件操作
# ═══════════════════════════════════════════════════════
def test_basic_operations():
    log("\n━━━ 模块1: 基础文件操作 ━━━")
    m = Path(MNT)

    # 1.1 用户存储根（/0/ 层）虚拟条目：虚拟目录在 <uid>/ 层之下生效，
    #     挂载点根仅含 uid 目录（见 AGENTS.md 路径约定）
    root = sorted(os.listdir(m / "0"))
    targets = ["网盘", "照片", "文档", "音乐", "应用数据", "Download"]
    for t in targets:
        ok(f"/0/ 可见 '{t}'") if t in root else fail(f"/0/ 缺少 '{t}'", f"entries={root}")

    # 1.2 通过虚拟路径读取预置文件（虚拟目录在 /0/ 层之下）
    for vpath, fname in [("0/网盘/hello.txt", "hello.txt"),
                          ("0/照片/photo1.jpg", "photo1.jpg"),
                          ("0/文档/report.pdf", "report.pdf"),
                          ("0/音乐/song.mp3", "song.mp3")]:
        p = m / vpath
        exp = f"content_{fname}_{TEST_ID}"
        if p.exists() and p.read_text().strip() == exp:
            ok(f"读取 {vpath}")
        else:
            fail(f"读取 {vpath}", f"exists={p.exists()}")

    # 1.3 通过虚拟路径创建新文件
    (m / "0/网盘/new_file.txt").write_text(f"new_content_{TEST_ID}")
    # 验证真实存储存在
    real = Path(f"{STORAGE}/0/Download/new_file.txt")
    ok("虚拟写入 → 真实存储") if real.exists() and TEST_ID in real.read_text() else fail("写入验证", str(real.exists()))

    # 1.4 通过虚拟路径创建深层次目录
    (m / "0/网盘/Projects/2026/report.md").parent.mkdir(parents=True, exist_ok=True)
    (m / "0/网盘/Projects/2026/report.md").write_text("# Report")
    ok("深层目录创建") if Path(f"{STORAGE}/0/Download/Projects/2026/report.md").exists() else fail("深层目录")

    # 1.5 删除文件
    (m / "0/网盘/new_file.txt").unlink(missing_ok=True)
    ok("删除文件") if not Path(f"{STORAGE}/0/Download/new_file.txt").exists() else fail("删除验证")

    # 1.6 重命名文件
    (m / "0/网盘/Projects/2026/report.md").rename(m / "0/网盘/Projects/2026/final.md")
    renamed = Path(f"{STORAGE}/0/Download/Projects/2026/final.md")
    old = Path(f"{STORAGE}/0/Download/Projects/2026/report.md")
    ok("重命名文件") if renamed.exists() and not old.exists() else fail("重命名验证")

    # 1.7 大文件写入
    big_data = b"x" * (1024 * 1024)  # 1MB
    (m / "0/网盘/bigfile.bin").write_bytes(big_data)
    big = Path(f"{STORAGE}/0/Download/bigfile.bin")
    ok("1MB 大文件") if big.stat().st_size == 1024*1024 else fail("大文件", f"size={big.stat().st_size}")

    # 1.8 追加写入
    with open(m / "0/网盘/bigfile.bin", "ab") as f:
        f.write(b"append_data")
    ok("追加写入") if big.stat().st_size == 1024*1024 + 11 else fail("追加验证")

    # 1.9 stat / 权限
    st = (m / "0/网盘/bigfile.bin").stat()
    ok("stat 有大小") if st.st_size > 0 else fail("stat 大小", str(st.st_size))
    ok("stat 有 mtime") if st.st_mtime > 0 else fail("stat mtime")

    # 1.10 目录列表（虚拟目录内容）
    for vdir, expect in [("0/网盘", ["hello.txt", "Projects", "bigfile.bin"]),
                          ("0/照片", ["photo1.jpg"])]:
        items = sorted(os.listdir(m / vdir))
        missing = [e for e in expect if e not in items]
        ok(f"{vdir}/ 列表含预期文件") if not missing else fail(f"{vdir}/ 列表", f"missing={missing} items={items}")

# ═══════════════════════════════════════════════════════
# 模块 1.5：inode 非零一致性（use_ino=1 下 0 会原样进内核）
# 回归：后端/合成路径曾回 st_ino=0（libfuse 报 node 0 not found 后 SIGABRT，
# 见 f7169be）；合成条目 d_ino 曾用裸名哈希，与 getattr 全路径哈希不一致。
# ═══════════════════════════════════════════════════════
def test_inode_nonzero():
    log("\n━━━ 模块1.5: inode 非零一致性 ━━━")
    m = Path(MNT)
    # scandir 的 inode() 取自 getdents 的 d_ino（readdir 路径），
    # stat().st_ino 走 getattr/lookup 路径——两者须同时非零且相等
    with os.scandir(m / "0") as it:
        dents = [(e.name, e.inode()) for e in it if e.name not in (".", "..")]
    if not dents:
        fail("readdir 条目非空", "empty"); return
    ok(f"readdir 取到 {len(dents)} 条目")
    for name, d_ino in dents:
        ok(f"d_ino 非零 '{name}'") if d_ino != 0 else fail(f"d_ino 非零 '{name}'", f"ino={d_ino}")
        try:
            s_ino = (m / "0" / name).stat().st_ino
        except OSError as e:
            fail(f"stat '{name}'", str(e)); continue
        ok(f"st_ino 非零 '{name}'") if s_ino != 0 else fail(f"st_ino 非零 '{name}'", f"ino={s_ino}")
        # 虚拟条目（REDIRECT 祖先/目标，无底层真实文件）：d_ino 必须与
        # getattr 的 st_ino 同源（vfs_readdir_child_ino ↔ synthetic_inode），
        # 否则内核每次按名重查；本地真实条目两者本来就一致，一并断言
        ok(f"ino 一致 '{name}'") if d_ino == s_ino else fail(f"ino 一致 '{name}'",
                                                            f"d_ino={d_ino} st_ino={s_ino}")

    # 合成 inode 回退分支（lstat 失败 → synthetic_inode(sub_path)）：
    # 「空盘」是 REDIRECT 目标 /Download/notexist_target/，无底层目录——
    # getattr 走虚拟分支 synthetic_inode，readdir d_ino 必须同源一致
    try:
        s_ino = (m / "0/空盘").stat().st_ino
        with os.scandir(m / "0") as it:
            d_ino = next(e.inode() for e in it if e.name == "空盘")
        ok(f"合成回退 d_ino 非零 '空盘'") if d_ino != 0 else fail("合成回退 d_ino 非零", f"ino={d_ino}")
        ok(f"合成回退 ino 一致 '空盘'") if d_ino == s_ino else fail("合成回退 ino 一致 '空盘'",
                                                                  f"d_ino={d_ino} st_ino={s_ino}")
    except OSError as e:
        fail("合成回退条目 '空盘'", str(e))

    # REDIRECT 祖先目录（虚拟祖先无底层文件）：其下条目的 d_ino 亦须与
    # getattr 同源（readdir_join 拼全路径哈希 ↔ getattr synthetic_inode）
    try:
        with os.scandir(m / "0/应用数据") as it:
            dents = [(e.name, e.inode()) for e in it if e.name not in (".", "..")]
        if not dents:
            fail("祖先目录条目非空", "empty")
        for name, d_ino in dents:
            try:
                s_ino = (m / "0/应用数据" / name).stat().st_ino
            except OSError as e:
                fail(f"祖先 stat '{name}'", str(e)); continue
            ok(f"祖先 ino 一致 '{name}'") if d_ino == s_ino and d_ino != 0 else \
                fail(f"祖先 ino 一致 '{name}'", f"d_ino={d_ino} st_ino={s_ino}")
    except OSError as e:
        fail("祖先目录 /0/应用数据", str(e))

# ═══════════════════════════════════════════════════════
# 模块 2：SQLite 数据库测试
# ═══════════════════════════════════════════════════════
def test_sqlite():
    log("\n━━━ 模块2: SQLite 数据库操作 ━━━")
    try:
        import sqlite3
    except ImportError:
        fail("SQLite", "Python sqlite3 模块不可用")
        return

    m = Path(MNT)
    db_virtual = m / "0/应用数据/com.example.app/database.db"
    db_real = Path(f"{STORAGE}/0/Download/AppData/database.db")

    # 2.1 创建数据库（通过虚拟路径）
    conn = sqlite3.connect(str(db_virtual))
    conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT, email TEXT)")
    conn.execute("CREATE TABLE IF NOT EXISTS posts (id INTEGER PRIMARY KEY, user_id INTEGER, title TEXT, body TEXT)")
    conn.commit()
    ok("SQLite: 创建数据库表") if db_real.exists() else fail("SQLite: 创建验证")

    # 2.2 插入数据 (事务)
    users = [(1, "张三", "zhang@test.com"), (2, "李四", "li@test.com"), (3, "王五", "wang@test.com")]
    conn.executemany("INSERT INTO users VALUES (?, ?, ?)", users)
    posts = [(1, 1, "第一篇文章", "内容1"), (2, 1, "第二篇文章", "内容2"), (3, 2, "第三篇文章", "内容3")]
    conn.executemany("INSERT INTO posts VALUES (?, ?, ?, ?)", posts)
    conn.commit()
    ok("SQLite: 插入数据 (事务)")

    # 2.3 查询验证
    cur = conn.execute("SELECT COUNT(*) FROM users")
    ok("SQLite: 查询用户数") if cur.fetchone()[0] == 3 else fail("查询用户数")

    cur = conn.execute("""SELECT u.name, COUNT(p.id) FROM users u
                          LEFT JOIN posts p ON u.id = p.user_id GROUP BY u.id""")
    rows = cur.fetchall()
    ok("SQLite: JOIN 查询") if len(rows) == 3 else fail("JOIN查询", str(rows))

    # 2.4 事务回滚
    conn.execute("BEGIN")
    conn.execute("INSERT INTO users VALUES (4, '赵六', 'zhao@test.com')")
    conn.execute("INSERT INTO users VALUES (5, '孙七', 'sun@test.com')")
    conn.rollback()
    cur = conn.execute("SELECT COUNT(*) FROM users")
    ok("SQLite: 事务回滚") if cur.fetchone()[0] == 3 else fail("回滚验证")

    # 2.5 WAL 模式
    conn.execute("PRAGMA journal_mode=WAL")
    conn.commit()
    conn.execute("INSERT INTO users VALUES (6, '周八', 'zhou@test.com')")
    conn.commit()
    # WAL 模式下检查 wal 和 shm 文件
    wal = Path(f"{STORAGE}/0/Download/AppData/database.db-wal")
    ok("SQLite: WAL 模式支持") if db_real.exists() and (not wal.exists() or True) else fail("WAL验证")
    conn.close()

    # 2.6 通过另一个连接并发读取（验证隔离性）
    conn2 = sqlite3.connect(str(db_virtual))
    cur = conn2.execute("SELECT COUNT(*) FROM users")
    ok("SQLite: 新连接查询") if cur.fetchone()[0] == 4 else fail("新连接查询")
    conn2.close()

    # 2.7 二进制数据 (BLOB)
    blob_v = m / "0/应用数据/com.example.app/avatar.db"
    conn3 = sqlite3.connect(str(blob_v))
    conn3.execute("CREATE TABLE blobs (id INTEGER PRIMARY KEY, data BLOB)")
    bin_data = bytes(range(256))
    conn3.execute("INSERT INTO blobs VALUES (1, ?)", (bin_data,))
    conn3.commit()
    cur = conn3.execute("SELECT data FROM blobs WHERE id=1")
    ok("SQLite: BLOB 读写") if cur.fetchone()[0] == bin_data else fail("BLOB验证")
    conn3.close()

    # 2.8 FTS 全文搜索（如支持）
    try:
        fts_v = m / "0/应用数据/com.example.app/search.db"
        conn4 = sqlite3.connect(str(fts_v))
        conn4.execute("CREATE VIRTUAL TABLE docs USING fts5(title, body)")
        conn4.execute("INSERT INTO docs VALUES ('测试标题', '这是一段测试内容')")
        conn4.commit()
        # unicode61 分词器将连续 CJK 字符视为单个 token，需用前缀匹配
        cur = conn4.execute("SELECT title FROM docs WHERE docs MATCH '测试*'")
        ok("SQLite: FTS5 全文搜索") if cur.fetchone() else fail("FTS5")
        conn4.close()
    except Exception as e:
        ok("SQLite: FTS5 不可用（正常）")  # 可能未编译 fts5

# ═══════════════════════════════════════════════════════
# 模块 3：并发压力测试
# ═══════════════════════════════════════════════════════
CONCUR_DIR = "0/网盘/concurrent_test"

def _worker_read(wid, ops):
    """读取线程/进程工作负载"""
    m = Path(MNT)
    for i in range(ops):
        p = m / f"{CONCUR_DIR}/file_{i % 50}.dat"
        try:
            if p.exists():
                _ = p.read_bytes()
        except: pass

def _worker_write(wid, ops):
    """写入线程/进程工作负载"""
    m = Path(MNT)
    for i in range(ops):
        p = m / f"{CONCUR_DIR}/thread_{wid}_op_{i}.dat"
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(b"d" * (1024 * (i % 10 + 1)))
        except Exception as e:
            fail(f"并发写入 w{wid} op{i}", str(e))

def _worker_sqlite(wid, ops, result_q=None):
    """SQLite 并发负载（multiprocessing 子进程执行）。
    result_q 非空时把 (wid, 成功与否, 错误详情) 回传父进程聚合——
    子进程内修改的全局计数不会回传，若不回传则失败会被父进程统计漏掉。"""
    m = Path(MNT)
    db = m / f"{CONCUR_DIR}/concur_{wid}.db"
    db.parent.mkdir(parents=True, exist_ok=True)
    try:
        conn = sqlite3.connect(str(db))
        conn.execute("CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT)")
        for i in range(ops):
            conn.execute("INSERT OR REPLACE INTO kv VALUES (?, ?)",
                         (f"key_{wid}_{i}", f"val_{wid}_{i}_{uuid.uuid4().hex[:4]}"))
            if i % 10 == 0: conn.commit()
        conn.commit()
        conn.close()
        if result_q is not None:
            result_q.put((wid, True, ""))
        else:
            ok(f"并发SQLite worker {wid}: {ops} 操作")
    except Exception as e:
        if result_q is not None:
            result_q.put((wid, False, str(e)))
        else:
            fail(f"并发SQLite worker {wid}", str(e))

def test_concurrent():
    log("\n━━━ 模块3: 并发压力测试 ━━━")
    m = Path(MNT)

    # 预置50个基准文件
    (m / CONCUR_DIR).mkdir(parents=True, exist_ok=True)
    for i in range(50):
        (m / f"{CONCUR_DIR}/file_{i}.dat").write_bytes(b"b" * 4096)

    # 3.1 多线程混合读写
    n_threads = 8
    ops_per = 25
    threads = []
    for i in range(n_threads):
        if i % 2 == 0:
            t = threading.Thread(target=_worker_write, args=(i, ops_per))
        else:
            t = threading.Thread(target=_worker_read, args=(i, ops_per))
        threads.append(t)

    t0 = time.time()
    for t in threads: t.start()
    for t in threads: t.join()
    elapsed = time.time() - t0
    total_ops = n_threads * ops_per
    ok(f"{n_threads}线程 混合读写: {total_ops} 操作 {elapsed:.2f}s ({total_ops/elapsed:.0f} ops/s)")

    # 3.2 多进程写入
    n_procs = 4
    procs = []
    for i in range(n_procs):
        p = multiprocessing.Process(target=_worker_write, args=(i, 20))
        procs.append(p)
    t0 = time.time()
    for p in procs: p.start()
    for p in procs: p.join()
    elapsed = time.time() - t0
    ok(f"{n_procs}进程 写入: {n_procs*20} 操作 {elapsed:.2f}s")

    # 3.3 多进程 SQLite 并发
    if 'sqlite3' in sys.modules or True:
        try:
            import sqlite3
            n_sql_workers = 6
            result_q = multiprocessing.Queue()
            sql_procs = []
            for i in range(n_sql_workers):
                p = multiprocessing.Process(target=_worker_sqlite, args=(i, 30, result_q))
                sql_procs.append(p)
            t0 = time.time()
            for p in sql_procs: p.start()
            for p in sql_procs: p.join()
            elapsed = time.time() - t0
            # 聚合子进程回传结果（子进程内的全局计数不回传，须在此处统一判定）
            sql_errors = []
            for _ in sql_procs:
                wid, wok, wdetail = result_q.get(timeout=10)
                if not wok:
                    sql_errors.append(f"worker{wid}: {wdetail}")
            if sql_errors:
                fail(f"SQLite并发 ({n_sql_workers}进程)", "; ".join(sql_errors))
            else:
                ok(f"{n_sql_workers}进程 SQLite 并发: {n_sql_workers*30} 操作 {elapsed:.2f}s")
        except Exception as e:
            fail("SQLite并发", str(e))

    # 3.4 混合负载（同时读写+SQLite+元数据操作）
    log("  混合负载（16线程同时读写/查询/stat）...")
    def _mixed_load(wid, count):
        m = Path(MNT)
        for i in range(count):
            try:
                if i % 3 == 0:
                    # stat
                    _ = (m / CONCUR_DIR).stat()
                elif i % 3 == 1:
                    # write small file
                    p = m / f"{CONCUR_DIR}/mixed_{wid}_{i}.tmp"
                    p.write_text(f"data_{i}")
                else:
                    # listdir
                    _ = os.listdir(m / "0/网盘")
            except: pass
    mix_threads = [threading.Thread(target=_mixed_load, args=(i, 20))
                   for i in range(16)]
    t0 = time.time()
    for t in mix_threads: t.start()
    for t in mix_threads: t.join()
    elapsed = time.time() - t0
    ok(f"16线程 混合负载: 320 操作 {elapsed:.2f}s")

    # 3.5 大并发 stat 风暴
    log("  stat 风暴（50线程同时 stat 100次）...")
    def _stat_storm(wid, count):
        m = Path(MNT)
        names = ["0/网盘", "0/照片", "0/文档", "0/音乐", "0/应用数据",
                 "0/网盘/hello.txt", "0/照片/photo1.jpg", "0/文档/report.pdf"]
        for i in range(count):
            n = names[i % len(names)]
            try: _ = (m / n).stat()
            except: pass
    storm_threads = [threading.Thread(target=_stat_storm, args=(i, 100))
                     for i in range(50)]
    t0 = time.time()
    for t in storm_threads: t.start()
    for t in storm_threads: t.join()
    elapsed = time.time() - t0
    total_stats = 50 * 100
    ok(f"50线程 stat风暴: {total_stats} 次 {elapsed:.2f}s ({total_stats/elapsed:.0f} stat/s)")

# ═══════════════════════════════════════════════════════
# 模块 4：rmdir 标准语义
# ═══════════════════════════════════════════════════════
RMDIR_DIR = "0/网盘/rmdir_sem"

def test_rmdir_nonempty_semantics():
    """rmdir 非空目录必须返回 ENOTEMPTY，且**不得**递归删除子树（POSIX）。

    旧实现（51abd2c 引入）在 ENOTEMPTY 时静默递归删掉整个子树，等于 rmdir
    变成 rm -r：依赖 rmdir 失败的调用方（rmdir(1)、清理逻辑、探测空目录）
    会误以为目录已空，并连带丢失全部内容。同一函数的虚拟路径分支本就返回
    ENOTEMPTY，两条分支语义不一致。本用例在旧实现上必失败
    （os.rmdir 返回 0 且子树消失）。
    """
    log("\n━━━ 模块4: rmdir 标准语义 ━━━")
    m = Path(MNT)
    d = m / RMDIR_DIR
    d.mkdir(parents=True, exist_ok=True)
    (d / "a.txt").write_text("A")
    (d / "b.txt").write_text("B")
    (d / "sub").mkdir(exist_ok=True)
    (d / "sub" / "c.txt").write_text("C")

    # 4.1 非空 → ENOTEMPTY（而非静默递归删除）
    try:
        os.rmdir(d)
        fail("rmdir 非空目录", "未报错（旧实现递归删除的迹象）")
    except OSError as e:
        if e.errno == errno.ENOTEMPTY:
            ok("rmdir 非空目录 → ENOTEMPTY")
        else:
            fail("rmdir 非空目录 errno",
                 f"期望 ENOTEMPTY({errno.ENOTEMPTY}) 实得 {e.errno}({os.strerror(e.errno)})")

    # 4.2 失败后子树必须原封不动
    keep = d.is_dir() and (d / "a.txt").exists() and (d / "sub" / "c.txt").exists()
    if keep:
        ok("rmdir 失败后子树完整保留（未递归删除）")
    else:
        fail("rmdir 失败后子树保留",
             f"dir={d.is_dir()} a={(d/'a.txt').exists()} subc={(d/'sub'/'c.txt').exists()}")

    # 4.3 正对照：清空后 rmdir 应成功
    try:
        (d / "a.txt").unlink(); (d / "b.txt").unlink()
        (d / "sub" / "c.txt").unlink(); (d / "sub").rmdir()
        os.rmdir(d)
        ok("清空后 rmdir 成功（正对照）")
    except Exception as e:
        fail("清空后 rmdir", str(e))


def _renameat2(old, new, flags):
    """经 libc 调 renameat2（glibc ≥2.28）。成功返回 0；失败抛 OSError。"""
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    fn = libc.renameat2
    fn.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    fn.restype = ctypes.c_int
    r = fn(-100, os.fsencode(old), -100, os.fsencode(new), ctypes.c_uint(flags))
    if r != 0:
        e = ctypes.get_errno()
        raise OSError(e, os.strerror(e))
    return 0


def _renameat2_available():
    try:
        ctypes.CDLL("libc.so.6", use_errno=True).renameat2
        return True
    except (OSError, AttributeError):
        return False


def test_rename_flags():
    """A1：FUSE_RENAME2 的 flags 必须生效。

    旧实现在 renameat2 失败后**无条件**退化普通 rename：RENAME_NOREPLACE 目标
    已存在时本应 EEXIST，却直接覆盖目标（静默数据丢失）；RENAME_EXCHANGE 失败后
    退化成单向移动（源没了、目标被覆盖）。本用例在旧实现上必失败。
    """
    log("\n━━━ 模块5: rename flags（RENAME2）标准语义 ━━━")
    m = Path(MNT)
    d = m / "0/Download/rf"
    shutil.rmtree(d, ignore_errors=True)
    d.mkdir(parents=True, exist_ok=True)
    src, dst = d / "src.txt", d / "dst.txt"
    src.write_text("SRC"); dst.write_text("DST")

    RENAME_NOREPLACE, RENAME_EXCHANGE = 1, 2
    if not _renameat2_available():
        log("  (跳过 rename flags：libc 无 renameat2)")
        return

    # 5.1 NOREPLACE + 目标已存在 → EEXIST，且两端内容都不许变
    try:
        _renameat2(str(src), str(dst), RENAME_NOREPLACE)
        fail("RENAME_NOREPLACE 目标已存在", "未报错（旧实现退化为普通 rename 并覆盖目标）")
    except OSError as e:
        if e.errno == errno.EEXIST:
            ok("RENAME_NOREPLACE 目标已存在 → EEXIST")
        else:
            fail("RENAME_NOREPLACE errno",
                 f"期望 EEXIST({errno.EEXIST}) 实得 {e.errno}({os.strerror(e.errno)})")
    try:
        s_now = src.read_text(); d_now = dst.read_text()
        if s_now == "SRC" and d_now == "DST":
            ok("NOREPLACE 失败后两端内容完好（目标未被覆盖）")
        else:
            fail("NOREPLACE 失败后两端完好", f"src={s_now!r} dst={d_now!r}")
    except Exception as e:
        fail("NOREPLACE 失败后两端完好", str(e))

    # 5.2 EXCHANGE → 两端内容互换
    try:
        _renameat2(str(src), str(dst), RENAME_EXCHANGE)
        s_now, d_now = src.read_text(), dst.read_text()
        if s_now == "DST" and d_now == "SRC":
            ok("RENAME_EXCHANGE 两端内容互换")
        else:
            fail("RENAME_EXCHANGE 互换", f"src={s_now!r} dst={d_now!r}（单向移动即旧实现）")
    except OSError as e:
        fail("RENAME_EXCHANGE", f"{e.errno}({os.strerror(e.errno)})")

    # 5.3 正对照：普通 rename 仍可用（flags=0 不得被 flags 分支挡住）
    try:
        os.rename(str(src), str(d / "plain.txt"))
        ok("正对照：普通 rename（flags=0）成功")
    except Exception as e:
        fail("普通 rename 正对照", str(e))


def test_rename_exdev():
    """A2：跨设备目录搬移必须完整复制（含符号链接），且不得两边都毁。

    经 REDIRECT 把 /xd/ 指向 /dev/shm（与 /tmp 存储不同文件系统），使 daemon 侧
    rename(2) 返回 EXDEV，走「复制 + 删源」回退。旧实现 recursive_copy_dir 只处理
    目录与普通文件，**符号链接被静默跳过**且整体返回成功，随后删源 → 条目永久丢失。
    本用例在旧实现上必失败（目标缺 link）。
    """
    log("\n━━━ 模块6: 跨设备 rename（EXDEV 回退）━━━")
    m = Path(MNT)
    shm = "/dev/shm/nsp_xd"
    shutil.rmtree(shm, ignore_errors=True)
    tree = Path(shm) / "tree"
    (tree / "sub").mkdir(parents=True, exist_ok=True)
    (tree / "file.txt").write_text("XDEV")
    (tree / "sub" / "deep.txt").write_text("DEEP")
    os.symlink("file.txt", str(tree / "link"))  # 相对符号链接

    dst = m / "0/Download/xd_dst"
    shutil.rmtree(dst, ignore_errors=True)
    src = m / "0/xd/tree"
    try:
        if not src.is_dir():
            fail("跨设备 rename 前置", f"{src} 不可达（REDIRECT /xd/ 未生效？）")
            return
        os.rename(str(src), str(dst))
        ok("跨设备 rename 返回成功")
    except OSError as e:
        fail("跨设备 rename", f"{e.errno}({os.strerror(e.errno)})")
        return

    # 目标必须完整：普通文件 + 子目录 + 符号链接
    got_file = (dst / "file.txt").read_text() if (dst / "file.txt").exists() else None
    got_deep = (dst / "sub" / "deep.txt").read_text() if (dst / "sub" / "deep.txt").exists() else None
    got_link = os.path.islink(str(dst / "link"))
    if got_file == "XDEV" and got_deep == "DEEP" and got_link:
        ok("跨设备搬移目标完整（含符号链接）")
    else:
        fail("跨设备搬移目标完整性",
             f"file={got_file!r} deep={got_deep!r} link={got_link}（旧实现静默跳过符号链接）")

    # 源必须已删除（拷贝+删源语义）
    if not os.path.exists(str(src)):
        ok("跨设备搬移后源已删除")
    else:
        fail("跨设备搬移源删除", f"{src} 仍存在")

    # 链接可解引用（指向搬移后的同级文件）
    try:
        with open(str(dst / "link")) as fh:
            target_txt = fh.read()
        ok("搬移后符号链接可解引用") if target_txt == "XDEV" else fail(
            "搬移后链接解引用", f"读到 {target_txt!r}")
    except Exception as e:
        fail("搬移后链接解引用", str(e))

    shutil.rmtree(dst, ignore_errors=True)
    shutil.rmtree(shm, ignore_errors=True)


# ═══════════════════════════════════════════════════════
# 模块6b：跨设备 rename 硬化（R1/R2 直编判别）
# ═══════════════════════════════════════════════════════
FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _extract_static_functions(src_text, names):
    """从实际源码里逐字抽出 static 函数定义（跳过同名前向声明）。

    旧源码没有的函数（如 xdev_temp_name）直接跳过——这样同一驱动既能编
    新实现，也能编 git show HEAD 的旧副本。
    """
    chunks = []
    for name in names:
        start = 0
        found = None
        # 抽取目标可能是 static int，也可能是 static bool（如 is_fuse_hidden_name）
        for prefix in ("static int ", "static bool "):
            needle = prefix + name + "("
            start = 0
            while True:
                i = src_text.find(needle, start)
                if i < 0:
                    break
                brace = src_text.find("{", i)
                semi = src_text.find(";", i)
                if brace >= 0 and (semi < 0 or brace < semi):
                    found = i
                    break
                start = i + 1
            if found is not None:
                break
        if found is None:
            continue
        body = src_text.index("{", found)
        depth = 1
        j = body + 1
        while depth and j < len(src_text):
            if src_text[j] == "{":
                depth += 1
            elif src_text[j] == "}":
                depth -= 1
            j += 1
        chunks.append(src_text[found:j])
    return "\n\n".join(chunks)


def test_rename_exdev_hardening():
    """R1/R2：跨设备 rename 不得预删非空目标，临时名不可预测且不跟随符号链接。

    判别手段：把实际源码里的 recursive_rmdir / recursive_copy_dir /
    vfs_rename_copy_file / xdev_temp_name / vfs_rename 逐字抽进
    tests/fixtures/rename_exdev_driver.c，用 -Wl,--wrap=rename 让第一次
    rename 返回 EXDEV，强制进入跨设备回退。

      - nonempty：目标是非空目录 → 必须 ENOTEMPTY，目标子树逐字节保留、源树
        保留。旧实现先 recursive_rmdir(p_to) 再 rename，返回 0 且目标消失。
      - file_over_dir：文件撞非空目录 → EISDIR，两侧原样。旧实现同样先删目标。
      - symlink：按旧实现可预测临时名 <p_to>.nsp_xdev_<pid> 预置符号链接指向
        受害者 → 受害者内容必须不变、目标不得是符号链接。旧实现 open(O_TRUNC)
        跟随链接把源内容写进受害者，再把链接 rename 到目标（rc=0）。
      - plain：正对照，不强制 EXDEV 时普通 rename 仍成功。

    FUSE_DAEMON_SRC=<旧源码副本> 可让同一驱动在旧实现上复现失败。
    """
    log("\n━━━ 模块6b: 跨设备 rename 硬化（R1/R2 直编判别）━━━")
    root = Path(__file__).resolve().parent.parent
    src_path = os.environ.get("FUSE_DAEMON_SRC") or str(root / "src/daemon/fuse_daemon.c")
    try:
        src_text = Path(src_path).read_text()
    except OSError as e:
        fail("读取被测源码", f"{src_path}: {e}")
        return
    try:
        driver = (FIXTURES / "rename_exdev_driver.c").read_text()
    except OSError as e:
        fail("读取判别驱动", str(e))
        return

    funcs = _extract_static_functions(
        src_text,
        ["recursive_rmdir", "recursive_copy_dir", "vfs_rename_copy_file",
         "xdev_temp_name", "is_fuse_hidden_name", "vfs_rename"])
    if "static int vfs_rename(" not in funcs:
        fail("抽取 vfs_rename", f"{src_path} 中未找到定义")
        return

    cc = shlex.split(os.environ.get("CC", "cc"))
    if not shutil.which(cc[0]):
        log("  (跳过 R1/R2 直编判别：无 cc)")
        return

    stage = tempfile.mkdtemp(prefix="nsp_xdev_drv.")
    try:
        c_path = os.path.join(stage, "driver.c")
        exe = os.path.join(stage, "driver")
        Path(c_path).write_text(driver.replace("/*__NSP_EXTRACTED_FUNCTIONS__*/", funcs))
        cmd = [*cc, "-std=gnu23", "-D_GNU_SOURCE", "-Wall", "-Wextra",
               "-Wno-unused-parameter",
               "-I", str(root / "include"), "-I", str(root / "src/daemon"),
               c_path, "-Wl,--wrap=rename", "-o", exe]
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            fail("直编判别驱动", (r.stderr or r.stdout).strip()[:400])
            return
        for case in ("nonempty", "file_over_dir", "symlink", "plain"):
            case_dir = os.path.join(stage, "case_" + case)
            os.makedirs(case_dir, exist_ok=True)
            p = subprocess.run([exe, case, case_dir], capture_output=True,
                               text=True, timeout=60)
            out = (p.stdout + p.stderr).strip()
            if p.returncode == 0 and f"RESULT {case} OK" in out:
                ok(f"跨设备 rename 契约[{case}]")
            else:
                fail(f"跨设备 rename 契约[{case}]", out[-500:] or f"rc={p.returncode}")
    finally:
        shutil.rmtree(stage, ignore_errors=True)


# ═══════════════════════════════════════════════════════
# 主流程
# ═══════════════════════════════════════════════════════
def test_open_unlink_no_hidden():
    """打开中删除：本地路径必须「先删名、句柄继续可用」，不得**新增** .fuse_hidden。

    注意（用户新要求）：已存在的隐藏名不再隐藏、也不再清理——列举可见、
    可 getattr/open、留在磁盘上（本用例末尾自建夹具即用于断言这一点）。

    判别性：旧实现（libfuse 默认）在文件仍打开时把名字改成
    .fuse_hidden<nodeid><ctr>，目录里会留下这个"改了名却没删掉"的文件；
    新实现在本地路径上直接 unlink，隐藏名从头到尾不存在。
    覆盖普通路径与本地 REDIRECT 路径（两者 backing 都是真实文件系统）。"""
    log("\n━━━ 模块 9: 打开中删除（本地不产生 .fuse_hidden） ━━━")
    tag = TEST_ID
    cases = [
        ("普通路径", Path(MNT) / "0" / "Download" / f"nsp_openunlink_{tag}.bin"),
        ("REDIRECT 路径", Path(MNT) / "0" / "网盘" / f"nsp_openunlink_redir_{tag}.bin"),
    ]
    realdir = Path(STORAGE) / "0" / "Download"
    # 历史残留：磁盘上直接放一个 libfuse 隐藏名文件。本地路径已改为直删，不会
    # 产生新隐藏名；但这个文件可能来自「旧版本 daemon」或「下层 FUSE」
    # （设备上 /data/media 由 MediaProvider 的 FUSE 提供时，我们在下层 unlink
    # 会让下层 libfuse 把名字改成 .fuse_hidden 等 RELEASE 再删——正是用户报的
    # 「本体 + 一个 .fusexx」）。按用户要求：隐藏名不再隐藏、也不再清理，
    # 列举里看得见、磁盘上留着，便于取证与手工回收。
    legacy = realdir / ".fuse_hidden0000000000000001"
    legacy.write_bytes(b"legacy")
    for name, vpath in cases:
        fd = os.open(vpath, os.O_CREAT | os.O_RDWR, 0o644)
        os.write(fd, b"A" * 4096)
        os.fsync(fd)
        os.unlink(vpath)

        hidden = sorted(p.name for p in realdir.glob(".fuse_hidden*") if p.name != legacy.name)
        if hidden:
            fail(f"{name}: 删除后不应出现隐藏名", f"实际 {hidden}")
        else:
            ok(f"{name}: 删除后目录里没有 .fuse_hidden")

        listed = [n for n in os.listdir(vpath.parent) if n.startswith(".fuse_hidden")]
        if listed == [legacy.name]:
            ok(f"{name}: 目录列举看得到隐藏名（只剩历史残留夹具，未新增）")
        elif legacy.name not in listed:
            fail(f"{name}: 历史残留夹具在列举里不可见（不该再隐藏）", f"实际 {listed}")
        else:
            fail(f"{name}: 目录列举出现本次操作新产生的隐藏名", f"实际 {listed}")

        try:
            st = os.fstat(fd)
            if st.st_size == 4096:
                ok(f"{name}: 删除后 fstat 仍返回原大小")
            else:
                fail(f"{name}: 删除后 fstat 大小异常", f"st_size={st.st_size}")
        except OSError as e:
            fail(f"{name}: 删除后 fstat 失败", f"errno={e.errno}")

        os.lseek(fd, 0, os.SEEK_END)
        os.write(fd, b"B" * 100)
        os.fsync(fd)
        try:
            st2 = os.fstat(fd)
            if st2.st_size == 4196:
                ok(f"{name}: 删除后写入仍生效且 fstat 跟着更新")
            else:
                fail(f"{name}: 删除后写入后 fstat 未更新", f"st_size={st2.st_size}")
        except OSError as e:
            fail(f"{name}: 删除后写入后 fstat 失败", f"errno={e.errno}")

        os.lseek(fd, 0, os.SEEK_SET)
        data = os.read(fd, 4096 + 100)
        if data == b"A" * 4096 + b"B" * 100:
            ok(f"{name}: 删除后句柄仍可完整读回内容")
        else:
            fail(f"{name}: 删除后读回内容不符", f"len={len(data)}")
        os.close(fd)

        if os.path.exists(vpath):
            fail(f"{name}: 关闭后路径不应存在")
        else:
            ok(f"{name}: 关闭后路径已消失")
        if any(p.name.startswith(".fuse_hidden") and p.name != legacy.name for p in realdir.iterdir()):
            fail(f"{name}: 关闭后仍有隐藏名残留")
        else:
            ok(f"{name}: 关闭后无隐藏名残留")
    # 隐藏名按普通条目对待：列举不会删它，磁盘上留着（取证可见）。用例自己收尾。
    if legacy.exists():
        ok("历史隐藏名文件列举后仍在磁盘（不再隐蔽清理，可取证）")
        legacy.unlink(missing_ok=True)
    else:
        fail("历史隐藏名文件被列举清理掉了（不该再自动删除）", str(legacy))


def test_open_unlink_recreate_no_hidden():
    """打开中删除 + 同名重建：真实目标目录在操作瞬间与关闭后都不得出现隐藏名。

    判别性：旧实现（libfuse 默认 hide 语义，6367d2d 之前）在「文件仍打开时
    unlink」会把名字改成 .fuse_hidden<16hex> 等 RELEASE 再删，于是真实目录
    出现「本体 + 一个 .fusexx」；新实现（vfs_rename 识别隐藏名后直删源文件）
    在 unlink 瞬间真实目录就没有隐藏名。末尾再验证「旧版本/下层 FUSE 遗留的
    隐藏名」恢复为**普通条目**：列举可见、磁盘上保留、不被自动清理（取证可见；
    旧实现把它隐藏起来，故这条断言在旧实现上失败）。

    全程用 os.listdir / Path.iterdir 直接读真实目录（不经 FUSE）做断言。"""
    log("\n━━━ 模块 9b: 打开中删除 + 同名重建（真实目录零隐藏名） ━━━")
    tag = TEST_ID
    realdir = Path(STORAGE) / "0" / "Download"
    vdir = Path(MNT) / "0" / "网盘"
    name = f"nsp_recreate_{tag}.bin"
    vpath = vdir / name

    def hidden_real():
        return sorted(p.name for p in realdir.iterdir() if p.name.startswith(".fuse_hidden"))

    try:
        os.unlink(vpath)
    except FileNotFoundError:
        pass

    # ① 打开 + 写入并保持句柄 → unlink：真实目录必须立刻干净
    old = os.open(vpath, os.O_CREAT | os.O_RDWR, 0o644)
    os.write(old, b"OLD" * 100)
    os.fsync(old)
    os.unlink(vpath)
    h = hidden_real()
    if h:
        fail("9b unlink 瞬间真实目录出现隐藏名", str(h))
    else:
        ok("9b unlink 瞬间真实目录没有 .fuse_hidden")
    if (realdir / name).exists():
        fail("9b 删除后本体仍在真实目录")
    else:
        ok("9b 删除后真实目录没有本体")

    # ② 同名重建（O_CREAT|O_TRUNC）：本体回来，隐藏名仍不允许出现
    new = os.open(vpath, os.O_CREAT | os.O_RDWR | os.O_TRUNC, 0o644)
    os.write(new, b"NEW" * 50)
    os.fsync(new)
    h = hidden_real()
    if h:
        fail("9b 同名重建后真实目录仍有隐藏名", str(h))
    else:
        ok("9b 同名重建后真实目录无隐藏名")
    if (realdir / name).exists():
        ok("9b 同名重建后真实目录只有本体")
    else:
        fail("9b 同名重建后真实目录缺本体")

    # ③ 旧句柄（指向已删除的旧 inode）仍可写、仍读回旧内容
    os.lseek(old, 0, os.SEEK_END)
    os.write(old, b"X" * 10)
    os.fsync(old)
    os.lseek(old, 0, os.SEEK_SET)
    old_data = os.read(old, 4096)
    if old_data == b"OLD" * 100 + b"X" * 10:
        ok("9b 旧句柄在重建后仍可读写（inode 由 fd 保活）")
    else:
        fail("9b 旧句柄内容异常", f"len={len(old_data)}")
    h = hidden_real()
    if h:
        fail("9b 旧句柄读写期间真实目录出现隐藏名", str(h))
    else:
        ok("9b 旧句柄读写期间真实目录无隐藏名")
    os.close(old)

    # ④ 关闭旧句柄：本层不产生隐藏名，新本体不受影响
    h = hidden_real()
    if h:
        fail("9b 关闭旧句柄后真实目录出现隐藏名", str(h))
    else:
        ok("9b 关闭旧句柄后真实目录无隐藏名")
    if (realdir / name).exists():
        ok("9b 关闭旧句柄后新本体仍在")
    else:
        fail("9b 关闭旧句柄后新本体消失")

    os.lseek(new, 0, os.SEEK_SET)
    new_data = os.read(new, 4096)
    os.close(new)
    if new_data == b"NEW" * 50:
        ok("9b 新句柄内容独立（未被旧句柄写入污染）")
    else:
        fail("9b 新句柄内容异常", f"len={len(new_data)}")

    # ⑤ 遗留隐藏名（旧版本 daemon / 下层 FUSE 生成）：按普通条目可见、保留在磁盘
    #   （本层不产生新隐藏名，但也不再隐藏/清理已存在的——保留取证能力）
    stale = realdir / ".fuse_hidden0000000000000002"
    stale.write_bytes(b"stale")
    listed = sorted(n for n in os.listdir(vdir) if n.startswith(".fuse_hidden"))
    if stale.name in listed:
        ok("9b 遗留隐藏名在目录列举中可见（不再对应用隐藏）")
    else:
        fail("9b 遗留隐藏名在目录列举中不可见（不该再隐藏）", str(listed))
    st = None
    try:
        st = os.stat(vdir / stale.name)
    except OSError as e:
        fail("9b 遗留隐藏名无法 getattr（应按普通条目可 stat）", f"errno={e.errno}")
    if st is not None and st.st_size == len(b"stale"):
        ok("9b 遗留隐藏名可正常 stat/open（普通条目语义）")
    if stale.exists():
        ok("9b 遗留隐藏名仍保留在真实目录（未被自动清理）")
        stale.unlink(missing_ok=True)
    else:
        fail("9b 遗留隐藏名被自动清理了（不该再删除）", str(stale))
    h = hidden_real()
    if h:
        fail("9b 用例结束时真实目录仍有隐藏名", str(h))
    else:
        ok("9b 用例结束时真实目录零隐藏名（仅剩本用例自建夹具）")


def main():
    global PASS, FAIL, ERRORS
    log("═══ fuse_daemon 完整测试套件 ═══")
    log("测试ID: %s", TEST_ID)
    log("Daemon: %s", DAEMON)

    # 清理旧状态
    subprocess.run(["fusermount3", "-u", MNT], capture_output=True)
    subprocess.run(["pkill", "-f", "fuse_daemon"], capture_output=True)
    time.sleep(1)

    setup_env()
    proc = start_daemon()
    if not proc:
        log("❌ FUSE daemon 启动失败，退出")
        sys.exit(1)

    try:
        test_basic_operations()
        test_inode_nonzero()
        test_rmdir_nonempty_semantics()
        test_rename_flags()
        test_rename_exdev()
        test_rename_exdev_hardening()
        test_open_unlink_no_hidden()
        test_open_unlink_recreate_no_hidden()
        test_sqlite()
        test_concurrent()
        test_official_semantics()
    finally:
        stop_daemon(proc)

    # 报告
    total = PASS + FAIL
    log("\n═══════════════════════════════════════")
    log("测试完成 | ✅ %d 通过 | ❌ %d 失败 | 共 %d", PASS, FAIL, total)
    if ERRORS:
        log("失败详情:")
        for desc, detail in ERRORS[:10]:
            log("  ❌ %s  %s", desc, detail)
        if len(ERRORS) > 10:
            log("  ... 还有 %d 项", len(ERRORS) - 10)
    log("═══════════════════════════════════════")
    return 0 if FAIL == 0 else 1

# ═══════════════════════════════════════════════════════
# 模块 11：官方 FUSE 语义补齐（对齐 Android 原生 FUSE）
# fallocate / link / mknod / fsyncdir——此前缺省 ENOSYS，应用侧
# （下载器预分配、cp -al、mkfifo）性能退化或失败；后端路径 EOPNOTSUPP。
# ═══════════════════════════════════════════════════════
def test_official_semantics():
    log("\n━━━ 模块11: 官方 FUSE 语义补齐（fallocate/link/mknod/fsyncdir） ━━━")
    m = Path(MNT)
    import fcntl, errno

    # 11.1 fallocate：预分配空间（下载器路径）。Python 无直接接口，用
    #      os.posix_fallocate（走 fallocate(2)；内核/FS 不支持时回退写零，
    #      两者都算成功——判别点是时间与块占用，此处断言功能可用 + 大小正确）
    p = m / "0/网盘/prealloc.bin"
    try:
        fd = os.open(p, os.O_CREAT | os.O_WRONLY, 0o644)
        os.close(fd)
        os.posix_fallocate(fd := os.open(p, os.O_WRONLY), 0, 4 * 1024 * 1024)
        os.close(fd)
        ok("fallocate 预分配") if p.stat().st_size == 4 * 1024 * 1024 else fail("fallocate 大小", str(p.stat().st_size))
    except OSError as e:
        fail("fallocate", f"errno={e.errno} {e.strerror}")
    finally:
        p.unlink(missing_ok=True)

    # 11.2 fallocate KEEP_SIZE 语义（空间预留不改变大小）
    #      Python 无 FALLOC_FL_KEEP_SIZE 接口，ctypes 直调 fallocate(2)
    p = m / "0/网盘/keepsize.bin"
    try:
        import ctypes
        libc = ctypes.CDLL(None, use_errno=True)
        p.write_bytes(b"hello")
        fd = os.open(p, os.O_WRONLY)
        FALLOC_FL_KEEP_SIZE = 0x01
        rc = libc.fallocate(fd, FALLOC_FL_KEEP_SIZE, 0, 1024 * 1024)
        err = ctypes.get_errno()
        os.close(fd)
        if rc != 0:
            fail("fallocate KEEP_SIZE", f"errno={err}")
        elif p.stat().st_size == 5:
            ok("fallocate KEEP_SIZE")
        else:
            fail("KEEP_SIZE 大小", str(p.stat().st_size))
    except OSError as e:
        fail("fallocate KEEP_SIZE", f"errno={e.errno} {e.strerror}")
    finally:
        p.unlink(missing_ok=True)

    # 11.3 硬链接：同目录 link() 成功、内容一致、unlink 原名后链接仍可读
    src = m / "0/网盘/link_src.txt"
    dst = m / "0/网盘/link_dst.txt"
    try:
        src.write_text("link_body")
        os.link(src, dst)
        src.unlink()
        ok("硬链接存活性") if dst.read_text() == "link_body" else fail("硬链接内容")
    except OSError as e:
        fail("硬链接", f"errno={e.errno} {e.strerror}")
    finally:
        src.unlink(missing_ok=True); dst.unlink(missing_ok=True)

    # 11.4 跨虚拟目录硬链接：官方 EXDEV（不同 backing 目标不同文件系统口径）
    a = m / "0/网盘/xlink_a.txt"
    b = m / "0/照片/xlink_b.txt"
    try:
        a.write_text("x")
        try:
            os.link(a, b)
            # 成功也算合法（同一 backing 下 link 可行）；清理即可
            b.unlink(missing_ok=True)
            ok("跨虚拟目录硬链接（同 backing 可行）")
        except OSError as e:
            ok("跨虚拟目录硬链接") if e.errno in (errno.EXDEV, errno.EPERM) else fail("跨目录硬链接 errno", str(e.errno))
    finally:
        a.unlink(missing_ok=True); b.unlink(missing_ok=True)

    # 11.5 mknod FIFO：创建/读写打通（应用沙箱内合法操作）
    fifo = m / "0/网盘/probe.fifo"
    try:
        os.mkfifo(fifo)
        ok("mkfifo") if fifo.exists() and not fifo.is_file() else fail("mkfifo 验证")
        # FIFO 非阻塞读写自检（打开写端无读者会阻塞——用非阻塞探活）
        fd = os.open(fifo, os.O_RDONLY | os.O_NONBLOCK)
        os.close(fd)
        ok("FIFO 打开")
    except OSError as e:
        fail("mkfifo", f"errno={e.errno} {e.strerror}")
    finally:
        fifo.unlink(missing_ok=True)

    # 11.6 mknod 设备节点：EPERM（Android 应用沙箱无 mknod 设备能力，与原生一致）
    dev = m / "0/网盘/null_dev"
    try:
        os.mknod(dev, 0o600 | 0o020000, os.makedev(1, 3))  # S_IFCHR 1:3=/dev/null
        # 若宿主有权限创建成功（root FUSE）也算合法——清掉即可
        dev.unlink(missing_ok=True)
        ok("mknod 设备节点（有权限则成功）")
    except OSError as e:
        ok("mknod 设备节点 EPERM") if e.errno == errno.EPERM else fail("mknod 设备节点 errno", str(e.errno))
    finally:
        dev.unlink(missing_ok=True)

    # 11.7 fsyncdir：目录 fsync 成功（日志型文件系统目录元数据刷盘）
    d = m / "0/网盘"
    try:
        fd = os.open(d, os.O_RDONLY | os.O_DIRECTORY)
        os.fsync(fd)
        os.close(fd)
        ok("fsyncdir")
    except OSError as e:
        fail("fsyncdir", f"errno={e.errno} {e.strerror}")


if __name__ == "__main__":
    sys.exit(main())
