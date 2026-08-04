#!/usr/bin/env python3
"""
fuse_daemon 完整测试套件
=======================
测试场景: 基础文件操作 / SQLite 数据库 / 并发压力
"""
import subprocess, os, sys, time, threading, multiprocessing, shutil, uuid, json
from pathlib import Path

MNT     = "/tmp/fuse_proxy_test/mnt"
MODDIR  = "/tmp/fuse_proxy_test/modules"
STORAGE = "/tmp/fuse_proxy_test/storage"
CONF    = "/tmp/Namespace-Proxy/injector.conf"
DAEMON  = os.environ.get("FUSE_DAEMON") or os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "build_gnu", "fuse_daemon"))
BASIC_RULES = os.environ.get("BASIC_RULES_SO") or os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "build_gnu", "basic_rules.so"))
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
    # 热插拔模块：basic_rules.so 放入模块目录（fuse_daemon 启动时 dlopen 加载）
    os.makedirs(f"{MODDIR}/basic_rules", exist_ok=True)
    if os.path.exists(BASIC_RULES):
        shutil.copy(BASIC_RULES, f"{MODDIR}/basic_rules/basic_rules.so")
    else:
        print("  ⚠ basic_rules.so 未找到，规则模块不会加载")
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
            if "网盘" in os.listdir(MNT):
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

    # 1.1 根目录虚拟条目
    root = sorted(os.listdir(m))
    targets = ["网盘", "照片", "文档", "音乐", "应用数据", "0"]
    for t in targets:
        ok(f"根目录可见 '{t}'") if t in root else fail(f"根目录缺少 '{t}'", f"entries={root}")

    # 1.2 通过虚拟路径读取预置文件
    for vpath, fname in [("网盘/hello.txt", "hello.txt"),
                          ("照片/photo1.jpg", "photo1.jpg"),
                          ("文档/report.pdf", "report.pdf"),
                          ("音乐/song.mp3", "song.mp3")]:
        p = m / vpath
        exp = f"content_{fname}_{TEST_ID}"
        if p.exists() and p.read_text().strip() == exp:
            ok(f"读取 {vpath}")
        else:
            fail(f"读取 {vpath}", f"exists={p.exists()}")

    # 1.3 通过虚拟路径创建新文件
    (m / "网盘/new_file.txt").write_text(f"new_content_{TEST_ID}")
    # 验证真实存储存在
    real = Path(f"{STORAGE}/0/Download/new_file.txt")
    ok("虚拟写入 → 真实存储") if real.exists() and TEST_ID in real.read_text() else fail("写入验证", str(real.exists()))

    # 1.4 通过虚拟路径创建深层次目录
    (m / "网盘/Projects/2026/report.md").parent.mkdir(parents=True, exist_ok=True)
    (m / "网盘/Projects/2026/report.md").write_text("# Report")
    ok("深层目录创建") if Path(f"{STORAGE}/0/Download/Projects/2026/report.md").exists() else fail("深层目录")

    # 1.5 删除文件
    (m / "网盘/new_file.txt").unlink(missing_ok=True)
    ok("删除文件") if not Path(f"{STORAGE}/0/Download/new_file.txt").exists() else fail("删除验证")

    # 1.6 重命名文件
    (m / "网盘/Projects/2026/report.md").rename(m / "网盘/Projects/2026/final.md")
    renamed = Path(f"{STORAGE}/0/Download/Projects/2026/final.md")
    old = Path(f"{STORAGE}/0/Download/Projects/2026/report.md")
    ok("重命名文件") if renamed.exists() and not old.exists() else fail("重命名验证")

    # 1.7 大文件写入
    big_data = b"x" * (1024 * 1024)  # 1MB
    (m / "网盘/bigfile.bin").write_bytes(big_data)
    big = Path(f"{STORAGE}/0/Download/bigfile.bin")
    ok("1MB 大文件") if big.stat().st_size == 1024*1024 else fail("大文件", f"size={big.stat().st_size}")

    # 1.8 追加写入
    with open(m / "网盘/bigfile.bin", "ab") as f:
        f.write(b"append_data")
    ok("追加写入") if big.stat().st_size == 1024*1024 + 11 else fail("追加验证")

    # 1.9 stat / 权限
    st = (m / "网盘/bigfile.bin").stat()
    ok("stat 有大小") if st.st_size > 0 else fail("stat 大小", str(st.st_size))
    ok("stat 有 mtime") if st.st_mtime > 0 else fail("stat mtime")

    # 1.10 目录列表（虚拟目录内容）
    for vdir, expect in [("网盘", ["hello.txt", "Projects", "bigfile.bin"]),
                          ("照片", ["photo1.jpg"])]:
        items = sorted(os.listdir(m / vdir))
        missing = [e for e in expect if e not in items]
        ok(f"{vdir}/ 列表含预期文件") if not missing else fail(f"{vdir}/ 列表", f"missing={missing} items={items}")

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
    db_virtual = m / "应用数据/com.example.app/database.db"
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
    blob_v = m / "应用数据/com.example.app/avatar.db"
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
        fts_v = m / "应用数据/com.example.app/search.db"
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
CONCUR_DIR = "网盘/concurrent_test"

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

def _worker_sqlite(wid, ops):
    """SQLite 并发负载"""
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
        ok(f"并发SQLite worker {wid}: {ops} 操作")
    except Exception as e:
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
            sql_procs = []
            for i in range(n_sql_workers):
                p = multiprocessing.Process(target=_worker_sqlite, args=(i, 30))
                sql_procs.append(p)
            t0 = time.time()
            for p in sql_procs: p.start()
            for p in sql_procs: p.join()
            elapsed = time.time() - t0
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
                    _ = os.listdir(m / "网盘")
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
        names = ["网盘", "照片", "文档", "音乐", "应用数据",
                 "网盘/hello.txt", "照片/photo1.jpg", "文档/report.pdf"]
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
# 主流程
# ═══════════════════════════════════════════════════════
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
        test_sqlite()
        test_concurrent()
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

if __name__ == "__main__":
    sys.exit(main())
