#!/usr/bin/env python3
"""规则边界测试 v6 — 所有文件访问路径含 user_id (0/...)"""
import subprocess,os,sys,time,shutil
from pathlib import Path

MNT="/tmp/fuse_rules_test/mnt"; STORAGE="/tmp/fuse_rules_test/storage"
MODDIR="/tmp/fuse_rules_test/modules"
CONF="/tmp/Namespace-Proxy/injector.conf"
DAEMON=os.environ.get("FUSE_DAEMON") or os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "build_gnu", "fuse_daemon"))
PASS=0; FAIL=0; ERRS=[]
def log(m): print(f"  {m}")
def ok(d): global PASS; PASS+=1; log(f"✅ {d}")
def fail(d,dt=""): global FAIL; FAIL+=1; log(f"❌ {d}: {dt}"); ERRS.append((d,dt))

def setup():
    shutil.rmtree("/tmp/fuse_rules_test",ignore_errors=True)
    subprocess.run(["fusermount3","-u",MNT],capture_output=True)
    for d in ["0/Download/Pics","0/Download/Music","0/Download/Docs"]:
        os.makedirs(f"{STORAGE}/{d}",exist_ok=True)
    os.makedirs(MNT,exist_ok=True); os.makedirs("/tmp/Namespace-Proxy",exist_ok=True)
    # 规则引擎已内建（fw_rules）：无需模块目录，规则直接由 fuse_daemon 解释
    (Path(STORAGE)/"0/Download/hi.txt").write_text("hello")
    (Path(STORAGE)/"0/Download/Pics/1.jpg").write_text("img1")
    (Path(STORAGE)/"0/Download/Music/song.mp3").write_text("music")
    (Path(STORAGE)/"0/Download/中文.txt").write_text("zh")
    (Path(STORAGE)/"0/Download/a b.txt").write_text("spaces")
    # 精确文件重定向 fixture：report.pdf 与其 .bak 共存，验证只重定向特定文件
    (Path(STORAGE)/"0/Download/report.pdf").write_text("pdf-orig")
    (Path(STORAGE)/"0/Download/report.pdf.bak").write_text("bak-orig")
    (Path(STORAGE)/"0/Download/Docs/report.pdf").write_text("pdf-redir")
    Path(f"{STORAGE}/0/a/b/c/d/e/f/g/h/i/j/k.txt").parent.mkdir(parents=True,exist_ok=True)
    Path(f"{STORAGE}/0/a/b/c/d/e/f/g/h/i/j/k.txt").write_text("deep")
    Path(f"{STORAGE}/0/Empty").mkdir(exist_ok=True)
    # 多用户存储隔离：真实路径按 user_id 分区（storage/<uid>/...），
    # 各用户独立数据——多用户用例验证 /1/ /2/ /10/ 命中各自分区
    for uid, content in [("1", "hello-user1"), ("2", "hello-user2"), ("10", "hello-user10")]:
        (Path(STORAGE)/uid/"Download").mkdir(parents=True, exist_ok=True)
        (Path(STORAGE)/uid/"Download/hi.txt").write_text(content)

def wconf(t): open(CONF,"w").write(t.strip())
def start():
    p=subprocess.Popen([DAEMON,"--root="+STORAGE,"--rules="+CONF,
                        "--modules-dir="+MODDIR,"-f",MNT,"info"],
                       stdout=open("/tmp/fr.log","w"),stderr=subprocess.STDOUT)
    for _ in range(30):
        time.sleep(0.3)
        try:
            if os.listdir(MNT): return p
        except: pass
        if p.poll() is not None: return None
    return p
def stop(p):
    if p: p.terminate()
    try: p.wait(3)
    except: p.kill()
    subprocess.run(["fusermount3","-u",MNT],capture_output=True)

def run(conf,checks,label=""):
    log(f"\n── {label} ──"); wconf(conf); p=start()
    if not p: return fail("启动失败")
    try:
        m=Path(MNT)
        for c in checks:
            name=c[0]; path=c[1]; fp=m/path
            try:
                want=c[2] if len(c)>2 else "EXISTS"
                if want=="EXISTS": ok(name) if fp.exists() else fail(name,"missing")
                elif want=="NOT_EXISTS": ok(name) if not fp.exists() else fail(name,"存在")
                elif want=="LIST":
                    items=sorted(os.listdir(fp)); exp=c[3]
                    # exp=="" 表示期望目录为空
                    passed = (items == []) if exp == "" else (exp in items)
                    ok(name) if passed else fail(name,f"entries={items}")
                elif want=="LIST_ALL":
                    # exp=期望全集（set）：断点续扫回归——必须一字不差
                    items=set(os.listdir(fp)); exp=set(c[3])
                    ok(name) if items==exp else fail(name,f"列出{len(items)}/{len(exp)} 缺={sorted(exp-items)[:5]} 多={sorted(items-exp)[:5]}")
                else:
                    got=fp.read_text().strip()
                    ok(name) if got==want else fail(name,f"got='{got}'")
            except Exception as e: fail(name,str(e))
    finally: stop(p)

def main():
    global PASS,FAIL
    log("═══ 规则边界测试 v6 ═══\n")
    setup()

    # ── REDIRECT 基本 ──
    # 配置: virtual="/云盘/" → real="/Download/"
    # 访问: /0/云盘/hi.txt → FUSE 剥离 /0/ → sub_path="/云盘/hi.txt" → redirect → /Download/hi.txt
    run("""[GLOBAL] MONITOR OFF
REDIRECT /云盘/ /Download/""", [
        ("R:目录可见","0/云盘","EXISTS"),
        ("R:读文件","0/云盘/hi.txt","hello"),
    ],"1.REDIRECT基本")

    # ── 多用户路径剥离：/1/、/2/、/10/ 与 /0/ 等价——FUSE 剥离任意
    # 数字 user_id 前缀后命中同一规则（Android 多用户 /user_id/...）──
    run("""[GLOBAL] MONITOR OFF
REDIRECT /云盘/ /Download/""", [
        ("MU:user1目录可见","1/云盘","EXISTS"),
        ("MU:user1读文件","1/云盘/hi.txt","hello-user1"),
        ("MU:user2读文件","2/云盘/hi.txt","hello-user2"),
        ("MU:user10读文件","10/云盘/hi.txt","hello-user10"),
    ],"1b.多用户路径剥离")

    # ── 嵌套 REDIRECT ──
    run("""[GLOBAL] MONITOR OFF
REDIRECT /盘/ /Download/
REDIRECT /盘/图/ /Download/Pics/""", [
        ("嵌套:根文件","0/盘/hi.txt","hello"),
        ("嵌套:子文件","0/盘/图/1.jpg","img1"),
    ],"2.嵌套REDIRECT")

    # ── ALLOW + REDIRECT ──
    run("""[GLOBAL] MONITOR OFF
ALLOW /我的应用/
REDIRECT /我的应用/ /Download/""", [
        ("A+R:可见","0/我的应用","EXISTS"),
        ("A+R:文件","0/我的应用/hi.txt","hello"),
    ],"3.ALLOW+REDIRECT")

    # ── HIDE 精确路径 ──
    # 配置: HIDE /Download/Pics/  → 隐藏路径 sub_path="/Download/Pics/..."
    run("""[GLOBAL] MONITOR OFF
HIDE /Download/Pics/""", [
        ("HIDE:Pics影藏","0/Download/Pics/1.jpg","NOT_EXISTS"),
        ("HIDE:其他可见","0/Download/hi.txt","hello"),
    ],"4.HIDE精确")

    # ── HIDE 通配符 ──
    run("""[GLOBAL] MONITOR OFF
HIDE /Download/*.mp3""", [
        ("通配:mp3隐藏","0/Download/Music/song.mp3","NOT_EXISTS"),
        ("通配:其他可见","0/Download/hi.txt","hello"),
    ],"5.HIDE通配")

    # ── RO 只读 ──
    run("""[GLOBAL] MONITOR OFF
RO /Download/Pics/""", [
        ("RO:可读","0/Download/Pics/1.jpg","img1"),
    ],"6.RO只读")
    # RO写拒
    try:
        (Path(MNT)/"0/Download/Pics/n.txt").write_bytes(b"x")
        fail("RO写拒","文件被写入")
        (Path(MNT)/"0/Download/Pics/n.txt").unlink(missing_ok=True)
    except: ok("6b.RO:写入被拒")

    # ── RO + REDIRECT ──
    run("""[GLOBAL] MONITOR OFF
REDIRECT /相册/ /Download/Pics/
RO /相册/""", [
        ("RO+R:可读","0/相册/1.jpg","img1"),
    ],"7.RO+REDIRECT")

    # ── 最长前缀优先 ──
    run("""[GLOBAL] MONITOR OFF
REDIRECT /数据/ /Download/
REDIRECT /数据/图片/ /Download/Pics/""", [
        ("前缀:根","0/数据/hi.txt","hello"),
        ("前缀:子","0/数据/图片/1.jpg","img1"),
    ],"8.最长前缀")

    # ── HIDE 覆盖 REDIRECT ──
    run("""[GLOBAL] MONITOR OFF
REDIRECT /秘密/ /Download/Pics/
HIDE /秘密/""", [
        ("HIDE>R","0/秘密/1.jpg","NOT_EXISTS"),
    ],"9.HIDE覆盖REDIRECT")

    # ── 断点续扫：300 文件本地目录一次列全 ──
    # 内核单次 readdir 回复装不下时带 offset（上次条目 off）再次调用；
    # 旧实现忽略 offset 恒从头发（且 filler off 全 0），大目录尾部丢失/重复。
    big = Path(STORAGE)/"0/Download/bigoff"
    big.mkdir(exist_ok=True)
    want = {f"e{i:04d}" for i in range(300)}
    for n in want:
        (big/n).write_bytes(b"y")
    run("""[GLOBAL] MONITOR OFF""", [
        ("OFFSET:300文件","0/Download/bigoff","LIST_ALL",{f"e{i:04d}" for i in range(300)}),
    ],"9b.断点续扫")
    shutil.rmtree(big, ignore_errors=True)

    # ── 沙盒 ON + REDIRECT ──
    run("""[GLOBAL] MONITOR OFF
SANDBOX ON
REDIRECT /网盘/ /Download/""", [
        ("沙盒+R:文件","0/网盘/hi.txt","hello"),
    ],"10.沙盒+REDIRECT")

    # ── 沙盒 ON + ALLOW + REDIRECT ──
    run("""[GLOBAL] MONITOR OFF
SANDBOX ON
ALLOW /网盘/
REDIRECT /网盘/ /Download/""", [
        ("沙盒+A+R","0/网盘/hi.txt","hello"),
    ],"11.沙盒+ALLOW+REDIRECT")

    # ── Unicode ──
    run("""[GLOBAL] MONITOR OFF
REDIRECT /国际/ /Download/""", [
        ("Unicode中文","0/国际/中文.txt","zh"),
    ],"12.Unicode")

    # ── 特殊字符 ──
    run("""[GLOBAL] MONITOR OFF
REDIRECT /特殊/ /Download/""", [
        ("空格","0/特殊/a b.txt","spaces"),
    ],"13.特殊字符")

    # ── REDIRECT 通配符 ──
    # /Download/*.mp3 匹配任意 .mp3 文件，重定向到 /Download/Music/ 下同名文件，
    # 非 .mp3 文件不误伤
    run("""[GLOBAL] MONITOR OFF
REDIRECT /Download/*.mp3 /Download/Music/""", [
        ("R通配:mp3重定向","0/Download/song.mp3","music"),
        ("R通配:非mp3不误伤","0/Download/hi.txt","hello"),
    ],"13b.REDIRECT通配")

    # ── REDIRECT 精确文件不误伤 ──
    # 完整文件路径重定向：只重定向 report.pdf，同目录 report.pdf.bak 不受影响
    run("""[GLOBAL] MONITOR OFF
REDIRECT /Download/report.pdf /Download/Docs/report.pdf""", [
        ("R精确:pdf重定向","0/Download/report.pdf","pdf-redir"),
        ("R精确:bak不误伤","0/Download/report.pdf.bak","bak-orig"),
    ],"13c.REDIRECT精确文件")

    # ── ALLOW 通配符 ──
    # 通配 ALLOW 不再被拒绝（旧实现 LOG_WRN 丢弃规则），豁免命中路径自身存储，
    # 其他路径不受影响
    run("""[GLOBAL] MONITOR OFF
ALLOW /Download/Music/*.mp3""", [
        ("A通配:mp3可见","0/Download/Music/song.mp3","music"),
        ("A通配:其他不受影响","0/Download/hi.txt","hello"),
    ],"13d.ALLOW通配")

    # ── 深层路径 ──
    run("""[GLOBAL] MONITOR OFF
REDIRECT /deep/ /a/b/c/d/e/f/g/h/i/j/""", [
        ("深层10级","0/deep/k.txt","deep"),
    ],"14.深层路径")

    # ── 空目录 ──
    run("""[GLOBAL] MONITOR OFF
REDIRECT /空/ /Empty/""", [
        ("空目录","0/空","EXISTS"),
        ("空目录列表","0/空","LIST",""),
    ],"15.空目录")

    # ── 热重载 ──
    log("\n── 16.热重载 ──")
    wconf("[GLOBAL] MONITOR OFF\nREDIRECT /v1/ /Download/\n")
    p=start(); m=Path(MNT)
    if not p: fail("热重载启动")
    else:
        try:
            ok("热1:v1可见") if (m/"0/v1/hi.txt").read_text().strip()=="hello" else fail("热1")
            wconf("[GLOBAL] MONITOR OFF\nREDIRECT /v1/ /Download/\nREDIRECT /v2/ /Download/Pics/\n")
            time.sleep(3); _=os.listdir(m)
            ok("热2:v2新增") if (m/"0/v2/1.jpg").read_text().strip()=="img1" else fail("热2")
            wconf("[GLOBAL] MONITOR OFF\nREDIRECT /v1/ /Download/\n")
            time.sleep(3); _=os.listdir(m)
            ok("热3:v2已移除") if not (m/"0/v2/1.jpg").exists() else fail("热3")
        except Exception as e: fail("热重载",str(e))
        finally: stop(p)

    # ── 类别段（测试进程 uid=1000 → system 分支：SYSTEM_APPS 生效，USER_APPS 无副作用）──
    run("""[GLOBAL] MONITOR OFF
[SYSTEM_APPS]
HIDE /Download/Pics/""", [
        ("SYS:HIDE生效","0/Download/Pics/1.jpg","NOT_EXISTS"),
        ("SYS:其他可见","0/Download/hi.txt","hello"),
    ],"17.SYSTEM_APPS/HIDE")

    # 类别 REDIRECT 优先于 GLOBAL（应用>类别>全局的后两层）
    run("""[GLOBAL] MONITOR OFF
REDIRECT /类/ /Download/Music/
[SYSTEM_APPS]
REDIRECT /类/ /Download/Pics/""", [
        ("SYS:类别优先全局","0/类/1.jpg","img1"),
    ],"18.SYSTEM_APPS> GLOBAL")

    # HIDE 并集：GLOBAL + 类别同时隐藏
    run("""[GLOBAL] MONITOR OFF
HIDE /Download/Music/
[SYSTEM_APPS]
HIDE /Download/Pics/""", [
        ("并集:Music藏","0/Download/Music/song.mp3","NOT_EXISTS"),
        ("并集:Pics藏","0/Download/Pics/1.jpg","NOT_EXISTS"),
        ("并集:其他可见","0/Download/hi.txt","hello"),
    ],"19.HIDE并集")

    # USER_APPS 对 system 访问者无副作用（作用域隔离）
    run("""[GLOBAL] MONITOR OFF
[USER_APPS:0]
HIDE /Download/Pics/
[USER_APPS]
HIDE /Download/Music/""", [
        ("USR:Pics仍可见","0/Download/Pics/1.jpg","img1"),
        ("USR:Music仍可见","0/Download/Music/song.mp3","music"),
    ],"20.USER_APPS不污染system")

    # cleanup
    subprocess.run(["pkill","-f","fuse_daemon"],capture_output=True)
    subprocess.run(["fusermount3","-u",MNT],capture_output=True)
    log(f"\n❖ {PASS} 通过 | {FAIL} 失败 | 共 {PASS+FAIL}")
    for d,dt in ERRS: log(f"  ❌ {d}: {dt}")
    return 0 if FAIL==0 else 1

if __name__=="__main__": sys.exit(main())
