#!/usr/bin/env python3
"""规则边界测试 v6 — 所有文件访问路径含 user_id (0/...)"""
import subprocess,os,sys,time,shutil
from pathlib import Path

MNT="/tmp/fuse_rules_test/mnt"; STORAGE="/tmp/fuse_rules_test/storage"
MODDIR="/tmp/fuse_rules_test/modules"
CONF="/tmp/Namespace-Proxy/injector.conf"
ROOT=os.path.abspath(os.path.join(os.path.dirname(__file__),".."))
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
    # 作用域优先级 fixture：同一虚拟前缀在不同作用域指向不同目标（内容可区分）
    (Path(STORAGE)/"0/PrioA").mkdir(exist_ok=True)
    (Path(STORAGE)/"0/PrioB").mkdir(exist_ok=True)
    (Path(STORAGE)/"0/PrioA/prio.txt").write_text("prio-a")
    (Path(STORAGE)/"0/PrioB/prio.txt").write_text("prio-b")
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
                elif want=="NOT_LISTED":
                    # 断言该名字**不**出现在目录列举里（HIDE 必须隐藏彻底：
                    # 旧实现 probe 传剥层路径而早退，条目照旧列出、stat 却 ENOENT）
                    items=sorted(os.listdir(fp))
                    ok(name) if c[3] not in items else fail(name,f"{c[3]} 出现在列表 {items}")
                elif want=="LIST_ALL":
                    # exp=期望全集（set）：断点续扫回归——必须一字不差（含裸条目数）
                    raw=os.listdir(fp); items=set(raw); exp=set(c[3])
                    ok(name) if items==exp and len(raw)==len(exp) else fail(name,f"列出{len(items)}/{len(exp)} 缺={sorted(exp-items)[:5]} 多={sorted(items-exp)[:5]}")
                else:
                    got=fp.read_text().strip()
                    ok(name) if got==want else fail(name,f"got='{got}'")
            except Exception as e: fail(name,str(e))
    finally: stop(p)

# ═══════ 跨应用隔离（直编真源码的驱动段） ═══════
# 旧实现只在 probe（readdir 条目过滤）判跨应用隔离，resolve（getattr/open）
# 放过——于是任何"按名打开"的命令都能读到 /Android/data/<他包>/ 的内容
# （用户报障：特殊命令可访问他包 Android/data）。本段把真实 fw_rules.c 直编
# 成驱动（同 test_backing_gate 配方，不发 FUSE），用 uid.map 夹具把 10123
# 映射成 com.demo.app，逐路径比对 resolve/probe/backing 三项裁决——因为宿主机
# 调用者 uid=1000（fw_pkg 对 uid<10000 一律返回 system）无法在真 FUSE 上
# 造出"应用调用者"。
ISO_DIR="/tmp/fuse_rules_iso"
ISO_DRIVER=os.path.join(ROOT,"tests","fixtures","cross_app_isolation_driver.c")
ISO_SOURCES=["src/daemon/fw_rules.c","src/daemon/fw_pkg.c","src/config/config_parser.c",
             "src/config/path_vars.c","src/core/path_trie.c","src/core/nsp_util.c",
             "src/core/nsp_comm.c","src/core/common.c","src/core/sys_pkg.c",
             "src/core/uid_map.c","src/core/fast_pid.c","src/injector/config_publisher.c"]

def isolation_section():
    """跨应用隔离：resolve 与 probe 必须同口径（看不见 = 打不开）"""
    import re, shlex
    log("\n── 27.跨应用隔离：resolve/probe 同口径（直编真 fw_rules.c） ──")
    cc=shlex.split(os.environ.get("CC","cc"))
    if shutil.which(cc[0]) is None:
        log("跳过：缺少 C 编译器（本段不计通过）"); return
    pc=subprocess.run(["pkg-config","--libs","json-c"],capture_output=True,text=True)
    if pc.returncode!=0:
        log("跳过：缺少 json-c（本段不计通过）"); return
    shutil.rmtree(ISO_DIR,ignore_errors=True)
    cfg=os.path.join(ISO_DIR,"cfg"); os.makedirs(cfg)
    dst_inc=os.path.join(ISO_DIR,"include"); shutil.copytree(os.path.join(ROOT,"include"),dst_inc)
    # CONFIG_DIR 指向临时配置根：uid.map 即本段夹具（框架只读，不写）
    pat=re.compile(r'^#define\s+(?:NSP_CONFIG_DIR|CONFIG_DIR)\s+"/var/fuse-proxy"\s*$',re.M)
    hits=0
    for name in sorted(os.listdir(dst_inc)):
        if not name.endswith(".h"): continue
        fp=os.path.join(dst_inc,name)
        text=open(fp,encoding="utf-8").read()
        new,n=pat.subn(lambda m: m.group(0).replace('"/var/fuse-proxy"','"%s"'%cfg),text)
        if n:
            open(fp,"w",encoding="utf-8").write(new); hits+=n
    if not hits:
        log("跳过：未定位 GNU 配置根常量（本段不计通过）"); return
    exe=os.path.join(ISO_DIR,"iso_drv")
    cmd=cc+["-std=c23","-DTARGET_GNU=1","-D_GNU_SOURCE","-Wall","-Wno-unused-parameter",
            "-I",dst_inc,"-I",os.path.join(ROOT,"include"),
            "-I",os.path.join(ROOT,"src","daemon"),ISO_DRIVER]+ \
        [os.path.join(ROOT,s) for s in ISO_SOURCES]+["-o",exe,"-pthread","-ldl","-lm"]+ \
        subprocess.run(["pkg-config","--cflags","--libs","json-c"],
                       capture_output=True,text=True).stdout.split()
    r=subprocess.run(cmd,capture_output=True,text=True)
    if r.returncode!=0:
        fail("隔离驱动编译",r.stderr.strip()[-400:]); return
    conf_path=os.path.join(cfg,"injector.conf"); map_path=os.path.join(cfg,"uid.map")
    BASE="[GLOBAL]\nMONITOR OFF\n"
    ALLOW="[GLOBAL]\nMONITOR OFF\nALLOW_CROSS_APP_DATA ON\n"

    def drive(conf,uid,paths,uid_map=None,argv0=None):
        open(conf_path,"w",encoding="utf-8").write(conf)
        if os.path.exists(map_path): os.unlink(map_path)
        if uid_map is not None:
            open(map_path,"w",encoding="utf-8").write(uid_map)
        args=[argv0 or exe,conf_path,str(uid)]+list(paths)
        rr=subprocess.run(args,executable=exe,capture_output=True,text=True)
        if rr.returncode!=0:
            fail("隔离驱动执行",rr.stderr.strip()[-300:]); return None,{}
        glob=None; out={}
        for line in rr.stdout.strip().splitlines():
            if line.startswith("global="): glob=int(line.split("=",1)[1]); continue
            parts=line.split()
            out[parts[0]]=dict(p.split("=",1) for p in parts[1:])
        return glob,out

    def expect(desc,got,want):
        if got==want: ok(f"{desc} → {want}")
        else: fail(desc,f"期望 {want}，实测 {got}")

    def case(desc,conf,uid,checks,uid_map=None,argv0=None,global_want=None):
        glob,got=drive(conf,uid,[c[0] for c in checks],uid_map=uid_map,argv0=argv0)
        if glob is None: return
        if global_want is not None: expect(f"{desc}｜全局仲裁门",glob,global_want)
        for path,want in checks:
            fields=got.get(path)
            if fields is None: fail(f"{desc}｜{path}","驱动未输出该路径"); continue
            sub={k:int(fields[k]) for k in want}
            expect(f"{desc}｜{path}",sub,want)

    own="10123 com.demo.app\n10500 com.plain.app\n"
    # (1) 默认隔离开启：他包 data/obb 既不可列举也不可打开；自身放行
    case("默认隔离",BASE,10123,[
        ("/0/Android/data/com.other.app/files/x",{"resolve":1,"probe":1,"backing":1}),
        ("/0/Android/data/com.other.app",{"resolve":1,"probe":1}),
        ("/0/Android/obb/com.other.app/x",{"resolve":1,"probe":1,"backing":1}),
        ("/0/Android/data/com.demo.app/files/x",{"resolve":0,"probe":0}),
        ("/0/Android/obb/com.demo.app/x",{"resolve":0,"probe":0}),
        # media/obj 不在隔离范围（历史只隔离 data/obb，放宽会改变用户既有行为）
        ("/0/Android/media/com.other.app/x",{"resolve":0,"probe":0,"backing":0}),
        # 骨架与直接父：本身不隐藏，但 backing 必须仲裁（readdir 要按调用方过滤）
        ("/0/Android/data",{"resolve":0,"probe":0,"backing":1}),
        ("/0/Android",{"backing":1}),
        ("/0/Download/hi.txt",{"resolve":0,"probe":0,"backing":0}),
    ],uid_map=own,global_want=1)
    # (2) ALLOW_CROSS_APP_DATA ON：恢复旧行为（放行=不隔离），backing 门一并放开
    case("允许跨应用",ALLOW,10123,[
        ("/0/Android/data/com.other.app/files/x",{"resolve":0,"probe":0,"backing":0}),
        ("/0/Android/data/com.other.app",{"backing":0}),
        ("/0/Android/data",{"backing":0}),
    ],uid_map=own,global_want=0)
    # (3) 身份不可解析（root/system）不隔离，但仍交 daemon 仲裁（DAC/规则照旧）
    case("root 不隔离",BASE,0,[
        ("/0/Android/data/com.other.app/files/x",{"resolve":0,"probe":0,"backing":1}),
    ],uid_map=own,global_want=1)
    # (4) SANDBOX ON 的调用方不放行隔离——其 data/obb 访问本就被重定向进
    #     **自己的**沙盒镜像（读不到他包内容），故 resolve 放行、列举照旧过滤
    #     （沙盒语义优先；test_monitor_layers 守护镜像路径可用）
    case("沙盒豁免隔离",BASE+"[com.demo.app]\nSANDBOX ON\n",10123,[
        ("/0/Android/data/com.other.app/f",{"resolve":0,"probe":1}),
        ("/0/Download/q.txt",{"resolve":0,"probe":0}),
    ],uid_map=own,global_want=1)
    # (5) 多开/隔离进程后缀（<pkg>:push，走 /proc 回退）：基础包名比较不得把
    #     自己的包判成他包（否则应用连自己的 data 都打不开）
    case("进程后缀",BASE,10123,[
        ("/0/Android/data/com.demo.app/files/x",{"resolve":0,"probe":0}),
        ("/0/Android/data/com.other.app/x",{"resolve":1,"probe":1}),
    ],uid_map=None,argv0="com.demo.app:push")
    shutil.rmtree(ISO_DIR,ignore_errors=True)

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

    # ── RO 只读（可读性冒烟；写入拒绝的逐回调 errno 矩阵见
    # test_decision_enforce.py B 组——此处 run() 返回时已卸载，
    # 卸载后写 MNT 测的是宿主空目录而非 RO 规则，属无效断言故不保留）──
    run("""[GLOBAL] MONITOR OFF
RO /Download/Pics/""", [
        ("RO:可读","0/Download/Pics/1.jpg","img1"),
    ],"6.RO只读")

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

    # 作用域优先：**跨作用域的静态/动态通道不得互相压过**（Trie 只是同层静态规则的
    # 加速索引，不是更高优先级层）。旧实现先取「任一作用域的静态命中」再才看线性，
    # 于是 GLOBAL 的静态 REDIRECT 会压过类别段的动态规则 → 用例 21 会读到 prio-a。
    run("""[GLOBAL] MONITOR OFF
REDIRECT /prio/ /PrioA/
REDIRECT /prio3/ /PrioA/
[SYSTEM_APPS] MONITOR OFF
REDIRECT /prio/* /PrioB/""", [
        ("P1:类别动态（通配）压过GLOBAL静态","0/prio/prio.txt","prio-b"),
        ("P2:未被类别覆盖时GLOBAL静态仍生效","0/prio3/prio.txt","prio-a"),
    ],"21.作用域优先-类别动态 vs GLOBAL静态")

    # 反向组合：GLOBAL 动态 + 类别静态 → 仍是类别（静态）胜（防过度纠正）
    run("""[GLOBAL] MONITOR OFF
REDIRECT /prio2/* /PrioB/
[SYSTEM_APPS] MONITOR OFF
REDIRECT /prio2/ /PrioA/""", [
        ("P3:类别静态压过GLOBAL动态","0/prio2/prio.txt","prio-a"),
    ],"22.作用域优先-类别静态 vs GLOBAL动态")

    # 变量目标：只有**真正依赖 $package** 的规则才在包名不可解析时失效
    # （旧实现见目标含变量即要求包名可解析，把自定义变量的规则一并否掉；
    #  测试进程 uid=1000 → pkg 恒为 system 不可解析，正好是这个分支）
    run("""[GLOBAL] MONITOR OFF
PRIO_DST=/PrioB/
REDIRECT /priov/ $PRIO_DST
REDIRECT /priop/ /PrioA/$package/""", [
        ("V1:自定义变量目标生效","0/priov/prio.txt","prio-b"),
        ("V2:$package 目标在包名不可解析时失效","0/priop/prio.txt","NOT_EXISTS"),
    ],"23.变量目标：仅 $package 依赖才按包名否决")

    # 作用域优先 × 变量目标：类别段的变量规则同样压过 GLOBAL 静态
    run("""[GLOBAL] MONITOR OFF
REDIRECT /prios/ /PrioA/
[SYSTEM_APPS] MONITOR OFF
PRIO_X=/PrioB/
REDIRECT /prios/ $PRIO_X""", [
        ("P4:类别段变量规则压过GLOBAL静态","0/prios/prio.txt","prio-b"),
    ],"24.作用域优先-类别变量 vs GLOBAL静态")

    # HIDE 必须隐藏彻底：条目不能只"打不开"，还必须**不出现在父目录列举**里
    # （probe 入参是带 <uid>/ 层的原始 FUSE 路径；旧实现传剥层路径让探针直接早退）
    run("""[GLOBAL] MONITOR OFF
HIDE /Download/Pics/
HIDE /Download/*.mp3""", [
        ("H1:静态 HIDE 条目不在父目录列举","0/Download","NOT_LISTED","Pics"),
        ("H2:通配 HIDE 条目不在父目录列举","0/Download/Music","NOT_LISTED","song.mp3"),
        ("H3:未被隐藏的兄弟条目仍在","0/Download","EXISTS"),
    ],"25.HIDE 条目不得出现在父目录列举")

    # ── A18：超长规则路径/变量值必须被**拒绝**，不得静默截断成更短前缀 ──
    #    截断后的规则是原路径的**前缀**，HIDE/RO 命中范围被放大（隐藏/只读更多
    #    路径），违反 AGENTS 红线「MAX_PATH_LEN 放不下返回 -1 而非截断」。
    #    判别构造：把「截断后的那个前缀」在底层真实建成目录/文件——
    #      旧实现（snprintf/strncpy 截断）→ 该前缀被隐藏/被重定向命中；
    #      新实现（放不下即拒绝该行）→ 前缀照常可见、重定向不生效。
    LONG_A, LONG_B = "A" * 300, "B" * 300
    # 直接 HIDE：/Dl/<A*300> → snprintf(out, 256) 截断为 255 字节 = "/Dl/" + A*251
    trunc_hide = "Dl/" + "A" * 251
    Path(f"{STORAGE}/0/{trunc_hide}").mkdir(parents=True, exist_ok=True)
    (Path(STORAGE) / "0" / trunc_hide / "keep.txt").write_text("trunc-visible")
    # 变量值：LONGVAR=/Dv/<A*300> → strncpy 截断为 255 字节 = "/Dv/" + A*251。
    # 用 **REDIRECT 引用变量**（而非 HIDE）观察：变量 HIDE 走 dyn 分支且受
    # pkg_resolvable 门控（测试进程 uid=1000 → pkg=system 不可解析 → 整条跳过），
    # 只有「目标含自定义变量」的 REDIRECT 不经包名门控（config.md §5）。
    trunc_var = "Dv/" + "A" * 251
    Path(f"{STORAGE}/0/{trunc_var}").mkdir(parents=True, exist_ok=True)
    (Path(STORAGE) / "0" / trunc_var / "probe.txt").write_text("var-visible")
    # REDIRECT 目标：/Download/<B*300> → "?/Download/<B*300>" 被截断到目标缓冲
    # 之内。截断点取决于旧实现的 snprintf 尺寸参数（MAX_PATH_LEN 与 -1 两处写法
    # 不一致，落在 254/255 字节上），故把该区间内每个可能的截断名都建成真实目录：
    # 旧实现无论截到哪一个都会命中，新实现（整行拒绝）一个都不命中。
    trunc_b_len = 243
    for k in range(trunc_b_len, trunc_b_len + 4):
        d = Path(STORAGE) / "0/Download" / ("B" * k)
        d.mkdir(parents=True, exist_ok=True)
        (d / "probe.txt").write_text("trunc-target")
    run(f"""[GLOBAL] MONITOR OFF
HIDE /Dl/{LONG_A}
HIDE /Download/Pics/
LONGVAR=/Dv/{LONG_A}
REDIRECT /vv/ $LONGVAR
REDIRECT /rv/ /Download/{LONG_B}""", [
        ("A18-1:超长 HIDE 被拒绝（截断前缀未被隐藏）", "0/" + trunc_hide, "EXISTS"),
        ("A18-2:同配置正常 HIDE 仍生效（配置整体未被拒）", "0/Download/Pics/1.jpg", "NOT_EXISTS"),
        ("A18-3:超长变量值被拒绝，引用它的 REDIRECT 不放大", "0/vv/probe.txt", "NOT_EXISTS"),
        ("A18-4:超长 REDIRECT 目标被拒绝（截断目标未命中）", "0/rv/probe.txt", "NOT_EXISTS"),
    ], "26.A18 超长规则路径 fail-closed（不截断）")

    # ── 27. 跨应用隔离（resolve 与列举同口径）──
    isolation_section()

    # cleanup
    subprocess.run(["pkill","-f","fuse_daemon"],capture_output=True)
    subprocess.run(["fusermount3","-u",MNT],capture_output=True)
    log(f"\n❖ {PASS} 通过 | {FAIL} 失败 | 共 {PASS+FAIL}")
    for d,dt in ERRS: log(f"  ❌ {d}: {dt}")
    return 0 if FAIL==0 else 1

if __name__=="__main__": sys.exit(main())
