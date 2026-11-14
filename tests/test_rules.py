#!/usr/bin/env python3
"""规则边界测试 v6 — 所有文件访问路径含 user_id (0/...)"""
import subprocess,os,sys,time,shutil
from pathlib import Path

MNT="/tmp/fuse_rules_test/mnt"; STORAGE="/tmp/fuse_rules_test/storage"
MODDIR="/tmp/fuse_rules_test/modules"
CONF="/tmp/fuse_rules_test/injector.conf"  # 本套件 BASE 内，勿与其他套件共用
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
    os.makedirs(MNT,exist_ok=True); os.makedirs(os.path.dirname(CONF),exist_ok=True)
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
# （特殊命令能读到 /Android/data/<他包>/ 就是这条缺口）。本段把真实 fw_rules.c 直编
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
    CAP="[GLOBAL]\nMONITOR OFF\nALLOW_CROSS_APP_BY_CAPABILITY ON\n"
    CAP_OFF="[GLOBAL]\nMONITOR OFF\nALLOW_CROSS_APP_BY_CAPABILITY OFF\n"
    WL=BASE+"ALLOW_CROSS_APP_PKGS com.demo.app\n"

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
    # (4) SANDBOX ON 的调用方：他包 Android/data|obb 子树不归沙盒改写（沙盒对它
    #     让位），落回真实路径交隔离层——没有能力/显式声明时照旧看不见，与原生同
    #     口径；其余路径（/Download 等）仍进沙盒镜像。
    case("沙盒让位:他包仍隔离",BASE+"[com.demo.app]\nSANDBOX ON\n",10123,[
        ("/0/Android/data/com.other.app/f",{"resolve":1,"probe":1,"sandbox":0}),
        ("/0/Download/q.txt",{"resolve":0,"probe":0,"sandbox":1}),
    ],uid_map=own,global_want=1)
    # (4b) 沙盒的 /Android 只有一种口径：三个容器与调用方自己的私有目录留在
    #      真实目录，其余（含 /Android 本身）整树进镜像——应用在这里新建的条目
    #      必须改写到镜像落点，写进真实目录就等于沙盒没开。
    sb = BASE + "[com.demo.app]\nSANDBOX ON\n"
    case("沙盒:/Android 非私有路径", sb, 10123, [
        ("/0/Android/123.txt",{"sandbox":1}),
        ("/0/Android/xxx",{"sandbox":1}),
        ("/0/Android/obj/dex/classes.dex",{"sandbox":1}),
        ("/0/Android/media/com.other.app/x",{"sandbox":1}),
        ("/0/Android/media/com.demo.app2/x",{"sandbox":1}),
        ("/0/Android",{"sandbox":1}),
        ("/0/Android/data",{"sandbox":0}),
        ("/0/Android/obb",{"sandbox":0}),
        ("/0/Android/media",{"sandbox":0}),
        ("/0/Android/data/com.demo.app/files/x",{"sandbox":0}),
        ("/0/Android/obb/com.demo.app/x",{"sandbox":0}),
        ("/0/Android/media/com.demo.app/x",{"sandbox":0}),
        ("/0/Android/data/com.other.app/f",{"sandbox":0}),
    ], uid_map=own)
    # (4c) 现网配置里遗留的 SANDBOX_ANDROID_TREE 行只做解析兼容：ON/OFF 都不再
    #      影响任何落点，仍走上面那一种口径（同一组断言，两种取值各跑一遍）。
    for _legacy in ("ON", "OFF"):
        case("遗留开关不改变口径:" + _legacy,
             BASE + "SANDBOX_ANDROID_TREE " + _legacy + "\n[com.demo.app]\nSANDBOX ON\n",
             10123, [
                 ("/0/Android/123.txt",{"sandbox":1}),
                 ("/0/Android/xxx",{"sandbox":1}),
                 ("/0/Android/media/com.other.app/x",{"sandbox":1}),
                 ("/0/Android/media",{"sandbox":0}),
                 ("/0/Android/data/com.demo.app/files/x",{"sandbox":0}),
             ], uid_map=own)
    # 落点逐条钉住：sandbox 位只说"改了"，改到哪必须对上（镜像落点 = 应用沙盒
    # 目录下同一个 sub_path；让位的路径则原样落真实目录）。
    glob,got = drive(sb, 10123, ["/0/Android/123.txt","/0/Android/xxx",
                                 "/0/Android/data/com.demo.app/files/x",
                                 "/0/Android/media/com.demo.app/x"], uid_map=own)
    if glob is not None:
        for path,suffix in (
                ("/0/Android/123.txt","/0/Android/data/com.demo.app/sandbox/Android/123.txt"),
                ("/0/Android/xxx","/0/Android/data/com.demo.app/sandbox/Android/xxx"),
                ("/0/Android/data/com.demo.app/files/x","/0/Android/data/com.demo.app/files/x"),
                ("/0/Android/media/com.demo.app/x","/0/Android/media/com.demo.app/x"),
        ):
            real = (got.get(path) or {}).get("real","")
            if real.endswith(suffix): ok(f"沙盒落点｜{path}")
            else: fail(f"沙盒落点｜{path}", f"期望落点以 {suffix} 结尾，实测 '{real}'")
    # HIDE 与 ALLOW 在沙盒之前/之后都要按原语义生效：HIDE 仍不可见，ALLOW 仍回
    # 真实路径（不因"整树进镜像"把两条显式规则吃掉）。
    case("沙盒整树:HIDE 优先", BASE + "[com.demo.app]\nSANDBOX ON\nHIDE /Android/123.txt\n",
         10123, [("/0/Android/123.txt",{"resolve":1,"probe":1})], uid_map=own)
    case("沙盒整树:同段 ALLOW 豁免",
         BASE + "[com.demo.app]\nSANDBOX ON\nALLOW /Android/123.txt\n", 10123,
         [("/0/Android/123.txt",{"redir":1,"sandbox":0})], uid_map=own)
    # (5) 多开/隔离进程后缀（<pkg>:push，走 /proc 回退）：基础包名比较不得把
    #     自己的包判成他包（否则应用连自己的 data 都打不开）
    case("进程后缀",BASE,10123,[
        ("/0/Android/data/com.demo.app/files/x",{"resolve":0,"probe":0}),
        ("/0/Android/data/com.other.app/x",{"resolve":1,"probe":1}),
    ],uid_map=None,argv0="com.demo.app:push")
    # (6) 系统应用显式应用段：uid<10000 曾被 fw_pkg 短路成伪包 "system"，
    #     应用段永不命中（实机：GLOBAL/类别段 HIDE 生效、[系统应用] 段不生效）。
    #     现在经 fw_pkg_resolve_exact（uid.map → cmdline）解析真实包名后命中应用段。
    sysmap="1000 com.android.settings\n"
    case("系统应用应用段",BASE+"[com.android.settings]\nHIDE /secret_sys\n",1000,[
        ("/0/secret_sys",{"resolve":1,"probe":1}),
        ("/0/Download/x.txt",{"resolve":0,"probe":0}),
    ],uid_map=sysmap)
    # (7) 系统应用无对应应用段：维持伪包口径（仅 SYSTEM_APPS 类别层参与，
    #     未写类别规则时 HIDE 不命中），且不得误命中其他应用段
    case("系统应用无应用段",BASE+"[com.android.settings]\nHIDE /secret_sys\n",1000,[
        ("/0/secret_sys",{"resolve":0,"probe":0}),
    ],uid_map="1001 com.android.phone\n")
    # ── 特权应用自动豁免隔离（Android 权限体系对齐）：packages.list 的 seinfo
    # 字段以 "platform" 开头 = platform 签名（DocumentsUI 等文件中介的本职是
    # 访问他包 /Android/data，逐包手工写规则不可维护）。default 签名照常隔离；
    # packages.list 不可读/无该 uid → fail-safe 不豁免。
    plist=os.path.join(cfg,"packages.list")
    open(plist,"w").write(
        "com.android.documentsui 10071 0 /data/user/0/com.android.documentsui "
        "platform:privapp:targetSdkVersion=36 none 0 36 1 @system\n"
        "com.demo.app 10123 0 /data/user/0/com.demo.app default:targetSdkVersion=30 "
        "3003 0 26101061 1 @null\n"
        "com.plain.app 10500 0 /data/user/0/com.plain.app default:targetSdkVersion=33 "
        "none 0 33 1 @null\n"
        "com.installer.app 10339 0 /data/user/0/com.installer.app default:targetSdkVersion=34 "
        "none 0 34 1 @null\n"
        "com.shared.a 10610 0 /data/user/0/com.shared.a default:targetSdkVersion=34 "
        "none 0 34 1 @null\n"
        "com.shared.b 10610 0 /data/user/0/com.shared.b default:targetSdkVersion=34 "
        "none 0 34 1 @null\n"
        "com.other.app 10777 0 /data/user/0/com.other.app default:targetSdkVersion=34 "
        "none 0 34 1 @null\n")
    os.environ["NSP_PACKAGELIST"]=plist
    case("特权豁免:privapp",BASE,10071,[
        ("/0/Android/data/com.other.app/x",{"resolve":0,"probe":0}),
        ("/0/Download/hi.txt",{"resolve":0,"probe":0}),
    ],uid_map="10071 com.android.documentsui\n",global_want=1)
    case("特权豁免:default 签名照常隔离",BASE,10123,[
        ("/0/Android/data/com.other.app/x",{"resolve":1,"probe":1}),
    ],uid_map="10123 com.demo.app\n",global_want=1)
    case("特权豁免:uid 无 packages.list 行 fail-safe",BASE,10999,[
        ("/0/Android/data/com.other.app/x",{"resolve":1,"probe":1}),
    ],uid_map="10999 com.ghost.app\n",global_want=1)
    # ── All files access（MANAGE_EXTERNAL_STORAGE，生产查 appops）= 原生的
    # PASS_THROUGH 档：持该能力的调用方读他包 data/obb 一律放行（安装器读 IM
    # 落盘的安装包、文件管理器读别的应用目录）。默认配置就生效（总闸默认 ON，
    # 与原生一致）；豁免只针对跨应用隔离，HIDE 等显式规则照旧。
    os.environ["NSP_MANAGE_EXTERNAL"]="com.installer.app"
    case("AllFiles 豁免:data/obb 放行",BASE,10339,[
        ("/0/Android/data/com.other.app/x",{"resolve":0,"probe":0}),
        ("/0/Android/obb/com.other.app/y",{"resolve":0,"probe":0}),
        ("/0/Android/data",{"resolve":0,"probe":0,"backing":1}),
        ("/0/Download/a.apk",{"resolve":0,"probe":0}),
    ],uid_map="10339 com.installer.app\n",global_want=1)
    case("AllFiles 豁免:显式 ON 与默认一致",CAP,10339,[
        ("/0/Android/data/com.other.app/x",{"resolve":0,"probe":0}),
    ],uid_map="10339 com.installer.app\n",global_want=1)
    case("AllFiles 豁免:不豁免 HIDE",BASE+"HIDE /Download\n",10339,[
        ("/0/Download/a.apk",{"resolve":1,"probe":1}),
        ("/0/Android/data/com.other.app/x",{"resolve":0,"probe":0}),
    ],uid_map="10339 com.installer.app\n",global_want=1)
    # 显式关掉总闸 = 主动选择「比原生更严」：持有能力也不再放行跨应用读取。
    case("AllFiles 总闸关:仍隔离",CAP_OFF,10339,[
        ("/0/Android/data/com.other.app/x",{"resolve":1,"probe":1}),
    ],uid_map="10339 com.installer.app\n",global_want=1)
    # 沙盒 + 能力档：他包目录按能力放行（沙盒让位后落回真实路径），自身路径照旧进
    # 沙盒——这正是安装器读另一应用落盘安装包的场景。
    os.environ["NSP_MANAGE_EXTERNAL"]="com.demo.app"
    case("沙盒+能力:他包放行自身仍沙盒",BASE+"[com.demo.app]\nSANDBOX ON\n",10123,[
        ("/0/Android/data/com.other.app/f",{"resolve":0,"probe":0,"sandbox":0}),
        ("/0/Download/q.txt",{"resolve":0,"probe":0,"sandbox":1}),
    ],uid_map=own,global_want=1)
    del os.environ["NSP_MANAGE_EXTERNAL"]
    case("AllFiles 未持有:照常隔离",BASE,10339,[
        ("/0/Android/data/com.other.app/x",{"resolve":1,"probe":1}),
    ],uid_map="10339 com.installer.app\n",global_want=1)
    # ── 能装包（INSTALL_PACKAGES 权限 / REQUEST_INSTALL_PACKAGES appop）= 原生的
    # INSTALLER 档：只放行 obb，data 不在其列（原生给的是 EXT_OBB_RW_GID 而非
    # 整盘）。legacy storage 不再作为跨应用放行依据——Android 16 已无 legacy 挂载
    # 模式，它只影响非私有路径的写入语义。
    os.environ["NSP_INSTALLER"]="com.plain.app"
    case("能装包:obb 放行 data 仍隔离",BASE,10500,[
        ("/0/Android/obb/com.other.app/y",{"resolve":0,"probe":0}),
        ("/0/Android/data/com.other.app/x",{"resolve":1,"probe":1}),
    ],uid_map="10500 com.plain.app\n",global_want=1)
    case("能装包:不豁免 HIDE",BASE+"HIDE /Download\n",10500,[
        ("/0/Download/a.apk",{"resolve":1,"probe":1}),
        ("/0/Android/obb/com.other.app/y",{"resolve":0,"probe":0}),
    ],uid_map="10500 com.plain.app\n",global_want=1)
    case("能装包:总闸关 obb 也隔离",CAP_OFF,10500,[
        ("/0/Android/obb/com.other.app/y",{"resolve":1,"probe":1}),
    ],uid_map="10500 com.plain.app\n",global_want=1)
    del os.environ["NSP_INSTALLER"]
    # ── 显式规则优先于隔离这条默认边界：他在他包路径上写了规则，按规则走，
    # 隔离只是"没有规则时的默认边界"。HIDE 仍是 HIDE，ALLOW 才是放行。
    case("显式 ALLOW 压过隔离",
         BASE+"[com.demo.app]\nALLOW /Android/data/com.other.app\n",10123,[
        ("/0/Android/data/com.other.app/x",{"resolve":0,"probe":0}),
        ("/0/Android/data/com.third.app/x",{"resolve":1,"probe":1}),
    ],uid_map="10123 com.demo.app\n",global_want=1)
    case("显式 HIDE 仍拒绝",
         BASE+"[com.demo.app]\nHIDE /Android/data/com.other.app\n",10123,[
        ("/0/Android/data/com.other.app/x",{"resolve":1,"probe":1}),
    ],uid_map="10123 com.demo.app\n",global_want=1)
    # ── 按包名白名单：列出的调用方可访问他包 data/obb，与 appops 授权无关；未列出
    # 的照常隔离；匹配按调用方自身包名，同 uid 的兄弟包不会被顺带放行；白名单只
    # 解除隔离，HIDE 等显式规则照旧生效（非法包名项跳过、整行仍生效）。
    case("白名单:命中放行",WL,10123,[
        ("/0/Android/data/com.other.app/x",{"resolve":0,"probe":0}),
        ("/0/Android/obb/com.other.app/y",{"resolve":0,"probe":0}),
    ],uid_map="10123 com.demo.app\n",global_want=1)
    case("白名单:未列出照常隔离",WL,10500,[
        ("/0/Android/data/com.other.app/x",{"resolve":1,"probe":1}),
    ],uid_map="10500 com.plain.app\n",global_want=1)
    case("白名单:不按 uid 连带兄弟包",
         BASE+"ALLOW_CROSS_APP_PKGS com.shared.a\n",10610,[
        ("/0/Android/data/com.other.app/x",{"resolve":1,"probe":1}),
    ],uid_map="10610 com.shared.b\n",global_want=1)
    case("白名单:同 uid 兄弟包各自写才放行",
         BASE+"ALLOW_CROSS_APP_PKGS com.shared.a,com.shared.b\n",10610,[
        ("/0/Android/data/com.other.app/x",{"resolve":0,"probe":0}),
    ],uid_map="10610 com.shared.b\n",global_want=1)
    case("白名单:不豁免 HIDE",WL+"HIDE /Download\n",10123,[
        ("/0/Download/a.apk",{"resolve":1,"probe":1}),
        ("/0/Android/data/com.other.app/x",{"resolve":0,"probe":0}),
    ],uid_map="10123 com.demo.app\n",global_want=1)
    case("白名单:非法项跳过整行仍生效",
         BASE+"ALLOW_CROSS_APP_PKGS /bad,pkg:1,com.demo.app\n",10123,[
        ("/0/Android/data/com.other.app/x",{"resolve":0,"probe":0}),
    ],uid_map="10123 com.demo.app\n",global_want=1)
    # ── 同 uid 多包 = 同一应用身份（Linux DAC 只认 uid）：系统里 MediaProvider 与
    # DownloadsProvider 同宿于 android.process.media 这类结构，全局挂载下按包名
    # 比较会把下载器读 Downloads 私有目录判成跨应用。不同 uid 照常隔离，HIDE
    # 等显式规则照旧生效（豁免只针对跨应用隔离本身）。
    case("同 uid 多包:互访放行",BASE,10610,[
        ("/0/Android/data/com.shared.b/x",{"resolve":0,"probe":0}),
        ("/0/Android/data/com.shared.a/y",{"resolve":0,"probe":0}),
    ],uid_map="10610 com.shared.a\n",global_want=1)
    case("同 uid 多包:跨 uid 照常隔离",BASE,10610,[
        ("/0/Android/data/com.other.app/x",{"resolve":1,"probe":1}),
    ],uid_map="10610 com.shared.a\n",global_want=1)
    case("同 uid 多包:不豁免 HIDE",BASE+"HIDE /Download\n",10610,[
        ("/0/Download/a.apk",{"resolve":1,"probe":1}),
        ("/0/Android/data/com.shared.b/x",{"resolve":0,"probe":0}),
    ],uid_map="10610 com.shared.a\n",global_want=1)
    # ── 媒体提供者不参与沙盒：它在 FUSE 视图里是第三方应用取字节的通道
    #    （Photo Picker / 缩略图 / 转码），重定向进空沙盒目录会让所有未被 ALLOW
    #    覆盖的媒体 ENOENT（v3 全局替换下「选完图读不出」的根因）。与 v1 不给
    #    媒体提供者挂 FUSE 实例的口径一致；应用段/类别段显式 SANDBOX ON 被忽略
    #    并告警；HIDE 等显式规则与跨应用隔离让位保持原样。
    MEDIA_MAP="10277 com.android.providers.media.module\n"+own
    case("媒体提供者:全局沙盒不生效",BASE+"SANDBOX ON\n",10277,[
        ("/0/Download/hi.txt",{"resolve":0,"sandbox":0,"redir":0}),
        # 它不是"别的应用"，例外在打开与列举两侧同口径（原生里它的挂载模式是
        # PASS_THROUGH、签名是 platform，本来就看得到全部）
        ("/0/Android/data/com.other.app/f",{"resolve":0,"probe":0}),
    ],uid_map=MEDIA_MAP)
    case("媒体提供者:普通应用照常进沙盒",BASE+"SANDBOX ON\n",10123,[
        ("/0/Download/hi.txt",{"sandbox":1,"redir":1}),
    ],uid_map=MEDIA_MAP)
    case("媒体提供者:应用段 SANDBOX ON 被忽略",
         BASE+"SANDBOX ON\n[com.android.providers.media.module]\nSANDBOX ON\n",10277,[
        ("/0/Download/hi.txt",{"sandbox":0,"redir":0}),
    ],uid_map=MEDIA_MAP)
    # 类别段同样不能给它开沙盒（SYSTEM_APPS 判定读 sys_pkgs.cache，此处即夹具）
    sys_cache=os.path.join(cfg,"sys_pkgs.cache")
    open(sys_cache,"w",encoding="utf-8").write("com.android.providers.media.module\n")
    case("媒体提供者:类别段沙盒不生效",
         BASE+"SANDBOX ON\n[SYSTEM_APPS]\nSANDBOX ON\n",10277,[
        ("/0/Download/hi.txt",{"sandbox":0,"redir":0}),
    ],uid_map=MEDIA_MAP)
    os.unlink(sys_cache)
    case("媒体提供者:不豁免 HIDE",BASE+"SANDBOX ON\nHIDE /Download\n",10277,[
        ("/0/Download/hi.txt",{"resolve":1,"probe":1}),
    ],uid_map=MEDIA_MAP)
    del os.environ["NSP_PACKAGELIST"]
    # ── 规则路径里的变量展开：展开结果必须与静态规则同形态。
    #   解析期会给「不以 / 或 * 开头」的规则补前导 '/'（$DATA_BASE/files →
    #   /$DATA_BASE/files），变量值又可能自带前导 '/'，直接拼接会得到
    #   "//storage/..." 永不命中；值写 /sdcard、/mnt/sdcard 也是存储根别名。
    #   四种写法 × 值带/不带前导 '/' 都要落到同一路径。
    VP = "/0/Android/data/com.demo.app/files/x"
    case("变量:值 /sdcard 前缀", BASE +
         "DATA_BASE=/sdcard/Android/data/$package\n[com.demo.app]\nHIDE $DATA_BASE/files\n",
         10123, [(VP, {"resolve":1,"probe":1})], uid_map=own)
    case("变量:值 /storage/emulated/0 前缀", BASE +
         "DATA_BASE=/storage/emulated/0/Android/data/$package\n[com.demo.app]\nHIDE $DATA_BASE/files\n",
         10123, [(VP, {"resolve":1,"probe":1})], uid_map=own)
    case("变量:值不带前导 /", BASE +
         "DATA_BASE=Android/data/$package\n[com.demo.app]\nHIDE $DATA_BASE/files\n",
         10123, [(VP, {"resolve":1,"probe":1})], uid_map=own)
    case("变量:值 /mnt/sdcard 前缀", BASE +
         "DATA_BASE=/mnt/sdcard/Android/data/$package\n[com.demo.app]\nHIDE $DATA_BASE/files\n",
         10123, [(VP, {"resolve":1,"probe":1})], uid_map=own)
    case("变量:规则写 /$DATA_BASE/files", BASE +
         "DATA_BASE=/storage/emulated/0/Android/data/$package\n[com.demo.app]\nHIDE /$DATA_BASE/files\n",
         10123, [(VP, {"resolve":1,"probe":1})], uid_map=own)
    case("变量:规则写 ${DATA_BASE}/files", BASE +
         "DATA_BASE=/storage/emulated/0/Android/data/$package\n[com.demo.app]\nHIDE ${DATA_BASE}/files\n",
         10123, [(VP, {"resolve":1,"probe":1})], uid_map=own)
    case("变量:应用段内定义变量可见", BASE +
         "[com.demo.app]\nDATA_BASE=/sdcard/Android/data/$package\nHIDE $DATA_BASE/files\n",
         10123, [(VP, {"resolve":1,"probe":1})], uid_map=own)
    case("变量:无 HIDE 时可见（对照）", BASE,
         10123, [(VP, {"resolve":0,"probe":0})], uid_map=own)
    case("存储别名:字面 /sdcard 规则", BASE + "HIDE /sdcard/Android/data/com.demo.app/files\n",
         10123, [(VP, {"resolve":1,"probe":1})], uid_map=own)
    case("存储别名:字面 /mnt/sdcard 规则", BASE +
         "HIDE /mnt/sdcard/Android/data/com.demo.app/files\n",
         10123, [(VP, {"resolve":1,"probe":1})], uid_map=own)
    # ── 作用域优先 / 沙盒作用域（下面 A/B 两个形态的回归）：
    #   A「[GLOBAL] SANDBOX ON + ALLOW /Pictures/… 后，应用段再写 SANDBOX ON 仍不沙盒」
    #   B「应用段 HIDE 压不过 [GLOBAL] ALLOW（反过来 ALLOW 压 HIDE 却可以）」
    # 旧实现只有 REDIRECT 做过跨作用域比较：HIDE/RO 是三层并集（GLOBAL 恒赢），
    # 且 ALLOW 一命中就短路沙盒（br_to_real_path 的三个 sandbox 分支都以 !redir 为前提）。
    os.environ["NSP_REAL_ROOT"] = os.path.join(ISO_DIR, "root")
    case("作用域优先:应用 ALLOW 压 GLOBAL HIDE",
         BASE + "HIDE /Download\n[com.demo.app]\nALLOW /Download\n", 10123, [
        ("/0/Download/hi.txt", {"resolve":0,"probe":0}),
    ], uid_map=own)
    case("作用域优先:应用 HIDE 压 GLOBAL ALLOW",
         BASE + "ALLOW /Download\n[com.demo.app]\nHIDE /Download\n", 10123, [
        ("/0/Download/hi.txt", {"resolve":1,"probe":1}),
    ], uid_map=own)
    # 全局 ALLOW 与全局沙盒同作用域：ALLOW 照旧生效（不沙盒，历史行为不变）
    case("沙盒作用域:GLOBAL ALLOW 同层豁免全局沙盒",
         BASE + "SANDBOX ON\nALLOW /Download\n", 10123, [
        ("/0/Download/hi.txt", {"redir":1,"sandbox":0}),
    ], uid_map=own)
    # 应用段 SANDBOX ON 抬高沙盒的声明作用域：全局 ALLOW 不得凿洞（缺陷 A 本尊）
    case("沙盒作用域:应用 SANDBOX ON 压过 GLOBAL ALLOW",
         BASE + "SANDBOX ON\nALLOW /Download\n[com.demo.app]\nSANDBOX ON\n", 10123, [
        ("/0/Download/hi.txt", {"redir":1,"sandbox":1}),
    ], uid_map=own)
    # 要豁免就在同一应用段写 ALLOW（作用域相同，ALLOW 生效）
    case("沙盒作用域:应用段 ALLOW 豁免应用段沙盒",
         BASE + "SANDBOX ON\nALLOW /Download\n[com.demo.app]\nSANDBOX ON\nALLOW /Download\n",
         10123, [
        ("/0/Download/hi.txt", {"redir":1,"sandbox":0}),
    ], uid_map=own)
    # ALLOW 与 HIDE 命中同一路径时的层内次序：ALLOW 优先，作用域比较不变
    case("同层次序:应用段 ALLOW 压应用段 HIDE",
         BASE + "[com.demo.app]\nHIDE /Download\nALLOW /Download\n", 10123, [
        ("/0/Download/hi.txt", {"resolve":0,"probe":0}),
    ], uid_map=own)
    case("同层次序:应用段仅 HIDE 仍隐藏",
         BASE + "[com.demo.app]\nHIDE /Download\n", 10123, [
        ("/0/Download/hi.txt", {"resolve":1,"probe":1}),
    ], uid_map=own)
    case("同层次序:GLOBAL ALLOW 压 GLOBAL HIDE",
         BASE + "HIDE /Download\nALLOW /Download\n", 10123, [
        ("/0/Download/hi.txt", {"resolve":0,"probe":0}),
    ], uid_map=own)
    case("同层次序:跨层仍按作用域（应用 HIDE 压 GLOBAL ALLOW）",
         BASE + "ALLOW /Download\n[com.demo.app]\nHIDE /Download\n", 10123, [
        ("/0/Download/hi.txt", {"resolve":1,"probe":1}),
    ], uid_map=own)
    del os.environ["NSP_REAL_ROOT"]
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

    # ── ALLOW 与 HIDE 命中同一路径（同一作用域）：ALLOW 优先 ──
    # 旧次序 HIDE > ALLOW 会把下面这条放行重新压回隐藏
    run("""[GLOBAL] MONITOR OFF
HIDE /Download
ALLOW /Download""", [
        ("AH:同层ALLOW目录可见","0/Download","EXISTS"),
        ("AH:同层ALLOW读文件","0/Download/hi.txt","hello"),
        ("AH:同层ALLOW列举","0/Download","LIST","hi.txt"),
    ],"3a.ALLOW压HIDE")
    # 对照：没有 ALLOW 时 HIDE 照旧（ALLOW 优先不得把 HIDE 一并放过）
    run("""[GLOBAL] MONITOR OFF
HIDE /Download""", [
        ("AH:仅HIDE仍隐藏","0/Download/hi.txt","NOT_EXISTS"),
        ("AH:仅HIDE不列举","0","NOT_LISTED","Download"),
    ],"3b.仅HIDE")

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
    # 只清本套件起的 daemon（按 --rules 路径精确匹配），不误杀并发套件的进程
    subprocess.run(["pkill","-f","fuse_daemon.*--rules="+CONF],capture_output=True)
    subprocess.run(["fusermount3","-u",MNT],capture_output=True)
    log(f"\n❖ {PASS} 通过 | {FAIL} 失败 | 共 {PASS+FAIL}")
    for d,dt in ERRS: log(f"  ❌ {d}: {dt}")
    return 0 if FAIL==0 else 1

if __name__=="__main__": sys.exit(main())
