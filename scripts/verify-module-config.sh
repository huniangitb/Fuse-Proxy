#!/system/bin/sh
# 模块配置下发：真机最小验证（L4）
# ============================================================
# 验证目标（模块配置由框架读取并按 owner 下发）：
#   1. 框架读 <modules_dir>/<模块名>/<模块名>.conf 并把内容下发给模块——
#      模块据此注册后端前缀，FUSE 层可见行为随之改变；
#   2. 模块**不再自读**配置：旧路径 <rules 目录>/ftp.conf 完全不生效；
#   3. 模块**不再自跑 inotify**：改模块配置仍能热重载（靠框架侧 watch）。
#
# 判别信号（无需网络、无需 vsftpd）：
#   规则 `FTP /云盘 云盘` 只声明「该前缀属于 FTP」，真正分派还要
#   `module_backend_lookup` 命中（fuse_daemon.c: `rr.is_ftp && lookup()==0`）。
#   故：
#     - 后端未注册 → 回落本地 backing → 探针文件**读得到**（LOCAL_OK）；
#     - 后端已注册 → 分派给 FTP → 连 127.0.0.1:1 被拒 → **EIO**。
#   两者一读一错，肉眼可分，且不依赖任何外部服务。
#
# 四个阶段（A→D）：
#   A 无任何模块配置          → LOCAL_OK（无后端，回落本地）
#   B 写 <modules>/ftp_module/ftp_module.conf → EIO（框架读到并下发）
#   C 删掉该文件              → LOCAL_OK（框架热重载、模块清空后端）
#   D 只写旧路径 <rules>/ftp.conf             → LOCAL_OK（模块不再自读，旧路径无效）
#   B 证「框架读新路径」，C 证「框架侧 inotify」，D 证「模块不再自读」。
#
# 隔离：一切落在 $SAFE_ROOT（/data/local/tmp/nsp_safe）scratch，生产 backing/
#   路径永不进测试挂载；探针一律 `su shell` 降权执行；退出前卸挂载并清理。
#   ⚠ 日志通道是**抽象 UDS**（nsp_log_socket），scratch daemon 的日志会投给
#     正在运行的生产 log_monitor（与既有 B1 取证脚本同一处境，非用户数据）。
#
# 运行（root，经 scripts/adb-sh.sh）：
#   scripts/adb-sh.sh push build_android/fuse_daemon  /data/local/tmp/nsp_safe/bin/fuse_daemon
#   scripts/adb-sh.sh push build_android/ftp_module.so /data/local/tmp/nsp_safe/bin/ftp_module.so
#   scripts/adb-sh.sh push scripts/verify-module-config.sh /data/local/tmp/verify-module-config.sh
#   scripts/adb-sh.sh 'sh /data/local/tmp/verify-module-config.sh'
# ============================================================
set -u
HERE=$(dirname "$0")
. "$HERE/adb-safe.sh"

BIN=${FUSE_DAEMON_BIN:-$SAFE_ROOT/bin/fuse_daemon}
MOD=${FTP_MODULE_BIN:-$SAFE_ROOT/bin/ftp_module.so}
CFG=$SAFE_ROOT/cfg
MODDIR=$CFG/modules
RULES=$CFG/injector.conf
MODCONF=$MODDIR/ftp_module/ftp_module.conf
LEGACY=$CFG/ftp.conf
MNT=$SAFE_ROOT/mnt
ROOTDIR=$SAFE_ROOT/root
DLOG=$SAFE_ROOT/daemon.log
PIDF=$SAFE_ROOT/daemon.pid
SERVER=云盘
PROBE=$MNT/0/$SERVER/probe.txt
FAILS=0

for p in "$BIN" "$MOD"; do
    _is_prod "$p" && die "拒绝：scratch 二进制不得位于生产路径 $p"
done
[ -x "$BIN" ] || die "缺少可执行 daemon：$BIN（先 push build_android/fuse_daemon）"
[ -f "$MOD" ] || die "缺少模块：$MOD（先 push build_android/ftp_module.so）"

ok()   { log "  ✅ $*"; }
bad()  { log "  ❌ $*"; FAILS=$((FAILS + 1)); }

# 探针：以 shell（uid 2000）读本地 backing 里的探针文件，按结果分类
#   LOCAL_OK / BACKEND_EIO / ENOENT / UNKNOWN
probe() {
    out=$(su shell -c "cat '$PROBE' 2>&1" 2>&1)
    # 诊断走 stderr：probe 本身经 $() 取值，stdout 只允许放分类结果
    log "    原始输出：$out" >&2
    case "$out" in
        *nsp-modcfg-probe*) echo LOCAL_OK ;;
        # toybox 打印 "I/O error"，glibc 打印 "Input/output error"——两种都认
        *"I/O error"*|*"Input/output error"*) echo BACKEND_EIO ;;
        *"No such file"*) echo ENOENT ;;
        *) echo "UNKNOWN($out)" ;;
    esac
}

expect() { # $1=阶段 $2=期望 $3=实测
    if [ "$2" = "$3" ]; then ok "$1：$3（期望 $2）"; else bad "$1：实测 $3，期望 $2"; fi
}

snapshot() { # 生产侧不变量快照（前后比对用）
    echo "--- mounts ---"; grep -E 'fuse_daemon' /proc/mounts
    echo "--- procs ---"; ps -A 2>/dev/null | grep -E 'fuse_daemon|injector|rule_server|log_monitor' | awk '{print $1, $NF}'
    echo "--- prod cfg ---"; ls -l /data/Namespace-Proxy/ftp.conf /data/Namespace-Proxy/modules/ftp_module/ 2>&1
}

setup() {
    need_root "模块配置下发取证：建 scratch 布局"
    safe_umount "$MNT"
    safe_rm "$CFG"
    safe_rm "$ROOTDIR"
    safe_rm "$MNT"
    mkdir -p "$SAFE_ROOT/bin" "$MODDIR/ftp_module" "$MNT" "$ROOTDIR/0/$SERVER"
    printf 'nsp-modcfg-probe\n' > "$ROOTDIR/0/$SERVER/probe.txt"
    cp "$MOD" "$MODDIR/ftp_module/ftp_module.so" || die "复制模块失败"
    # 规则只声明 FTP 前缀归属；真正分派取决于模块是否注册了该前缀
    printf '[GLOBAL]\nFTP /%s %s\n' "$SERVER" "$SERVER" > "$RULES" || die "写规则失败"
    log "scratch 布局就绪：$CFG（初始**无**模块配置）"
}

start_daemon() {
    need_root "启动 scratch daemon（模块目录 $MODDIR）"
    safe_umount "$MNT"
    "$BIN" "$MNT" --root="$ROOTDIR" --rules="$RULES" --modules-dir="$MODDIR" -f \
        -o allow_other,auto_cache,fsname=nspcfgverify > "$DLOG" 2>&1 &
    DPID=$!
    echo "$DPID" > "$PIDF"
    n=0
    while [ $n -lt 50 ]; do
        grep -q " $MNT " /proc/mounts 2>/dev/null && break
        kill -0 "$DPID" 2>/dev/null || die "daemon 起不来，见 $DLOG：$(tail -5 "$DLOG")"
        sleep 0.2
        n=$((n + 1))
    done
    assert_mounted "$MNT"
    log "daemon 就绪 pid=$DPID"
}

stop_daemon() {
    need_root "停止 scratch daemon"
    DPID=$(cat "$PIDF" 2>/dev/null)
    [ -n "${DPID:-}" ] && kill "$DPID" 2>/dev/null
    sleep 0.5
    if [ -n "${DPID:-}" ] && kill -0 "$DPID" 2>/dev/null; then kill -9 "$DPID" 2>/dev/null; fi
    sleep 0.3
    safe_umount "$MNT"
}

alive() { kill -0 "$(cat "$PIDF")" 2>/dev/null && echo yes || echo no; }

# ── 主流程 ────────────────────────────────────────────────────────────
log "===== 生产侧基线快照（测试前）====="
snapshot > "$SAFE_ROOT/before.txt" 2>&1
cat "$SAFE_ROOT/before.txt"

log "===== 降权确认 ====="
d=$(su shell -c 'echo $(id -u):$(id -g)' 2>&1)
[ "$d" = "2000:2000" ] && ok "探针降权为 shell（$d）" || bad "探针未降权：$d"

setup
start_daemon

log "===== A. 无任何模块配置 → 回落本地 backing ====="
# 对照：模块必须**确实已加载**，否则 A/C/D 的「无后端」结论都是空转
if grep -q 'nsp_module_ftp_module' "/proc/$(cat "$PIDF")/maps" 2>/dev/null; then
    ok "模块已加载（maps 见 memfd:nsp_module_ftp_module）"
else
    bad "模块未加载——A/C/D 的否定结论不成立"
fi
expect "A" LOCAL_OK "$(probe)"
[ "$(alive)" = yes ] && ok "daemon 存活" || bad "daemon 已死"

log "===== B. 写模块配置（新路径）→ 框架读到并下发，后端接管 ====="
mkdir -p "$(dirname "$MODCONF")"
printf '[%s]\nhost = 127.0.0.1\nport = 1\nremote_dir = /\n' "$SERVER" > "$MODCONF" \
    || die "写模块配置失败"
log "  已写 $MODCONF，等框架 inotify + 下发（3s）"
sleep 3
expect "B" BACKEND_EIO "$(probe)"
[ "$(alive)" = yes ] && ok "daemon 存活" || bad "daemon 已死"

log "===== C. 删模块配置 → 框架热重载、模块清空后端 ====="
rm -f "$MODCONF"
log "  已删 $MODCONF，等热重载（3s）"
sleep 3
expect "C" LOCAL_OK "$(probe)"

log "===== D. 只写旧路径 <rules>/ftp.conf → 必须完全无效（模块不再自读）====="
printf '[%s]\nhost = 127.0.0.1\nport = 1\nremote_dir = /\n' "$SERVER" > "$LEGACY"
log "  已写旧路径 $LEGACY，等 3s"
sleep 3
expect "D" LOCAL_OK "$(probe)"
if grep -q '注册后端' "$DLOG" 2>/dev/null; then
    bad "D：daemon 日志出现「注册后端」——旧路径仍在生效"
else
    log "  （DLOG 无「注册后端」；该日志走抽象 UDS，此项仅作参考，判据以行为为准）"
fi

log "===== 清理 scratch ====="
stop_daemon
safe_rm "$CFG"
safe_rm "$ROOTDIR"
safe_rm "$MNT"
safe_rm "$DLOG"
safe_rm "$PIDF"

log "===== 生产侧不变量（测试后）====="
snapshot > "$SAFE_ROOT/after.txt" 2>&1
cat "$SAFE_ROOT/after.txt"
if diff -q "$SAFE_ROOT/before.txt" "$SAFE_ROOT/after.txt" >/dev/null 2>&1; then
    ok "生产侧零变化（挂载/进程/配置目录逐字一致）"
else
    bad "生产侧发生变化，见 before.txt 与 after.txt（保留现场）"
    KEEP=1
fi
[ "${KEEP:-0}" = 1 ] || safe_rm "$SAFE_ROOT/before.txt"
[ "${KEEP:-0}" = 1 ] || safe_rm "$SAFE_ROOT/after.txt"
[ -n "$(ls -A "$SAFE_ROOT" 2>/dev/null | grep -v '^bin$')" ] \
    && log "⚠ scratch 仍有残留：$(ls -A "$SAFE_ROOT")" || log "scratch 已清空（保留 bin/ 供下次）"

log "============================================"
if [ "$FAILS" = 0 ]; then
    log "结果：全部通过"
    exit 0
fi
log "结果：$FAILS 项失败"
exit 1
