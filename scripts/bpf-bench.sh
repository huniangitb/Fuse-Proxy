#!/system/bin/sh
# FUSE backing 仲裁验证（adb-safe 加固版）
# ============================================================
# 安全模型（详见 scripts/adb-safe.sh；每一条都是事故复盘的对策）：
#   1. 默认 shell 身份：除建/卸挂载外一切测试 I/O 经 `su shell` 降级执行
#      （uid 2000，与普通用户同身份）。source 本文件所在 harness 后，
#      rm/umount/mv/cp/dd/kill 等默认过检，绕过须显式（评审可见）。
#   2. 假 backing：backing 默认 SAFE_ROOT 下合成 fixture，生产 backing 永不
#      进测试挂载（USE_PROD_BACKING=1 仅用于只读复现，且删挂载点行为仍被拦截；
#      曾有 rm 穿透活 FUSE 镜像删生产 backing 的事故）。
#   3. 校验后销毁：umount 循环卸直到 /proc/mounts 消失（堆叠挂载需多次），
#      失败即 die；trap 保障异常退出先杀 daemon；全程 set -u，空变量直接炸；
#      umount/rm 错误禁止重定向吞掉。
# 说明：曾尝试 unshare -m 私有 ns 隔离，但本机 toybox 不支持传播标记
# （--make-rprivate 无效，挂载仍回漏主 ns），不采用有 theater 嫌疑的方案；
# 当前以“假 backing（爆炸半径=fixture）+ 强制校验”作为隔离主体。
#
# 验证内容（见 vfs_backing_setup）：全局 data/obb 永不挂接、daemon 全权仲裁。
# A/B 两档（默认参数 vs --no-bpf）行为应一致：root 按名 stat 成功、md5 一致、
# 文件数一致；另记录 lookup/readdir/顺序读基线（均为 daemon 路径耗时）。
#
# 运行（root，经 scripts/adb-sh.sh）：
#   sh /data/local/tmp/bpf-bench.sh
# ============================================================
set -u
HERE=$(dirname "$0")
. "$HERE/adb-safe.sh"

BIN=${FUSE_DAEMON_BIN:-/data/adb/modules/Namespace-Proxy/bin/fuse_daemon}
RULES=${FUSE_BENCH_RULES:-/data/Namespace-Proxy/injector.conf}
MNT=$SAFE_ROOT/bench_mnt
MODDIR=$SAFE_ROOT/bench_mod
VMNT=$MNT/0/Android/data/.bpf_bench
NFILES=200
BIGSIZE_MB=32
REPS=3
SHELL_PHASE=$SAFE_ROOT/bench_shell_phase.sh
RESULT=$SAFE_ROOT/bench.result

if [ "${USE_PROD_BACKING:-0}" = 1 ]; then
    BACKING=/data/media/0/Android/data/.bpf_bench_ro
    BENCH_ROOT=/data/media
    log "警告：使用生产 backing（只读 workload）"
    need_root "生产 backing 只读复现"
else
    BACKING=$SAFE_ROOT/bench_backing/0/Android/data/.bpf_bench
    BENCH_ROOT=$SAFE_ROOT/bench_backing
fi

# shell 降级阶段（heredoc 加引号：$ 保留到执行期，参数经位置参数传入）
gen_phase() {
    cat > "$SHELL_PHASE" <<'PHASEEOF'
. /data/local/tmp/adb-safe.sh
assert_downgraded
NFILES=$1
BIGSIZE_MB=$2
REPS=$3
VMNT=$4
BACKING=$5
now_ns() { date +%s%N; }
ms_diff() { awk -v a="$1" -v b="$2" 'BEGIN { printf "%d", (b - a) / 1000000 }'; }
avg() { echo "$*" | tr ' ' '\n' | awk '{s+=$1; n++} END {printf "%.1f", n ? s/n : 0}'; }
prep_files() {
    mkdir -p "$BACKING" || { echo "FATAL 建 workload 目录失败"; exit 1; }
    i=1
    while [ $i -le $NFILES ]; do
        [ -f "$BACKING/f$i" ] || head -c 4096 /dev/urandom > "$BACKING/f$i" 2>/dev/null
        i=$((i + 1))
    done
    [ -f "$BACKING/big" ] || head -c $((BIGSIZE_MB * 1024 * 1024)) /dev/urandom > "$BACKING/big" 2>/dev/null
    echo "PREP_OK n=$(ls "$BACKING" 2>/dev/null | wc -l)"
}
check_correct() {
    n=$(ls "$VMNT" 2>/dev/null | wc -l)
    [ "$n" -eq $((NFILES + 1)) ] || { echo "FAIL 文件数=$n"; exit 1; }
    a=$(md5sum "$BACKING/big" | cut -d' ' -f1)
    b=$(md5sum "$VMNT/big" | cut -d' ' -f1)
    [ "$a" = "$b" ] || { echo "FAIL md5 不一致"; exit 1; }
    stat "$VMNT" >/dev/null 2>&1 || { echo "FAIL root-stat"; exit 1; }
    echo "GATE_OK n=$n md5=$a"
}
bench_lookup() {
    t0=$(now_ns); i=1
    while [ $i -le $NFILES ]; do stat "$VMNT/f$i" >/dev/null 2>&1; i=$((i + 1)); done
    ms_diff "$t0" "$(now_ns)"
}
bench_readdir() {
    t0=$(now_ns); ls -U "$VMNT" >/dev/null 2>&1; ms_diff "$t0" "$(now_ns)"
}
bench_read() {
    t0=$(now_ns); dd if="$VMNT/big" of=/dev/null bs=1M 2>/dev/null
    dt=$(ms_diff "$t0" "$(now_ns)"); [ "$dt" -eq 0 ] && dt=1
    echo $((BIGSIZE_MB * 1000 / dt))
}
run_rounds() {
    L=""; R=""; S=""
    r=1
    while [ $r -le $REPS ]; do
        sleep 0.3
        l=$(bench_lookup); v=$(bench_readdir); s=$(bench_read)
        L="$L $l"; R="$R $v"; S="$S $s"
        echo "ROUND r=$r lookup=${l}ms readdir=${v}ms MBps=${s}"
        r=$((r + 1))
    done
    echo "AVG lookup=$(avg $L)ms readdir=$(avg $R)ms MBps=$(avg $S)"
    echo "RAW lookup:$L | readdir:$R | MBps:$S"
}
case "$6" in
    prep) prep_files;;
    gate) check_correct;;
    bench) run_rounds;;
esac
PHASEEOF
    chmod 755 "$SHELL_PHASE"
}

as_shell() {
    su shell -c "sh $SHELL_PHASE $NFILES $BIGSIZE_MB $REPS $VMNT $BACKING $1"
}

start_daemon() {
    need_root "启动 scratch daemon（$1）"
    mkdir -p "$MNT" "$MODDIR"
    safe_umount "$MNT"
    "$BIN" "$MNT" --root="$BENCH_ROOT" --rules="$RULES" -f \
        -o allow_other,auto_cache,fsname=bpfbench $2 > "$SAFE_ROOT/bench-$1.log" 2>&1 &
    DPID=$!
    echo "$DPID" > "$SAFE_ROOT/bench-$1.pid"
    n=0
    while [ $n -lt 50 ]; do
        grep -q " $MNT " /proc/mounts 2>/dev/null && break
        kill -0 $DPID 2>/dev/null || die "daemon 起不来，见 $SAFE_ROOT/bench-$1.log"
        sleep 0.2
        n=$((n + 1))
    done
    assert_mounted "$MNT"
    log "$1 daemon 就绪 pid=$DPID（root 身份仅建挂载）"
}

stop_daemon() {
    need_root "停止 scratch daemon（$1）"
    DPID=$(cat "$SAFE_ROOT/bench-$1.pid" 2>/dev/null)
    [ -n "$DPID" ] && kill "$DPID" 2>/dev/null
    sleep 0.5
    if [ -n "$DPID" ] && kill -0 "$DPID" 2>/dev/null; then
        kill -9 "$DPID" 2>/dev/null
    fi
    sleep 0.3
    safe_umount "$MNT"
}

run_mode() {
    log "========== 模式 $1 ($2) =========="
    start_daemon "$1" "$2"
    sleep 1
    case "$BACKING" in
        /data/media/*)
            [ -d "$BACKING" ] || die "生产 backing 缺失：$BACKING"
            ;;
        *)
            log "prep（shell 身份）： $(as_shell prep)"
            ;;
    esac
    echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true
    GATE_OUT=$(as_shell gate)
    log "门禁（shell 身份）： $GATE_OUT"
    case "$GATE_OUT" in GATE_OK*) ;; *) die "门禁失败，停止";; esac
    as_shell bench | while read -r line; do
        log "$line"
        case "$line" in RAW*) echo "$1 $line" >> "$RESULT";; esac
    done
    stop_daemon "$1"
}

main() {
    trap 'log "异常退出，打扫残留 daemon"; for f in "$SAFE_ROOT"/bench-*.pid; do [ -f "$f" ] && kill -9 "$(cat "$f")" 2>/dev/null; done; safe_umount "$MNT" 2>/dev/null || true' EXIT HUP INT TERM
    rm -f "$RESULT"
    gen_phase
    run_mode "bpf-on" ""
    run_mode "bpf-off" "--no-bpf"
    log "========== 汇总 =========="
    cat "$RESULT" 2>/dev/null
    log "daemon 状态核对（sys.log）："
    grep -E "FUSE backing|会话就绪.*bpfbench" /data/Namespace-Proxy/log/sys.log 2>/dev/null | tail -4
    if [ "${USE_PROD_BACKING:-0}" != 1 ]; then
        safe_rm "$SAFE_ROOT/bench_backing"
    fi
    safe_rm "$SHELL_PHASE"
    safe_rm "$SAFE_ROOT/bench_inner.sh"
    safe_rm "$SAFE_ROOT/bench_mod"
    safe_rm "$SAFE_ROOT/bench-bpf-on.log"
    safe_rm "$SAFE_ROOT/bench-bpf-off.log"
    safe_rm "$SAFE_ROOT/bench-bpf-on.pid"
    safe_rm "$SAFE_ROOT/bench-bpf-off.pid"
    safe_rm "$RESULT"
    trap - EXIT HUP INT TERM
    log "清理完毕"
}

main
