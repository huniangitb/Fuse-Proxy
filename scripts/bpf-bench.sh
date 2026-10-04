#!/system/bin/sh
# FUSE BPF 最小收益验证（设备侧单文件脚本）
# ============================================================
# 原理：bpf_setup 只对全局实例的 /Android/data|obb 生效（见 fuse_daemon.c
# vfs_bpf_setup），命中后内核把该目录子树后续 I/O 直送 backing，不再唤醒
# daemon。预期收益：lookup/readdir/顺序读更快 + daemon 用户态 CPU 更少。
#
# 方法：同一挂载点、同一 workload，A/B 对比两档——
#   bpf-on  = 默认参数（BPF 启用，需日志出现 "FUSE BPF: 已启用"）
#   bpf-off = 追加 --no-bpf（日志出现 "已被 --no-bpf 参数禁用"）
# 每档先做正确性门禁（md5/文件数与 backing 一致），再测三项：
#   1. lookup 延迟：200 个现存文件 stat 循环耗时
#   2. readdir 扫描：200 文件目录 ls -U 耗时
#   3. 顺序读吞吐：32MB 文件 dd 到 /dev/null；另采整轮 daemon CPU tick
#      增量（lookup+readdir+read 全包，读在双模式都走 passthrough，单列读
#      CPU 会恒 0，必须看整轮）
# 每项重复 3 次取平均。drop_caches 保证各轮起点一致。
#
# 运行（root）：
#   sh /data/local/tmp/bpf-bench.sh
# 不碰生产挂载（/storage/emulated）：用独立 scratch 挂载点，FUSE_ALIVE
# 会被 injector 忽略（ipc_server.c），退出后 kill + umount 无残留。
# ============================================================
BIN=/data/adb/modules/Namespace-Proxy/bin/fuse_daemon
ROOT=/data/media
RULES=/data/Namespace-Proxy/injector.conf
MNT=/data/local/tmp/nsp_bpf_bench
BACKING=/data/media/0/Android/data/.bpf_bench
NFILES=200
BIGSIZE_MB=32
REPS=3

log() { echo "[bpf-bench] $*"; }
die() { echo "[bpf-bench] FATAL: $*" >&2; exit 1; }

now_ns() { date +%s%N; }
ms_diff() { # $1=t0ns $2=t1ns → 毫秒（awk 算，sh 算术 32 位会溢出）
    awk -v a="$1" -v b="$2" 'BEGIN { printf "%d", (b - a) / 1000000 }'
}
# daemon CPU tick（utime+stime），comm 含括号故按 "*） " 切分后取 13/14 列
cpu_ticks() {
    line=$(cat /proc/$1/stat 2>/dev/null) || return 1
    rest=${line##*\) }
    set -- $rest
    echo $(( $12 + $13 ))
}
# daemon 上下文切换（BPF 旁路 ⇒ 内核不再唤醒 daemon，该数应断崖式下降；
# stat 的 tick 精度 10ms，对单轮几毫秒的 daemon CPU 全显 0，只能看它。
# 注意：干活的是 FUSE worker 线程，主线程常年 epoll 睡眠，故必须对
# /proc/PID/task/*/status 全线程求和，只看 PID 级全是 0——这正是初版的坑。）
csw() {
    awk '/voluntary_ctxt_switches|nonvoluntary_ctxt_switches/ {s += $2} END {print s+0}' \
        /proc/$1/task/*/status 2>/dev/null
}

prep_files() {
    mkdir -p "$BACKING" || die "建 workload 目录失败（$BACKING）"
    i=1
    while [ $i -le $NFILES ]; do
        [ -f "$BACKING/f$i" ] || head -c 4096 /dev/urandom > "$BACKING/f$i" 2>/dev/null
        i=$(( i + 1 ))
    done
    [ -f "$BACKING/big" ] || head -c $(( BIGSIZE_MB * 1024 * 1024 )) /dev/urandom > "$BACKING/big" 2>/dev/null
    log "workload 就绪：$NFILES 小文件 + ${BIGSIZE_MB}MB big"
}

start_daemon() { # $1=模式名 $2=额外参数
    mkdir -p "$MNT"
    umount -l "$MNT" 2>/dev/null
    # shellcheck disable=SC2086
    "$BIN" "$MNT" --root="$ROOT" --rules="$RULES" -f \
        -o allow_other,auto_cache,fsname=bpfbench $2 > /data/local/tmp/bpf-bench-$1.log 2>&1 &
    DPID=$!
    n=0
    while [ $n -lt 50 ]; do
        mountpoint -q "$MNT" 2>/dev/null && break
        grep -q "$MNT" /proc/mounts 2>/dev/null && break
        kill -0 $DPID 2>/dev/null || die "daemon 起不来，见 /data/local/tmp/bpf-bench-$1.log"
        sleep 0.2
        n=$(( n + 1 ))
    done
    log "$1 daemon 就绪 pid=$DPID"
}

stop_daemon() {
    kill $DPID 2>/dev/null
    sleep 0.5
    kill -0 $DPID 2>/dev/null && kill -9 $DPID 2>/dev/null
    sleep 0.3
    umount "$MNT" 2>/dev/null || umount -l "$MNT" 2>/dev/null
    log "daemon 已停，挂载已收"
}

check_correct() { # $1=模式名
    vmount="$MNT/0/Android/data/.bpf_bench"
    n=$(ls "$vmount" 2>/dev/null | wc -l)
    [ "$n" -eq $(( NFILES + 1 )) ] || die "$1 正确性门禁失败：文件数=$n"
    a=$(md5sum "$BACKING/big" | cut -d' ' -f1)
    b=$(md5sum "$vmount/big" | cut -d' ' -f1)
    [ "$a" = "$b" ] || die "$1 正确性门禁失败：md5 不一致"
    log "$1 正确性门禁通过（文件数=$n md5=$a）"
}

bench_lookup() { # stat 循环，输出毫秒
    vmount="$MNT/0/Android/data/.bpf_bench"
    t0=$(now_ns)
    i=1
    while [ $i -le $NFILES ]; do
        stat "$vmount/f$i" >/dev/null 2>&1
        i=$(( i + 1 ))
    done
    ms_diff "$t0" "$(now_ns)"
}

bench_readdir() { # 全目录扫描，输出毫秒
    t0=$(now_ns)
    ls -U "$MNT/0/Android/data/.bpf_bench" >/dev/null 2>&1
    ms_diff "$t0" "$(now_ns)"
}

bench_read() { # 顺序读：输出 "MB/s"
    vmount="$MNT/0/Android/data/.bpf_bench"
    t0=$(now_ns)
    dd if="$vmount/big" of=/dev/null bs=1M 2>/dev/null
    dt=$(ms_diff "$t0" "$(now_ns)")
    [ "$dt" -eq 0 ] && dt=1
    echo "$(( BIGSIZE_MB * 1000 / dt ))"
}

avg() { # 空格分隔数字 → 平均（awk）
    echo "$*" | tr ' ' '\n' | awk '{s+=$1; n++} END {printf "%.1f", n ? s/n : 0}'
}

run_mode() { # $1=模式名 $2=额外参数
    log "========== 模式 $1 ($2) =========="
    start_daemon "$1" "$2"
    sleep 1
    check_correct "$1"
    L=""; R=""; S=""; C=""; W=""
    r=1
    while [ $r -le $REPS ]; do
        echo 3 > /proc/sys/vm/drop_caches 2>/dev/null
        sleep 0.3
        c0=$(cpu_ticks $DPID); w0=$(csw $DPID)
        l=$(bench_lookup)
        v=$(bench_readdir)
        s=$(bench_read)
        c1=$(cpu_ticks $DPID); w1=$(csw $DPID)
        c=$(( c1 - c0 )); w=$(( w1 - w0 ))
        L="$L $l"; R="$R $v"; S="$S $s"; C="$C $c"; W="$W $w"
        log "轮$r: lookup=${l}ms readdir=${v}ms 读=${s}MB/s 轮cpu=${c}tick 轮切=${w}次"
        r=$(( r + 1 ))
    done
    log "--- $1 平均：lookup=$(avg $L)ms readdir=$(avg $R)ms 读=$(avg $S)MB/s 轮cpu=$(avg $C)tick 轮切=$(avg $W)次"
    echo "$1 lookup:$L | readdir:$R | MBps:$S | cputick:$C | csw:$W" >> /data/local/tmp/bpf-bench.result
    stop_daemon
}

rm -f /data/local/tmp/bpf-bench.result
prep_files
run_mode "bpf-on" ""
run_mode "bpf-off" "--no-bpf"
log "========== 汇总（各轮原始值 + 平均见上） =========="
cat /data/local/tmp/bpf-bench.result
log "daemon 状态核对（sys.log，以挂载点行定位本轮）："
grep -E "FUSE BPF|会话就绪.*nsp_bpf_bench" /data/Namespace-Proxy/log/sys.log | tail -6
