#!/system/bin/sh
# B1 真机取证：backing 直通与 MONITOR / 热重载不闭合
# ============================================================
# 背景：GNU 侧已修（backing 仲裁门补 MONITOR 维度，判别见
# tests/test_backing_gate.py），但「已挂接 dentry 对运行期新增规则不感知」
# 只能真机判定；下面 A/B 两项给出取证方法与判别标准，不依赖本机评审记录。
#
# 三项取证（全部落在 SAFE_ROOT scratch：假 backing + scratch 挂载点，生产
# backing/路径永不进测试挂载；经 adb-safe harness 守卫，rm/umount/kill 默认过检）：
#
#   A. 仅 [GLOBAL] MONITOR ON（无任何改路径规则）→ 该子树**必须不挂 backing**
#      （daemon 全权仲裁），访问探针路径应进 io.log。
#      判别：io.log 出现探针路径 → 门含 monitor、未直通（修复生效）；
#            无 → 仍直通（内核绕过 daemon，vfs_log_io 静默归零）。
#   B. 以「无规则」启动（该子树会挂 backing）→ 热重载加 HIDE → stat 应 ENOENT。
#      判别：stat 仍成功 → 运行期新增规则对已挂 dentry 不生效（已知缺口，
#            需处置选项 b：发布临界区对受影响子树 invalidate）；
#            ENOENT → entry 级 invalidate（vfs_inval_path）已能撤销已挂 backing。
#
# ⚠ 本脚本**未在真机验证过**（开发机无设备/NDK）。首次运行请逐段核对输出；
#   任何前提缺失一律 die，不静默通过。
#
# 运行（root，经 scripts/adb-sh.sh）：
#   scripts/adb-sh.sh push scripts/adb-safe.sh /data/local/tmp/adb-safe.sh
#   scripts/adb-sh.sh push scripts/verify-backing-monitor.sh /data/local/tmp/verify-backing-monitor.sh
#   scripts/adb-sh.sh 'sh /data/local/tmp/verify-backing-monitor.sh'
#
# 环境变量：
#   FUSE_DAEMON_BIN=<路径>  scratch daemon（默认 $SAFE_ROOT/bin/fuse_daemon）
#   USE_PROD_BIN=1          显式使用生产二进制（须同时给 FUSE_DAEMON_BIN，留痕）
# ============================================================
set -u
HERE=$(dirname "$0")
. "$HERE/adb-safe.sh"

# ── 二进制：默认绝不用已安装的生产二进制（详见 bpf-bench.sh 同款说明） ──
if [ "${USE_PROD_BIN:-0}" = 1 ]; then
    [ -n "${FUSE_DAEMON_BIN:-}" ] || die "USE_PROD_BIN=1 必须显式给 FUSE_DAEMON_BIN"
    BIN=$FUSE_DAEMON_BIN
    need_root "以生产二进制做 B1 取证（USE_PROD_BIN=1）：$BIN"
else
    BIN=${FUSE_DAEMON_BIN:-$SAFE_ROOT/bin/fuse_daemon}
    _is_prod "$BIN" && die "拒绝：scratch 二进制不得位于生产路径 $BIN（确需请设 USE_PROD_BIN=1）"
fi
[ -x "$BIN" ] || die "缺少可执行 daemon：$BIN（先把 scratch 副本放到 $SAFE_ROOT/bin/）"

# ── scratch 布局 ──────────────────────────────────────────────────────
MNT=$SAFE_ROOT/b1_mnt
ROOTDIR=$SAFE_ROOT/b1_root
RULES=$SAFE_ROOT/b1_rules.conf
PIDF=$SAFE_ROOT/b1.pid
DLOG=$SAFE_ROOT/b1-daemon.log
TAG=.nsp_b1_probe                 # 唯一标记：在日志里定位本次访问
LOGDIR=/data/Namespace-Proxy/log  # LOG_DIR = NSP_CONFIG_DIR "/log"
IOLOG=$LOGDIR/io.log              # 由 log_monitor 写（daemon 经抽象 UDS 投递）
PIOLOG=$LOGDIR/persistent_io.log  # 调试构建（-DNSP_ENABLE_IO_LOG）且无 UDS 转发时 daemon 直写
# 探针路径的**两种形态**（别混用——本脚本第一版就踩了：把 /0/ 写进规则，HIDE 永不命中）：
#   - FUSE 侧访问路径带用户层 /0/（挂载点内的真实路径）；
#   - 规则（HIDE/RO/…）匹配的是**剥离用户层后**的虚拟路径（仓库红线：虚拟前缀不含
#     user_id），故规则里写 /Download/… 而非 /0/Download/…。
#   对照 tests/test_decision_enforce.py：规则 `HIDE /ovr/gone` ↔ 访问 MNT/0/ovr/gone。
FUSE_PROBE="/0/Download/$TAG"     # 非 data/obb → 由按路径门裁决（正是 B1 的判定点）
FUSE_PROBE2="/0/Download/${TAG}2"
RULE_PROBE="/Download/$TAG"
RULE_PROBE2="/Download/${TAG}2"
SYSLOG=$LOGDIR/sys.log            # daemon 的 LOG_DBG/INFO 经 UDS 由 log_monitor 写这里

# daemon 自证：sys.log 里与本次探针相关的 backing 决策行
# （`放弃挂接 <path>` = 按路径门拒绝挂 backing；`<real> (fd=` = 真的挂了 backing）。
#  这些是 LOG_DBG，实测会经 UDS 落进 sys.log，可直接引用为证据。）
syslog_backing() {
    grep -a "FUSE backing" "$SYSLOG" 2>/dev/null | grep -a -- "$TAG" | tail -"${1:-4}"
}

# 探针路径在日志里的出现次数。两个文件都看：
#   - log_monitor 在跑（生产模块的常态）→ 记 io.log；
#   - 没跑 + daemon 是 debug 构建（带 NSP_ENABLE_IO_LOG）→ daemon 直写 persistent_io.log。
# 两者都无更新 = A 判定不成立（要么真直通，要么观测链断了——见 main 里的显式提示）。
iolog_hits() {
    n=0
    for f in "$IOLOG" "$PIOLOG"; do
        [ -f "$f" ] || continue
        # grep -c 无命中时**打印 0 但退出码 1**——不能写 `|| echo 0`（会得到 "0\n0"，
        # 进 $(( )) 即 "unexpected '0'"）。只取它的 stdout，空则按 0。
        c=$(grep -c -- "$TAG" "$f" 2>/dev/null)
        [ -n "$c" ] || c=0
        n=$((n + c))
    done
    echo "$n"
}

# 以 shell 身份（uid 2000，与普通用户同身份）在挂载点内操作
as_shell() {
    su shell -c "$1"
}

start_daemon() {
    need_root "启动 scratch daemon（规则 $1）"
    mkdir -p "$MNT"
    safe_umount "$MNT"
    "$BIN" "$MNT" --root="$ROOTDIR" --rules="$RULES" -f \
        -o allow_other,auto_cache,fsname=b1verify > "$DLOG" 2>&1 &
    DPID=$!
    echo "$DPID" > "$PIDF"
    n=0
    while [ $n -lt 50 ]; do
        grep -q " $MNT " /proc/mounts 2>/dev/null && break
        kill -0 "$DPID" 2>/dev/null || die "daemon 起不来，见 $DLOG"
        sleep 0.2
        n=$((n + 1))
    done
    assert_mounted "$MNT"
    log "daemon 就绪 pid=$DPID"
}

stop_daemon() {
    need_root "停止 scratch daemon"
    DPID=$(cat "$PIDF" 2>/dev/null)
    [ -n "$DPID" ] && kill "$DPID" 2>/dev/null
    sleep 0.5
    if [ -n "$DPID" ] && kill -0 "$DPID" 2>/dev/null; then kill -9 "$DPID" 2>/dev/null; fi
    sleep 0.3
    safe_umount "$MNT"
}

write_rules() {
    printf '%s' "$1" > "$RULES" || die "写规则失败：$RULES"
}

# 等热重载（fw_config 去抖 1s）落定
settle_reload() { sleep 2; }

# ── A：仅 MONITOR ON → 不挂 backing、访问进 io.log ─────────────────────
check_monitor_gate() {
    log "========== A. 仅 MONITOR ON：子树不得挂 backing =========="
    write_rules '[GLOBAL]
MONITOR ON
'
    # 探针 backing：$ROOTDIR/0/Download/$TAG
    mkdir -p "$ROOTDIR/0/Download/$TAG" || die "建 backing 目录失败"
    echo "b1-probe" > "$ROOTDIR/0/Download/$TAG/f" || die "写 backing 文件失败"
    start_daemon "MONITOR-only"
    sleep 1
    # 先报能力：本机内核到底支不支持 FUSE backing/透传。**不支持则 B 是「空转」**
    # （从没挂过 backing，谈不上「已挂 dentry 对运行期规则不感知」）。
    # 注意这些行是 daemon 经 UDS 由 log_monitor 写进 sys.log 的，不在 daemon 自己的
    # stdout/stderr 里（第一版查错了文件，误报「未见」）。
    PT=$(grep -a "FUSE Passthrough" "$SYSLOG" 2>/dev/null | tail -1)
    log "能力探测（sys.log）：${PT:-未见 FUSE Passthrough 行（未启用/日志被过滤）}"
    # 关键：**重复访问**。首次 lookup 无论是否挂 backing 都会落到 daemon（挂接本身
    # 就发生在这次 lookup 内），只测一次会把「首查有日志」误当「一直由 daemon 服务」。
    # 连续 3 轮 ls（opendir + readdir 每次都记 io.log），每轮后等 1s 让 log_monitor
    # 落盘（异步写，立刻读会少算）：每轮都增长 → 内核始终回 daemon（未挂 backing）；
    # 首轮后停住 → 首查即挂 backing 直通。
    sleep 1
    H0=$(iolog_hits)
    H1=""; H2=""; H3=""
    i=1
    while [ $i -le 3 ]; do
        as_shell "ls $MNT$FUSE_PROBE >/dev/null 2>&1"
        sleep 1
        case $i in
            1) H1=$(iolog_hits);;
            2) H2=$(iolog_hits);;
            3) H3=$(iolog_hits);;
        esac
        i=$((i + 1))
    done
    stop_daemon
    log "A: io.log 探针命中 起=$H0 轮1=$H1 轮2=$H2 轮3=$H3"
    log "A 自证（daemon 的 backing 决策行）：$(syslog_backing 2 | tr '\n' ' ')"
    if [ "$H2" -lt "$H3" ]; then
        log "A 结果：PASS —— 末轮仍在增长：内核始终回 daemon 服务（该子树未挂 backing，门含 monitor 的修复成立）"
    elif [ "$H0" -eq "$H1" ] && [ "$H1" -eq "$H3" ]; then
        if [ "$LOGOK" = 1 ]; then
            log "A 结果：FAIL —— 三轮访问**一条日志都没有**（log_monitor 在跑，观测链是通的）：该子树已挂 backing，内核完全绕过 daemon（MONITOR 下 IO 静默归零）"
        else
            log "A 结果：不确定 —— 三轮都没日志，且 log_monitor 未运行，无法区分「真直通」与「观测链断」"
        fi
    elif [ "$H0" -lt "$H1" ]; then
        log "A 结果：FAIL —— 日志只在首轮增长后停住：首次 lookup 后即挂 backing 直通（MONITOR 下仍绕过 daemon）"
    else
        log "A 结果：不确定 —— 增长形态异常（起=$H0 轮1=$H1 轮2=$H2 轮3=$H3），请人工核对 sys.log"
    fi
}

# ── B：先挂 backing、后热重载加 HIDE → 规则是否对已挂 dentry 生效 ──────
check_hot_reload() {
    log "========== B. 挂 backing 后热重载加 HIDE =========="
    # 初始：空规则（该子树会挂 backing），不启用 monitor（避免 A 的门把它拦下）
    write_rules ''
    # 两个探针：probe 先访问（挂 backing）；probe2 **热重载前从不访问**，作为
    # 「规则到底有没有被读到」的对照——否则「stat 仍成功」分不清是 dentry 缓存
    # 还是规则压根没生效（本脚本第一版就误判成缺口）。
    mkdir -p "$ROOTDIR/0/Download/$TAG" "$ROOTDIR/0/Download/${TAG}2" || die "建 backing 目录失败"
    echo b1 > "$ROOTDIR/0/Download/$TAG/f" || die "写 backing 文件失败"
    echo b1 > "$ROOTDIR/0/Download/${TAG}2/f" || die "写 backing 文件失败"
    start_daemon "no-rules"
    sleep 1
    # 首次访问建立 dentry 并挂 backing
    PRE=$(as_shell "stat $MNT$FUSE_PROBE/f >/dev/null 2>&1 && echo STAT_OK || echo STAT_FAIL")
    log "B: 热重载前 stat($FUSE_PROBE/f)=$PRE（期望 STAT_OK：底层文件真实存在，此刻该子树挂 backing）"
    log "B 自证（重载前，期望出现「真的挂了 backing」的 (fd= 行）：$(syslog_backing 2 | tr '\n' ' ')"
    # 热重载：两条 HIDE 一起下发（**规则路径不含 /0/**）
    write_rules "[GLOBAL]
HIDE $RULE_PROBE
HIDE $RULE_PROBE2
"
    settle_reload
    POST=$(as_shell "stat $MNT$FUSE_PROBE/f >/dev/null 2>&1 && echo STAT_OK || echo STAT_FAIL")
    CTRL=$(as_shell "stat $MNT$FUSE_PROBE2 >/dev/null 2>&1 && echo STAT_OK || echo STAT_FAIL")
    stop_daemon
    log "B: 热重载后 stat($FUSE_PROBE/f)=$POST（期望 STAT_FAIL：HIDE 生效）"
    log "B: 对照 stat($FUSE_PROBE2)=$CTRL（热重载前从未访问 → STAT_FAIL 表示规则确实被读到）"
    log "B 自证（重载后，期望出现「放弃挂接」）：$(syslog_backing 2 | tr '\n' ' ')"
    if [ "$PRE" != STAT_OK ]; then
        log "B 结果：不确定 —— 前置 stat 就没成功（$PRE），场景不成立"
    elif [ "$CTRL" != STAT_FAIL ]; then
        log "B 结果：不确定 —— 对照探针也未隐藏（$CTRL）。两种可能：①规则没被读到（重载链问题）；②该子树已被 backing 覆盖、daemon 根本不被咨询（**后者正是本项要测的缺口**）。判据：若同一脚本在「不挂 backing」的配置下对照会隐藏，则此处就是 ②。核对 $RULES 与 sys.log 的 backing 决策行"
    elif [ "$POST" = STAT_FAIL ]; then
        log "B 结果：PASS —— 运行期新增 HIDE 对已挂 backing 生效（对照探针已隐藏=规则确实被读到）；前提是本机支持 backing（见 A 的能力探测行），否则本项为空转"
    else
        log "B 结果：FAIL —— 规则确实生效（对照探针已隐藏）但**已挂 dentry 不受影响**（已知缺口；处置选项 b：发布临界区 invalidate 受影响子树）"
    fi
}

main() {
    trap 'log "异常退出，打扫残留"; [ -f "$PIDF" ] && kill -9 "$(cat "$PIDF")" 2>/dev/null; safe_umount "$MNT" 2>/dev/null || true' EXIT HUP INT TERM
    need_root "B1 取证需要建/卸 scratch 挂载"
    log "探针 FUSE 路径：$FUSE_PROBE（backing 根 $ROOTDIR）"
    # A 的判定依赖日志更新：log_monitor 在跑时记 io.log；没跑时只有带
    # NSP_ENABLE_IO_LOG 的 debug 构建才会由 daemon 直写 persistent_io.log。
    # LOGOK 决定「完全没有日志」该怎么读：观测链通 → 那是真直通（FAIL）；
    # 观测链断 → 只能说「不确定」。
    LOGOK=0
    if pgrep -f log_monitor >/dev/null 2>&1; then
        LOGOK=1
    else
        log "提示：未检测到 log_monitor 进程——io.log 不会更新；若 $BIN 非 debug 构建（无 NSP_ENABLE_IO_LOG），A 的观测链是断的"
    fi
    check_monitor_gate
    check_hot_reload
    log "========== 汇总 =========="
    log "A/B 判定见上（A=PASS 表示 GNU 侧修复在真机成立；B=FAIL 表示运行期规则感知缺口仍在）"
    log "daemon 日志：$DLOG（sys.log 亦含 FUSE backing 行：/data/Namespace-Proxy/log/sys.log）"
    # 清理 scratch（safe_rm 只允许 SAFE_ROOT/可写区、非挂载点、无下级挂载）
    safe_rm "$ROOTDIR"
    safe_rm "$RULES"
    safe_rm "$DLOG"
    safe_rm "$PIDF"
    trap - EXIT HUP INT TERM
    log "清理完毕"
}

main
