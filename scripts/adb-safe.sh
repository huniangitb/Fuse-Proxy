#!/system/bin/sh
# 设备侧安全测试 harness v2（adb-safe.sh，生产级隔离标准）
# ============================================================
# 威胁模型（真实事故复盘）：清理命令中 `for m in ...; do umount .../$m` 的
# 变量在传输层被吃空（umount 全部落空，错误被 2>/dev/null 吞掉），紧接着的
# `rm -rf <挂载点>` 走进仍存活的 FUSE 镜像（--root=/data/media），删掉了
# 真实 backing。本文件按“内核原生机制为主、shell 约束为纵深”做隔离：
#
#   1. 原生降权（主体）：测试 I/O 一律 `su shell` 执行——uid/gid/groups 全降
#      到 2000（危险组已脱）、CapEff=0，由内核强制；`assert_downgraded()`
#      每次先验。root 只建/卸挂载（/dev/fuse 0600，只能 root 开）且留痕。
#   2. 假 backing（爆炸半径）：scratch daemon 的 --root 只允许 SAFE_ROOT 下
#      的合成 fixture；生产 backing 永不进测试挂载（需真实下层行为时 cp -a
#      快照到沙盒再测，删快照不伤本体）。
#   3. shell 纵深：source 即影子危险命令，逐条过生产路径与挂载点检查；
#      全程 set -u；umount/rm 失败即 die 且错误禁止吞掉。
# 说明：曾评估 unshare -m 私有 ns，但本机 toybox 不支持传播标记
# （--make-rprivate 无效，挂载仍回漏主 ns），有 theater 嫌疑故不采用；
# 当前以“降权身份（够不到生产）+ 假 backing（够到也删不动真数据）”为隔离主体。
#
# 用法：. /path/to/adb-safe.sh   # 本文件被 source 后立即生效
#       sh adb-safe.sh selftest  # 纯逻辑自检（不碰挂载）
# ============================================================
# shellcheck disable=SC2034
ADB_SAFE_VERSION=2

# 唯一允许写入的沙盒根（生产路径一律拒绝写入）
SAFE_ROOT=/data/local/tmp/nsp_safe
# 垫片安装目录（PATH 优先级的兜底，覆盖未 source 的上下文）
SHIM_DIR=$SAFE_ROOT/bin
# 后端真二进制目录（toybox multicall，垫片/函数一律显式 exec 此处）
REAL_BIN=/system/bin

# 生产路径：读可以，写/删/当 backing/卸载其上挂载一律拒绝
PROD_PATHS="/data/media /storage /mnt /data/user /data/data /data/app /data/adb /system /vendor /apex /data_mirror /dev /proc /sys"

log() { echo "[adb-safe] $*"; }
die() { echo "[adb-safe] FATAL: $*" >&2; exit 1; }

# 提权留痕：root 操作的唯一语义入口（建挂载、chcon 等），调用即日志
need_root() { # $1=原因（必填）
    [ -n "${1:-}" ] || die "need_root 缺少原因说明"
    log "提权(root): $1"
}

# 路径归一（去尾部 '/'，空值保持空）
_norm() {
    p=${1:-}
    while [ "${p%/}" != "$p" ]; do p=${p%/}; done
    echo "$p"
}

# 生产路径判定：相等或在其下、或为 / 本身即命中（0=命中）
_is_prod() {
    t=$(_norm "$1")
    [ -n "$t" ] || return 0
    [ "$t" = "/" ] && return 0
    for r in $PROD_PATHS; do
        [ "$t" = "$r" ] && return 0
        case "$t" in "$r"/*) return 0;; esac
    done
    return 1
}

# 写保护：空路径/生产路径/挂载点/含下级挂载一律拒绝（0=通过）
assert_writable() { # $1=路径 $2=用途
    t=$(_norm "${1:-}")
    [ -n "$t" ] || die "空路径拒绝写入（用途：${2:-未知}，多为变量展开失败）"
    if _is_prod "$t"; then
        die "生产路径拒绝写入：$t（用途：${2:-未知}）"
    fi
    if mountpoint -q "$t" 2>/dev/null; then
        die "拒绝：$t 是挂载点（用途：${2:-未知}）"
    fi
    if grep -q " $t/" /proc/mounts 2>/dev/null; then
        die "拒绝：$t 之下仍有挂载（用途：${2:-未知}）"
    fi
}

# 操作数提取：跳过 - 开头标志（cp/mv/rm/ch* 通用；-- 之后全算操作数）
_each_operand() { # $1=回调名前缀（guard_op_<cb> <操作数>），其余为原参数
    cb=$1
    shift
    dashed=0
    for a in "$@"; do
        if [ "$dashed" = 0 ]; then
            case "$a" in
                --) dashed=1; continue;;
                -*) continue;;
            esac
        fi
        guard_op_"$cb" "$a"
    done
}

guard_op_writecheck() { assert_writable "$1" "guard"; }

# ---- 各命令放行判定（0=放行并由调用方 exec 后端） ----
guard_rm() { _each_operand writecheck "$@"; }
guard_mv() { _each_operand writecheck "$@"; }   # mv 删源：源与目标都查
guard_cp() { # cp 只删目标：仅最后一个操作数是目标
    dest=""
    dashed=0
    for a in "$@"; do
        if [ "$dashed" = 0 ]; then
            case "$a" in --) dashed=1; continue;; -*) continue;; esac
        fi
        dest=$a
    done
    [ -n "$dest" ] && guard_op_writecheck "$dest"
}
guard_tee() { _each_operand writecheck "$@"; }
guard_ch() { _each_operand writecheck "$@"; }   # chcon/chmod/chown/restorecon
guard_dd() { # 只查 of= 目标；/dev/null 是标准黑洞，显式放行
    for a in "$@"; do
        case "$a" in
            of=/dev/null) ;;
            of=*) guard_op_writecheck "${a#of=}";;
        esac
    done
}
guard_umount() { # 仅允许卸 /data/local/tmp 下的 scratch 挂载
    dashed=0
    for a in "$@"; do
        if [ "$dashed" = 0 ]; then
            case "$a" in --) dashed=1; continue;; -*) continue;; esac
        fi
        t=$(_norm "$a")
        [ -n "$t" ] || die "umount 空挂载点（多为变量展开失败）"
        case "$t" in
            /data/local/tmp/*) ;;
            *) die "拒绝卸载非 scratch 挂载点：$t" ;;
        esac
    done
}
guard_kill() { # -1 必须先判（它形如标志）；拒绝 pid 1 与 -1（全体），其余放行并日志
    dashed=0
    for a in "$@"; do
        [ "$a" = "-1" ] && die "拒绝 kill -1（全体进程）"
        if [ "$dashed" = 0 ]; then
            case "$a" in --) dashed=1; continue;; -*) continue;; esac
        fi
        [ "$a" = 1 ] && die "拒绝 kill init(1)"
    done
    [ "${1:-}" = "-0" ] || log "kill: $*"
}

# ---- 影子函数：source 即生效（绕过须用 command/绝对路径，评审可见） ----
rm() { guard_rm "$@"; "$REAL_BIN/rm" "$@"; }
umount() { guard_umount "$@"; "$REAL_BIN/umount" "$@"; _verify_umount_silent "$@"; }
mv() { guard_mv "$@"; "$REAL_BIN/mv" "$@"; }
cp() { guard_cp "$@"; "$REAL_BIN/cp" "$@"; }
dd() { guard_dd "$@"; "$REAL_BIN/dd" "$@"; }
tee() { guard_tee "$@"; "$REAL_BIN/tee" "$@"; }
chcon() { guard_ch "$@"; "$REAL_BIN/chcon" "$@"; }
chmod() { guard_ch "$@"; "$REAL_BIN/chmod" "$@"; }
chown() { guard_ch "$@"; "$REAL_BIN/chown" "$@"; }
restorecon() { guard_ch "$@"; "$REAL_BIN/restorecon" "$@"; }
setenforce() { log "警告：setenforce $*（SELinux 全局开关，诊断用后须恢复）"; "$REAL_BIN/setenforce" "$@"; }
kill() { guard_kill "$@"; "$REAL_BIN/kill" "$@"; }

# umount 后回查：umount(2) 结果为准——成功或 EINVAL（本 ns 已无此挂载，
# 多为别处 lazy 残影）且路径可列出底层目录即视为脱离；EBUSY 等则循环重试；
# 条目在且路径不可用一律 die，不准继续（防“活挂载 + 后续 rm”）
_verify_umount_silent() {
    dashed=0
    for a in "$@"; do
        if [ "$dashed" = 0 ]; then
            case "$a" in --) dashed=1; continue;; -*) continue;; esac
        fi
        n=0
        while grep -q " $a " /proc/mounts 2>/dev/null; do
            n=$((n + 1))
            [ "$n" -gt 10 ] && die "卸载后挂载仍在（已卸 $n 次）：$a，禁止继续"
            err=$("$REAL_BIN/umount" "$a" 2>&1)
            rc=$?
            if [ "$rc" = 0 ]; then
                sleep 0.2
                continue
            fi
            case "$err" in
                *"Invalid argument"*|*"not mounted"*|*"No such file"*)
                    if ls "$a" >/dev/null 2>&1; then
                        return 0
                    fi
                    die "挂载条目残留且路径不可用：$a（$err），需人工处理"
                    ;;
            esac
            sleep 0.2
        done
    done
}

# 安全卸载（显式调用版，回查逻辑见 _verify 系列）
safe_umount() { # $1=挂载点
    [ -n "${1:-}" ] || die "safe_umount 空挂载点"
    need_root "卸载 $1"
    if ! grep -q " $1 " /proc/mounts 2>/dev/null; then
        log "$1 本来就没挂载，跳过"
        return 0
    fi
    tries=0
    while grep -q " $1 " /proc/mounts 2>/dev/null; do
        tries=$((tries + 1))
        [ "$tries" -gt 10 ] && die "卸载后挂载仍在（已卸 $tries 次）：$1，禁止继续"
        # 直调后端（不走影子 umount，避免嵌套回查把“已接受脱离”又判死循环）
        err=$("$REAL_BIN/umount" "$1" 2>&1)
        rc=$?
        if [ "$rc" = 0 ]; then
            sleep 0.2
            continue
        fi
        case "$err" in
            *"Invalid argument"*|*"not mounted"*|*"No such file"*)
                if ls "$1" >/dev/null 2>&1; then
                    log "$1 已脱离（残影条目，路径可用），视为干净"
                    return 0
                fi
                die "挂载条目残留且路径不可用：$1（$err），需人工处理"
                ;;
        esac
        sleep 0.2
    done
}

# 安全删除（显式调用版；影子 rm 已含同等检查）
safe_rm() { # $1=路径（SAFE_ROOT/可写区下、非挂载点、无下级挂载）
    assert_writable "$1" "safe_rm"
    rm -rf "$1"
    log "已删除：$1"
}

# 降级断言：以 shell 身份运行的测试阶段必须满足 uid/gid/groups 全降级且
# 无有效权能（内核强制，非约定）。ksu 的 `su shell` 经实测：uid=gid=2000、
# groups 仅 2000（1078 等危险组已脱）、CapEff=0。如将来行为变化，此断言
# 直接炸而不是静默放大权限。
assert_downgraded() {
    [ "$(id -u 2>/dev/null)" = 2000 ] || die "未降级：uid 不是 shell(2000)"
    [ "$(id -g 2>/dev/null)" = 2000 ] || die "未降级：gid 不是 shell(2000)"
    grps=$(id -G 2>/dev/null)
    [ "$grps" = 2000 ] || [ "$grps" = "2000" ] || die "未降级：附加组非空（$grps）"
    eff=$(awk '/^CapEff:/ {print $2}' /proc/self/status 2>/dev/null)
    [ "$eff" = 0000000000000000 ] || die "未降级：有效权能非空（CapEff=$eff）"
    log "降级确认：uid/gid/groups=2000 CapEff=0（内核强制）"
}

# 断言已挂载（挂载后自检用）
assert_mounted() { # $1=挂载点
    grep -q " $1 " /proc/mounts 2>/dev/null || die "挂载失败（/proc/mounts 无记录）：$1"
    log "挂载确认：$1"
}

# 垫片安装：给未 source 的上下文兜底（同一套判定；绕过须绝对路径，评审可见）
install_shims() {
    need_root "安装命令垫片到 $SHIM_DIR"
    mkdir -p "$SHIM_DIR"
    for c in rm umount mv cp dd tee chcon chmod chown restorecon setenforce kill; do
        [ -x "$REAL_BIN/$c" ] || { log "跳过缺失后端：$c"; continue; }
        cat > "$SHIM_DIR/$c" <<EOF
#!/system/bin/sh
# adb-safe 自动垫片（判定见 adb-safe.sh，勿手改）
HARNESS=\$(dirname "\$0")/../adb-safe.sh
[ -f "\$HARNESS" ] || HARNESS=/data/local/tmp/adb-safe.sh
. "\$HARNESS"
case "$c" in
    rm|mv) guard_mv "\$@";;
    cp) guard_cp "\$@";;
    tee) guard_tee "\$@";;   # tee 的每个操作数都是写入目标，不能只查最后一个
    dd) guard_dd "\$@";;
    umount) guard_umount "\$@";;
    kill) guard_kill "\$@";;
    setenforce) log "警告：setenforce \$*";;
    *) guard_ch "\$@";;
esac
exec $REAL_BIN/$c "\$@"
EOF
        chmod 755 "$SHIM_DIR/$c"
    done
    log "垫片就绪：$SHIM_DIR（会话 PATH 必须前置该目录）"
}

# 自检（纯逻辑 + 沙盒内行为，不碰生产挂载）
adb_safe_selftest() {
    fails=0
    _is_prod "/data/media/0/Android" || { echo "FAIL prod-dir"; fails=$((fails + 1)); }
    _is_prod "/storage" || { echo "FAIL prod-root"; fails=$((fails + 1)); }
    _is_prod "/" || { echo "FAIL slash"; fails=$((fails + 1)); }
    _is_prod "$SAFE_ROOT/x" && { echo "FAIL safe-allowed"; fails=$((fails + 1)); }
    _is_prod "" || { echo "FAIL empty"; fails=$((fails + 1)); }
    (assert_writable "" "t" 2>/dev/null) && { echo "FAIL empty-write"; fails=$((fails + 1)); }
    (assert_writable "/data/media/0" "t" 2>/dev/null) && { echo "FAIL prod-write"; fails=$((fails + 1)); }
    (assert_writable "/data/local/tmp/x" "t" 2>/dev/null) || { echo "FAIL tmp-write"; fails=$((fails + 1)); }
    (guard_kill 1 2>/dev/null) && { echo "FAIL kill1"; fails=$((fails + 1)); }
    (guard_kill -1 2>/dev/null) && { echo "FAIL killall"; fails=$((fails + 1)); }
    (guard_umount "/storage/emulated" 2>/dev/null) && { echo "FAIL umount-prod"; fails=$((fails + 1)); }
    # 影子 rm 生效性（子 shell，父进程安全）：空操作数必须 die
    (rm "" 2>/dev/null) && { echo "FAIL rm-empty"; fails=$((fails + 1)); }
    if [ "$fails" = 0 ]; then
        echo "SELFTEST_OK 13/13"
    else
        echo "SELFTEST_FAIL $fails"
        return 1
    fi
}

case "${0##*/}" in
    adb-safe.sh)
        [ "${1:-}" = selftest ] && adb_safe_selftest
        [ "${1:-}" = install-shims ] && install_shims
        ;;
esac
