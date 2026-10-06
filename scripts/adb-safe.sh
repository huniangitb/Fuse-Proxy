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
#      路径判定走**物理路径**（词法折叠 `.`/`..` + 解析符号链接），不再只做
#      字面前缀比对——`$SAFE_ROOT/../../../../data/media/0` 与 `SAFE_ROOT` 下
#      指向 /data/media 的软链都曾可绕过写保护。无 readlink 时写保护 fail-closed
#      （拒绝写入），不退化成字面比对。`sh adb-safe.sh selftest` 覆盖这些用例。
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

# 路径归一：去尾部 '/'，并**折叠 '.' 与 '..'**（纯词法，不触盘）。相对路径按
# $PWD 补全，保证 '..' 语义正确。原实现只去尾斜杠，于是
# `$SAFE_ROOT/../../data/media/0` 这类字面不匹配 PROD_PATHS 的写法可直接绕过
# 写保护（本轮修复的缺陷之一）。
_norm() {
    p=${1:-}
    [ -n "$p" ] || { echo ""; return; }
    case "$p" in
        /*) ;;
        *) p="$PWD/$p" ;;
    esac
    # 拆词按 '/'，须临时关掉路径展开（段里出现 * ? 时否则会被 glob）
    case $- in
        *f*) _nf=0;;
        *) _nf=1; set -f;;
    esac
    _oifs=$IFS
    IFS=/
    out=""
    for seg in $p; do
        case "$seg" in
            ''|.) ;;
            ..) out=${out%/*} ;;
            *) out="$out/$seg" ;;
        esac
    done
    IFS=$_oifs
    [ "$_nf" = 1 ] && set +f
    [ -n "$out" ] || out=/
    echo "$out"
}

# readlink 后端解析：优先设备自带的 /system/bin（toybox），回退 PATH（开发机
# 自检用）。返回空串表示两者都没有——此时无法解析符号链接，写保护必须
# fail-closed（见 assert_writable），不能静默退化成纯词法比对。
_rl_bin() {
    if [ -x "$REAL_BIN/readlink" ]; then
        echo "$REAL_BIN/readlink"
        return 0
    fi
    command -v readlink 2>/dev/null
}

# 物理路径：词法归一后再解析符号链接。**生产路径判定必须走这里**——只做字面
# 比对会被 SAFE_ROOT 下指向 /data/media 的软链绕过（本轮修复的缺陷之二）。
#
# readlink -f 要求「除最后一段外都存在」，而写保护要判的恰恰是**尚不存在**的
# 写入目标（如 `link/0/newfile`），直接调它会解析失败并退回字面比对——软链洞
# 原样保留。故改为：从完整路径起逐级剥掉末段，直到某级能解析，再把剥掉的后缀
# 拼回。这样 `link/0/newfile` 会先解析出 `link/0` 的真实落点，再拼 `/newfile`。
_phys() {
    t=$(_norm "${1:-}")
    [ -n "$t" ] || { echo ""; return; }
    _rl=$(_rl_bin)
    if [ -z "$_rl" ]; then
        echo "$t"
        return
    fi
    _rest=""
    _cur=$t
    while :; do
        _r=$("$_rl" -f "$_cur" 2>/dev/null)
        if [ -n "$_r" ]; then
            _norm "$_r$_rest"
            return
        fi
        [ "$_cur" = "/" ] && break
        _base=${_cur##*/}
        _cur=${_cur%/*}
        [ -n "$_cur" ] || _cur=/
        _rest="/$_base$_rest"
    done
    echo "$t"
}

# 生产路径判定：相等或在其下、或为 / 本身即命中（0=命中）。按物理路径判。
# 内部变量加下划线前缀：本函数在**当前 shell**被直接调用（非子 shell），
# 用裸名 t/r 会覆盖调用方（assert_writable）的同名变量。
_is_prod() {
    _ip=$(_phys "${1:-}")
    [ -n "$_ip" ] || return 0
    [ "$_ip" = "/" ] && return 0
    for _r in $PROD_PATHS; do
        [ "$_ip" = "$_r" ] && return 0
        case "$_ip" in "$_r"/*) return 0;; esac
    done
    return 1
}

# 写保护：空路径/生产路径/挂载点/含下级挂载一律拒绝（0=通过）
# 判定与挂载点检查都用物理路径：软链/`..` 归一后若落在生产路径下，一律拒绝。
assert_writable() { # $1=路径 $2=用途
    # fail-closed：没有 readlink 就解析不了软链，此时「不是生产路径」无从保证，
    # 直接拒绝写入而不是退回字面比对（那正是软链绕过的成因）。
    [ -n "$(_rl_bin)" ] || die "无 readlink，无法解析符号链接——fail-closed 拒绝写入（用途：${2:-未知}）"
    t=$(_phys "${1:-}")
    [ -n "$t" ] || die "空路径拒绝写入（用途：${2:-未知}，多为变量展开失败）"
    if _is_prod "$t"; then
        die "生产路径拒绝写入：$t（用途：${2:-未知}；原始写法：${1:-}）"
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
        # 字面值用于 /proc/mounts 查找；放行判定按物理路径（软链/`..` 归一后
        # 若落到生产路径即拒绝）
        t=$(_phys "$a")
        [ -n "$t" ] || die "umount 空挂载点（多为变量展开失败）"
        case "$t" in
            /data/local/tmp/*) ;;
            *) die "拒绝卸载非 scratch 挂载点：$t（原始写法：$a）" ;;
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
# ck  期望成功；ckf 期望失败（守卫必须拦下）。
# 两者都在**子 shell**里执行：守卫拦下时走 die → exit 1，若在父 shell 执行会把
# 自检本身杀掉（原实现靠手写 `( ... )` 规避，这里统一收口）。
# 断言数 n 动态统计——写死总数会随用例增删失真。
adb_safe_selftest() {
    fails=0
    n=0
    ck() {
        _l=$1; shift; n=$((n + 1))
        ( "$@" ) 2>/dev/null || { echo "FAIL $_l"; fails=$((fails + 1)); }
    }
    ckf() {
        _l=$1; shift; n=$((n + 1))
        if ( "$@" ) 2>/dev/null; then echo "FAIL(应拒绝却放行) $_l"; fails=$((fails + 1)); fi
        return 0
    }

    # 无 readlink 时写保护 fail-closed，任何写入都会被拒——此时跑下去只会得到
    # 一串误导性的 FAIL，直接如实报告环境不可用。
    if [ -z "$(_rl_bin)" ]; then
        echo "SELFTEST_FAIL：环境无 readlink，无法解析符号链接（写保护 fail-closed）"
        return 1
    fi

    ck  "prod-dir"    _is_prod "/data/media/0/Android"
    ck  "prod-root"   _is_prod "/storage"
    ck  "slash"       _is_prod "/"
    ckf "safe-allowed" _is_prod "$SAFE_ROOT/x"
    ck  "empty"       _is_prod ""
    ckf "empty-write" assert_writable "" t
    ckf "prod-write"  assert_writable "/data/media/0" t
    ck  "tmp-write"   assert_writable "/data/local/tmp/x" t
    ckf "kill1"       guard_kill 1
    ckf "killall"     guard_kill -1
    ckf "umount-prod" guard_umount "/storage/emulated"
    ckf "rm-empty"    rm ""

    # ── `..` 绕过（原实现只去尾斜杠，字面比对直接放行）──
    # SAFE_ROOT=/data/local/tmp/nsp_safe 共 4 层，`../../../..` 回到 /；
    # 于是该串与 /data/media/0 等价，必须命中生产路径。
    ck  "dotdot-prod"    _is_prod "$SAFE_ROOT/../../../../data/media/0"
    ckf "dotdot-write"   assert_writable "$SAFE_ROOT/../../../../data/media/0/x" t
    ckf "dotdot-umount"  guard_umount "$SAFE_ROOT/../../../../data/media"
    # 归一不能误伤：合法 scratch 路径仍放行
    ckf "dotdot-safe"    _is_prod "$SAFE_ROOT/a/../b"
    ck  "norm-collapse"  _eq "$(_norm "$SAFE_ROOT/a/../b")" "$SAFE_ROOT/b"
    ck  "norm-root"      _eq "$(_norm "/a/../../..")" "/"

    # ── 符号链接绕过（需真实可写文件系统；不可用时跳过并如实报告）──
    # 链接目标用 /mnt：它同时是 PROD_PATHS 成员且在 Android 与 GNU 上都真实存在，
    # 于是本组既能覆盖设备侧、也能在开发机自检（用 /data/media 在 GNU 上解析不出，
    # 会退化成字面比对而误判 FAIL）。
    #
    # 建/删这个链接必须用 `command rm`（绕过影子 rm）：影子 rm 会把「解析后落在
    # 生产路径」的路径一律拒绝，而**删软链本身并不触碰目标**——那是本自检的清理
    # 动作，被自己的守卫拦下会让 selftest 直接 die（本轮实测踩到）。
    if mkdir -p "$SAFE_ROOT" 2>/dev/null; then
        _lnk=$SAFE_ROOT/_selftest_link
        command rm -f "$_lnk" 2>/dev/null
        if ln -s /mnt "$_lnk" 2>/dev/null; then
            ck  "symlink-prod"   _is_prod "$_lnk/0"
            ckf "symlink-write"  assert_writable "$_lnk/0/x" t
            ckf "symlink-umount" guard_umount "$_lnk/0"
        else
            echo "SKIP symlink 组（无法在 $SAFE_ROOT 建软链）——该 3 项不计入断言数"
        fi
        command rm -f "$_lnk" 2>/dev/null
    else
        echo "SKIP symlink 组（$SAFE_ROOT 不可写）——该 3 项不计入断言数"
    fi

    if [ "$fails" = 0 ]; then
        echo "SELFTEST_OK $n/$n"
        return 0
    fi
    echo "SELFTEST_FAIL $fails（共 $n 项）"
    return 1
}

# 字符串相等断言（供自检用，避免在 ck 参数里写 [ ] 被当成命令名）
_eq() { [ "$1" = "$2" ]; }

case "${0##*/}" in
    adb-safe.sh)
        # 必须显式 exit：末条 `[ ... ] && cmd` 为假时脚本会以 1 退出——自检全过
        # 也报失败（原实现的假红），自动化里无法区分通过与失败。
        if [ "${1:-}" = selftest ]; then
            adb_safe_selftest
            exit $?
        fi
        if [ "${1:-}" = install-shims ]; then
            install_shims
            exit $?
        fi
        ;;
esac
