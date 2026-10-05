#!/usr/bin/env bash
# 设备测试会话 wrapper（宿主侧，生产级隔离的最后一道门）
# ============================================================
# 本仓库一切设备操作必须经此脚本执行，禁止裸 `adb shell` 做变更：
#   scripts/adb-sh.sh [--unsafe-ok] '<device command>'
#   scripts/adb-sh.sh push <local> <remote>   # 仅允许推到 /data/local/tmp
#
# 强制项（每会话）：
#   1. 设备侧 PATH 前置垫片目录 + source adb-safe.sh + set -u，
#      影子函数对会话内一切命令默认生效（含 rm/umount/kill/dd 等）。
#   2. 命令文本预检：变更动词（rm/mv/cp/dd/tee/chmod/chown/chcon/umount/
#      mkfs/restorecon/setenforce/kill + 输出重定向 >）一旦触及生产路径
#      文本（/data/media /storage /mnt /data/user /data/data /data/adb
#      /system /vendor /apex），直接拒绝；确需例外时加 --unsafe-ok
#     （仅限已评审场景，用后须在提交信息/汇报中说明）。
#   3. 全程日志：starter 行打印到 stderr，审计可查。
# 说明：文本预检是启发式兜底（防手误/变量展开类事故，非防恶意绕过）；
# 真正的强制执行在设备侧 harness（路径归一判定 + 挂载点检查）。
# ============================================================
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
SAFE_SH=/data/local/tmp/adb-safe.sh
SHIM_DIR=/data/local/tmp/nsp_safe/bin

# shellcheck disable=SC2068
die() { echo "[adb-sh] FATAL: $*" >&2; exit 1; }

MUTATE='rm|mv|cp|dd|tee|chmod|chown|chcon|umount|mkfs|restorecon|setenforce|kill|mkswap|mknod'
# 输出重定向到文件才算变更（2>&1 这类 stderr 合并除外）
REDIR='(^|[^0-9])>[^&]'
# 动词类禁区：与变更动词同现即拒绝（读不影响）
PROD='/data/media|/storage|/mnt/|/data/user|/data/data|/data/adb|/system|/vendor|/apex|/data_mirror|/dev/fuse'
# 重定向类禁区：仅当重定向目标落入其中才拒绝（/proc/mounts 这类只读不在此列；
# /proc/sys/vm/drop_caches 是合法的性能 hygiene，单列豁免）
PROD_REDIR='/proc|/sys|/dev/'

UNSAFE_OK=0
if [ "${1:-}" = "--unsafe-ok" ]; then
    UNSAFE_OK=1
    shift
    echo "[adb-sh] 警告：已加 --unsafe-ok，跳过文本预检（须有评审依据）" >&2
fi

ensure_harness() {
    adb push "$HERE/adb-safe.sh" "$SAFE_SH" >/dev/null 2>&1 \
        || die "推送 harness 失败，检查 adb 连接"
}

bootstrap() {
    # $1 = 实际命令（已做文本预检）
    printf 'export PATH=%s:$PATH; . %s; set -u; %s' "$SHIM_DIR" "$SAFE_SH" "$1"
}

prescan() {
    # $1 = 命令文本；两条独立规则（--unsafe-ok 跳过，调用方已警告并承担评审责任）
    [ "$UNSAFE_OK" = 1 ] && return 0
    local cmd=$1
    if echo "$cmd" | grep -Eq "($MUTATE)"; then
        if echo "$cmd" | grep -Eq "($PROD)"; then
            die "文本预检拒绝：变更命令触及生产路径。如确需执行，加 --unsafe-ok（须评审）: $cmd"
        fi
    fi
    # 重定向目标检查：只看 > 后面的目标路径
    local tgts
    tgts=$(echo "$cmd" | grep -oE "$REDIR[^ |;\"]*" | sed -E 's/^[^>]*>//')
    for t in $tgts; do
        case "$t" in /proc/sys/vm/drop_caches) continue;; esac
        if echo "$t" | grep -Eq "($PROD|$PROD_REDIR)"; then
            die "文本预检拒绝：重定向目标触及禁区：$t。如确需执行，加 --unsafe-ok（须评审）"
        fi
    done
}

cmd_shell() {
    ensure_harness
    prescan "$1"
    echo "[adb-sh] adb shell: $1" >&2
    # shellcheck disable=SC2029
    adb shell "$(bootstrap "$1")"
}

cmd_push() {
    # $1=本地 $2=远端：远端只允许 /data/local/tmp 下
    case "$2" in
        /data/local/tmp/*) ;;
        *) die "push 目标只允许 /data/local/tmp 下：$2" ;;
    esac
    adb push "$1" "$2"
}

case "${1:-}" in
    push) shift; [ $# -eq 2 ] || die "用法: adb-sh.sh push <本地> <远端>"; cmd_push "$@" ;;
    ""|-h|--help) sed -n '2,16p' "$0" ;;
    *) cmd_shell "$@" ;;
esac
