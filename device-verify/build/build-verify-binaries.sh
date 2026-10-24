#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later WITH Fuse-Proxy-module-exception
#
# build-verify-binaries.sh — 构建「隔离配置根」的 Android 验证版二进制
#
# 目的：产出可直接推到设备的验证版 injector / fuse_daemon / log_monitor /
# rule_server / log_ctl / ftp_module.so，其编译期 NSP_CONFIG_DIR 指向
# /data/local/tmp/nsp_verify/config，从而与生产配置根 /data/Namespace-Proxy
# 完全隔离（设备验证不会读到、也写不到生产配置）。
#
# 做法（不修改仓库任何源码）：
#   1) 复制 include/nsp_constants.h 到生成目录，仅把 Android 分支的
#      "#define NSP_CONFIG_DIR "/data/Namespace-Proxy"" 一行替换为验证路径，
#      其余逐字不变（NSP_STORAGE_BASE 仍为 /data/media）；
#   2) 用 scripts/android-build.sh 交叉构建，并向 meson 传
#      c_args = -include<生成头绝对路径>（**必须是单个参数、无空格无逗号**）。
#      强制包含先定义 NSP_CONSTANTS_H，使真实头被 include guard 跳过，
#      全项目（含 libfuse/json-c/curl 子项目）统一使用覆盖后的常量；
#   3) 收集产物到 device-verify/dist/bin/ 并用 strings 硬校验（含验证路径、
#      不含生产路径），把大小/sha256/构建元信息写入 BUILD-INFO.txt。
#
# 幂等：可重复执行；已配置的构建目录走 meson reconfigure。
# 安全：不修改仓库源码、不 git commit；运行结束校验工作树未新增已跟踪改动。
#
# 用法：
#   device-verify/build/build-verify-binaries.sh [--clean] [--no-build]
#   -h | --help   显示帮助
#
# 环境变量：
#   NSP_VERIFY_GEN_DIR       生成头目录（默认 <repo>/device-verify/build/.gen）
#   NSP_VERIFY_LIBSSH2_DIR   libssh2/mbedTLS 预构建根（默认
#                            $HOME/.cache/fuse-proxy-android/sftp；SFTP 探针必需）
#   NSP_VERIFY_BUILD_DIR     meson 构建目录（默认 <repo>/build_android_verify）
#   ANDROID_API / ANDROID_NDK_HOME  交给 scripts/android-build.sh 处理
#
# 退出码：0 成功；1 失败（错误信息含可操作提示）。

set -euo pipefail

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------
readonly ARTIFACTS=(injector fuse_daemon log_monitor rule_server log_ctl ftp_module.so)
readonly VERIFY_CONFIG_DIR="/data/local/tmp/nsp_verify/config"
readonly PROD_CONFIG_DIR="/data/Namespace-Proxy"
readonly PROD_CONFIG_LINE="#define NSP_CONFIG_DIR \"${PROD_CONFIG_DIR}\""

# ---------------------------------------------------------------------------
# 输出助手
# ---------------------------------------------------------------------------
info() { printf '==> %s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

usage() {
    cat <<'EOF'
用法: build-verify-binaries.sh [选项]

构建编译期配置根为 /data/local/tmp/nsp_verify/config 的 Android 验证版二进制。

选项:
  --clean      删除 meson 构建目录与生成头目录后从零重建（幂等，耗时数分钟）
  --no-build   不编译，仅重新复制/校验已有产物（用于纯收集或校验）
  -h, --help   显示本帮助

环境变量:
  NSP_VERIFY_GEN_DIR       生成头目录，默认 <repo>/device-verify/build/.gen
                           （路径不得含空格/逗号——meson 的 -Dc_args 限制）
  NSP_VERIFY_LIBSSH2_DIR   libssh2/mbedTLS 预构建根，默认
                           $HOME/.cache/fuse-proxy-android/sftp
                           缺失时先运行 scripts/build-libssh2-android.sh
  NSP_VERIFY_BUILD_DIR     meson 构建目录，默认 <repo>/build_android_verify
  ANDROID_API              目标 API 级别（默认 35，见 scripts/android-build.sh）
  ANDROID_NDK_HOME         NDK 路径（默认自动搜索）

产物:
  device-verify/dist/bin/{injector,fuse_daemon,log_monitor,rule_server,log_ctl,ftp_module.so}
  device-verify/dist/bin/BUILD-INFO.txt

示例:
  device-verify/build/build-verify-binaries.sh            # 增量构建 + 收集
  device-verify/build/build-verify-binaries.sh --clean    # 从零重建
  device-verify/build/build-verify-binaries.sh --no-build # 只收集校验
EOF
}

# ---------------------------------------------------------------------------
# 参数解析
# ---------------------------------------------------------------------------
CLEAN=0
NO_BUILD=0
while [ "$#" -gt 0 ]; do
    case "$1" in
        --clean)    CLEAN=1 ;;
        --no-build) NO_BUILD=1 ;;
        -h|--help)  usage; exit 0 ;;
        --)         shift; break ;;
        *)          die "未知参数：$1（用 -h 查看用法）" ;;
    esac
    shift
done
[ "$#" -eq 0 ] || die "多余的参数：$*（本脚本不接受位置参数）"
if [ "$CLEAN" -eq 1 ] && [ "$NO_BUILD" -eq 1 ]; then
    die "--clean 与 --no-build 互斥（前者要求重建，后者要求不构建）"
fi

# ---------------------------------------------------------------------------
# 路径定位与工作目录
# ---------------------------------------------------------------------------
SCRIPT_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
SCRIPT_DIR="$(dirname "$SCRIPT_PATH")"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
[ -f "$REPO_ROOT/meson.build" ] || die "无法定位仓库根（$SCRIPT_DIR 上两级缺 meson.build）；本脚本必须放在 <repo>/device-verify/build/ 下"
[ -f "$REPO_ROOT/scripts/android-build.sh" ] || die "找不到 $REPO_ROOT/scripts/android-build.sh（仓库结构已变）"
[ -x "$REPO_ROOT/scripts/android-build.sh" ] || die "$REPO_ROOT/scripts/android-build.sh 不可执行（chmod +x）"
[ -f "$REPO_ROOT/include/nsp_constants.h" ] || die "找不到 $REPO_ROOT/include/nsp_constants.h"

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/nsp-verify-build.XXXXXX")"
HEADER_TMP=""
cleanup() {
    [ -n "${HEADER_TMP:-}" ] && rm -f -- "$HEADER_TMP" 2>/dev/null || true
    [ -n "${WORK_DIR:-}" ] && rm -rf -- "$WORK_DIR" 2>/dev/null || true
}
trap cleanup EXIT

abspath() {
    if command -v realpath >/dev/null 2>&1; then
        realpath -m -- "$1"
    else
        case "$1" in
            /*) printf '%s\n' "$1" ;;
            *)  printf '%s/%s\n' "$PWD" "$1" ;;
        esac
    fi
}

GEN_DIR="${NSP_VERIFY_GEN_DIR:-$REPO_ROOT/device-verify/build/.gen}"
BUILD_DIR="${NSP_VERIFY_BUILD_DIR:-$REPO_ROOT/build_android_verify}"
DIST_DIR="$REPO_ROOT/device-verify/dist/bin"

GEN_DIR="$(abspath "$GEN_DIR")"
BUILD_DIR="$(abspath "$BUILD_DIR")"
GEN_HEADER="$GEN_DIR/nsp_constants.h"

if [ -z "${NSP_VERIFY_LIBSSH2_DIR:-}" ]; then
    LIBSSH2_DIR="${HOME:-/root}/.cache/fuse-proxy-android/sftp"
else
    LIBSSH2_DIR="$NSP_VERIFY_LIBSSH2_DIR"
fi
LIBSSH2_DIR="$(abspath "$LIBSSH2_DIR")"

# 构建目录在仓库内时传相对路径（android-build.sh 会 cd 到仓库根）。
BUILD_ARG="$BUILD_DIR"
case "$BUILD_DIR" in
    "$REPO_ROOT"/*) BUILD_ARG="${BUILD_DIR#"$REPO_ROOT"/}" ;;
esac

# 强制包含的路径限制：meson 的 -Dc_args 是单参数，空格会被拆成多个参数、
# 逗号会被并进文件名导致编译失败。
case "$GEN_HEADER" in
    *' '*|*$'\t'*|*,*)
        die "生成头路径含空格/制表符/逗号，无法作为 -include 单参数传给 meson：
       $GEN_HEADER
       请用 NSP_VERIFY_GEN_DIR 指向无空格、无逗号的目录。"
        ;;
esac

# libssh2 预构建必须在源码树之外：meson 的 cmake 子项目会忽略「源码树内、
# 子项目外」的 include 路径（症状是 curl 编译到 libssh2 头文件才报找不到）。
case "$LIBSSH2_DIR/" in
    "$REPO_ROOT"/*)
        die "NSP_VERIFY_LIBSSH2_DIR 不能位于仓库源码树内：$LIBSSH2_DIR
       meson 的 cmake 子项目会忽略源码树内的 include 路径；请用默认的
       \$HOME/.cache/fuse-proxy-android/sftp 或源码树外的其它目录。"
        ;;
esac

# ---------------------------------------------------------------------------
# 安全删除（--clean 用）：拒绝危险路径，构建目录必须是 meson 构建目录
# ---------------------------------------------------------------------------
safe_rm_tree() {
    local dir="$1" marker="${2:-}"
    [ -e "$dir" ] || return 0
    case "$dir" in
        ""|"/"|"$HOME"|"$REPO_ROOT"|"$DIST_DIR")
            die "拒绝删除危险路径：$dir" ;;
    esac
    if [ -n "$marker" ] && [ ! -e "$dir/$marker" ]; then
        die "拒绝删除 $dir：缺少标记 $marker，看起来不是预期目录（如需删除请手动处理）"
    fi
    rm -rf -- "$dir"
}

# ---------------------------------------------------------------------------
# [1/3] 生成隔离配置头
# ---------------------------------------------------------------------------
generate_header() {
    local src="$REPO_ROOT/include/nsp_constants.h"
    local n_src lines_src lines_gen new_hits prod_hits prod_def_hits changes
    local sb_src sb_gen

    mkdir -p -- "$GEN_DIR" || die "无法创建生成目录：$GEN_DIR"

    # 前提：源头恰有 1 行 Android 分支定义（GNU 分支是 /var/fuse-proxy，不匹配）。
    n_src=$(grep -c -x -F -- "$PROD_CONFIG_LINE" "$src" || true)
    if [ "$n_src" -ne 1 ]; then
        die "源头 $src 中整行等于
       $PROD_CONFIG_LINE
       的定义应恰有 1 行，实际 $n_src 行——上游格式已变。
       请同步更新本脚本的替换规则（不要改源码来迁就脚本）。"
    fi

    HEADER_TMP="$GEN_HEADER.tmp.$$"
    sed "s|^#define NSP_CONFIG_DIR \"$PROD_CONFIG_DIR\"\$|#define NSP_CONFIG_DIR \"$VERIFY_CONFIG_DIR\"|" \
        "$src" > "$HEADER_TMP"

    # --- 硬校验：任一失败立即退出，绝不拿半成品去编译 ---
    lines_src=$(wc -l < "$src")
    lines_gen=$(wc -l < "$HEADER_TMP")
    if [ "$lines_src" -ne "$lines_gen" ]; then
        die "生成头行数变化：$lines_src -> $lines_gen（替换应只改一行内容，不增删行）"
    fi

    new_hits=$(grep -c -F -- "$VERIFY_CONFIG_DIR" "$HEADER_TMP" || true)
    if [ "$new_hits" -ne 1 ]; then
        die "生成头中含 '$VERIFY_CONFIG_DIR' 的行应恰为 1，实际 $new_hits——替换规则未命中"
    fi

    # 口径说明：include/nsp_constants.h 的**注释**里本身就出现该路径字面量（平台根
    # 说明文字），而本脚本要求「其余逐字不变」，故这里校验的是「不再有以生产路径
    # 定义 NSP_CONFIG_DIR 的行」；注释未被改动由下面的「差异恰 2 行」保证。二进制
    # 层面另由 collect() 的 strings 校验（注释不进二进制，产物中生产路径必须 0 处）。
    prod_def_hits=$(grep -c -x -F -- "$PROD_CONFIG_LINE" "$HEADER_TMP" || true)
    if [ "$prod_def_hits" -ne 0 ]; then
        die "生成头仍有以生产路径定义 NSP_CONFIG_DIR 的行（$prod_def_hits 行）——替换未生效"
    fi
    prod_hits=$(grep -c -F -- "$PROD_CONFIG_DIR" "$HEADER_TMP" || true)
    if [ "$prod_hits" -gt 0 ]; then
        printf '    提示：生成头另有 %s 行注释提及生产路径（源头注释原文，按「逐字不变」保留）\n' "$prod_hits"
    fi

    # NSP_STORAGE_BASE 两行必须逐字不变（验证版仍用 /data/media）。
    sb_src=$(grep -E '^#define[[:space:]]+NSP_STORAGE_BASE[[:space:]]' "$src" || true)
    sb_gen=$(grep -E '^#define[[:space:]]+NSP_STORAGE_BASE[[:space:]]' "$HEADER_TMP" || true)
    [ -n "$sb_src" ] || die "源头未找到 NSP_STORAGE_BASE 定义（上游已变）"
    if [ "$sb_src" != "$sb_gen" ]; then
        die "NSP_STORAGE_BASE 定义被意外改动：
--- 源 ---
$sb_src
--- 生成 ---
$sb_gen"
    fi

    # 全文差异必须恰好 2 行（删 1 行 + 加 1 行），即其余逐字不变。
    changes=$(diff -u "$src" "$HEADER_TMP" | grep -cE '^[+-][^+-]' || true)
    if [ "$changes" -ne 2 ]; then
        die "生成头与源头的差异行数为 $changes（期望 2：删 1 行 + 加 1 行）——替换范围超出预期"
    fi

    mv -f -- "$HEADER_TMP" "$GEN_HEADER"
    HEADER_TMP=""

    info "生成头：$GEN_HEADER"
    printf '    NSP_CONFIG_DIR    : %s\n' "$VERIFY_CONFIG_DIR"
    printf '    NSP_STORAGE_BASE  : 保持不变（/data/media）\n'
    printf '    sha256            : %s\n' "$(sha256sum -- "$GEN_HEADER" | cut -d' ' -f1)"
}

# ---------------------------------------------------------------------------
# [2/3] 交叉构建
# ---------------------------------------------------------------------------
build_verify() {
    local -a cmd

    [ -d "$LIBSSH2_DIR/lib" ] || die "libssh2 预构建目录不存在或不完整：$LIBSSH2_DIR
       SFTP 探针（proto=sftp）必需 libssh2；请先运行：
           scripts/build-libssh2-android.sh
       或用 NSP_VERIFY_LIBSSH2_DIR=<预构建根> 指定已有目录
       （默认产出 \$HOME/.cache/fuse-proxy-android/sftp）。"

    cmd=( "$REPO_ROOT/scripts/android-build.sh" "$BUILD_ARG"
          -Dsftp=enabled
          -Dlibssh2_dir="$LIBSSH2_DIR"
          -Dc_args="-include$GEN_HEADER" )

    info "交叉构建（$BUILD_ARG，-Dsftp=enabled）"
    printf '    命令：'; printf '%q ' "${cmd[@]}"; printf '\n'

    if ! "${cmd[@]}"; then
        die "交叉构建失败（原因见上方 meson/ninja 输出）。
       常见原因：
         - 未找到 NDK：设置 ANDROID_NDK_HOME 或 ANDROID_API
         - libssh2 预构建缺失：scripts/build-libssh2-android.sh
         - 生成头路径含空格/逗号导致 -include 参数被拆开
       重试：device-verify/build/build-verify-binaries.sh --clean"
    fi
}

# ---------------------------------------------------------------------------
# [3/3] 收集 + strings 硬校验
# ---------------------------------------------------------------------------
VB_HITS=0
VB_PROD=0
verify_binary() {
    local f="$1" hit prod
    if command -v strings >/dev/null 2>&1; then
        hit=$(strings -a -- "$f" | grep -c -F -- "$VERIFY_CONFIG_DIR" || true)
        prod=$(strings -a -- "$f" | grep -c -F -- "$PROD_CONFIG_DIR" || true)
    else
        # 无 binutils 时的等价回退（按行计数的语义差异不影响「有/无」判定）。
        hit=$(LC_ALL=C grep -a -c -F -- "$VERIFY_CONFIG_DIR" "$f" || true)
        prod=$(LC_ALL=C grep -a -c -F -- "$PROD_CONFIG_DIR" "$f" || true)
    fi
    if [ "$hit" -lt 1 ]; then
        die "$(basename -- "$f") 未包含验证配置根 '$VERIFY_CONFIG_DIR'
       → -include 覆盖未生效，或产物是旧的（用 --clean 重建）"
    fi
    if [ "$prod" -ne 0 ]; then
        die "$(basename -- "$f") 仍包含生产配置根 '$PROD_CONFIG_DIR'（$prod 处）
       → 覆盖头未生效或产物陈旧，禁止用于设备验证（用 --clean 重建）"
    fi
    VB_HITS="$hit"
    VB_PROD="$prod"
}

collect() {
    local f src size sha gen_sha head_full head_short now wt_summary
    local -a rows=()
    local info_tmp="$DIST_DIR/BUILD-INFO.txt.tmp.$$"

    mkdir -p -- "$DIST_DIR" || die "无法创建产物目录：$DIST_DIR"

    info "收集并硬校验产物（strings）"
    for f in "${ARTIFACTS[@]}"; do
        src="$BUILD_DIR/$f"
        if [ ! -f "$src" ]; then
            die "缺少产物：$src
       请不带 --no-build 运行本脚本完成构建（或检查构建日志）。"
        fi
        [ -x "$src" ] || die "产物不可执行：$src（构建异常）"

        cp -f -- "$src" "$DIST_DIR/$f"
        chmod 755 -- "$DIST_DIR/$f"
        verify_binary "$DIST_DIR/$f"

        size=$(stat -c %s -- "$DIST_DIR/$f")
        sha=$(sha256sum -- "$DIST_DIR/$f" | cut -d' ' -f1)
        rows+=( "$(printf '  %-14s %10s bytes  verify_hits=%-3s prod_hits=%-2s  sha256=%s' \
                    "$f" "$size" "$VB_HITS" "$VB_PROD" "$sha")" )
        printf '    %-14s OK（验证路径命中 %s 处，生产路径 0 处）\n' "$f" "$VB_HITS"
    done

    gen_sha="n/a（--no-build 且生成头不存在）"
    if [ -f "$GEN_HEADER" ]; then
        gen_sha=$(sha256sum -- "$GEN_HEADER" | cut -d' ' -f1)
    fi
    head_full=$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo "unknown")
    head_short=$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo "unknown")
    now=$(date '+%Y-%m-%dT%H:%M:%S%z')
    wt_summary=$(git -C "$REPO_ROOT" status --porcelain | grep -v '^?? device-verify/' | grep -v '^$' | head -5 | tr '\n' ' ' || true)
    if [ -z "$wt_summary" ]; then
        wt_summary="clean（仅 device-verify/ 下未跟踪文件）"
    fi

    {
        printf 'Fuse-Proxy Android 验证版二进制（隔离配置根）\n'
        printf '================================================================\n'
        printf '构建时间      : %s\n' "$now"
        printf 'git HEAD      : %s (%s)\n' "$head_full" "$head_short"
        printf '工作树         : %s\n' "$wt_summary"
        printf '验证配置根    : %s\n' "$VERIFY_CONFIG_DIR"
        printf '生产配置根    : %s（产物中必须 0 处）\n' "$PROD_CONFIG_DIR"
        printf '构建目录      : %s\n' "$BUILD_DIR"
        printf '生成头        : %s\n' "$GEN_HEADER"
        printf '生成头 sha256 : %s\n' "$gen_sha"
        printf 'SFTP 预构建   : %s\n' "$LIBSSH2_DIR"
        printf 'meson 参数    : -Dsftp=enabled -Dlibssh2_dir=%s -Dc_args=-include%s\n' "$LIBSSH2_DIR" "$GEN_HEADER"
        printf '构建命令      : scripts/android-build.sh %s -Dsftp=enabled -Dlibssh2_dir=%s -Dc_args=-include%s\n' \
            "$BUILD_ARG" "$LIBSSH2_DIR" "$GEN_HEADER"
        printf '\n产物（全部经 strings 校验：含验证路径、无生产路径）：\n'
        printf '%s\n' "${rows[@]}"
        printf '\n校验方法: strings -a <file> | grep -c -F <路径>；每文件验证路径命中 >=1 且生产路径命中 =0\n'
        printf '生成方式: 复制 include/nsp_constants.h 并仅替换 Android 分支 NSP_CONFIG_DIR 一行；\n'
        printf '          构建时以 -include<生成头> 强制包含（先定义 NSP_CONSTANTS_H，真实头被 guard 跳过）。\n'
    } > "$info_tmp"
    mv -f -- "$info_tmp" "$DIST_DIR/BUILD-INFO.txt"

    printf '%s\n' "${rows[@]}"
    printf '    BUILD-INFO.txt：%s\n' "$DIST_DIR/BUILD-INFO.txt"
}

# ---------------------------------------------------------------------------
# 工作树不变量：不得引入对已跟踪文件的修改
# ---------------------------------------------------------------------------
STATUS_BEFORE="$WORK_DIR/status.before"
git -C "$REPO_ROOT" status --porcelain > "$STATUS_BEFORE" 2>/dev/null || true

check_worktree() {
    local status_after="$WORK_DIR/status.after"
    local new_entries bad pre
    git -C "$REPO_ROOT" status --porcelain > "$status_after" 2>/dev/null || true

    # 运行前就存在的未提交改动不属于本脚本（例如 Lead 的并行工作），仅提示。
    pre=$(grep -v '^?? device-verify/' "$STATUS_BEFORE" | grep -v '^$' || true)
    if [ -n "$pre" ]; then
        warn "运行前工作树已有未提交改动（非本脚本造成，未触碰）："
        printf '%s\n' "$pre" | sed 's/^/         /' >&2
    fi

    # 新增条目里只允许 device-verify/ 下的未跟踪文件。
    new_entries=$(comm -13 <(sort "$STATUS_BEFORE") <(sort "$status_after") || true)
    bad=$(printf '%s\n' "$new_entries" | grep -v '^?? device-verify/' | grep -v '^$' || true)
    if [ -n "$bad" ]; then
        die "本脚本引入了对已跟踪文件的修改（不允许）：
$bad
       请恢复：git -C \"$REPO_ROOT\" checkout -- <上述文件>；并检查脚本是否误写了源码。"
    fi

    if ! git -C "$REPO_ROOT" diff --quiet -- include/nsp_constants.h; then
        die "include/nsp_constants.h 被修改（必须保持原样）；请 git checkout -- include/nsp_constants.h"
    fi

    info "工作树校验通过：未新增对已跟踪文件的修改（device-verify/ 下未跟踪文件除外）"
}

# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------
START_SECONDS=$SECONDS

printf 'Fuse-Proxy 验证版 Android 二进制构建\n'
printf '  仓库根      : %s\n' "$REPO_ROOT"
printf '  生成头目录  : %s\n' "$GEN_DIR"
printf '  构建目录    : %s\n' "$BUILD_DIR"
printf '  产物目录    : %s\n' "$DIST_DIR"
printf '  SFTP 预构建 : %s\n' "$LIBSSH2_DIR"
printf '\n'

if [ "$CLEAN" -eq 1 ]; then
    info "[0/3] --clean：删除构建目录与生成头目录"
    safe_rm_tree "$BUILD_DIR" "meson-private"
    safe_rm_tree "$GEN_DIR" ""
    printf '    已清理。\n'
fi

if [ "$NO_BUILD" -eq 1 ]; then
    info "[1/3] 跳过生成头（--no-build）"
    info "[2/3] 跳过构建（--no-build）"
else
    info "[1/3] 生成隔离配置头"
    generate_header
    info "[2/3] 交叉构建"
    build_verify
fi

collect
check_worktree

ELAPSED=$(( SECONDS - START_SECONDS ))
printf '\n'
info "完成（耗时 ${ELAPSED}s）"
printf '  脚本    : %s\n' "$SCRIPT_PATH"
printf '  产物    : %s/（6 个二进制，全部含 %s）\n' "$DIST_DIR" "$VERIFY_CONFIG_DIR"
printf '  构建信息: %s/BUILD-INFO.txt\n' "$DIST_DIR"
printf '  下一步  : 将 %s/ 推送到设备 /data/local/tmp/nsp_verify/bin/ 后按设备验证流程执行\n' "$DIST_DIR"
exit 0
