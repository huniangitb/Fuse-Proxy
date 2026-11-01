#!/usr/bin/env bash
# Fuse-Proxy 验收门（一条命令跑完，逐门出 PASS/FAIL 并落报告）
#
# 把 docs/testing.md §4 的验收门变成可执行的单一入口。此前各门散落在不同命令里，
# 全靠人工逐条照做：漏跑哪一门、哪一门是上次的旧结果，事后无从对账。
#
#   scripts/acceptance.sh                  # 跑默认门（G1 G2 G3 G4 G9；G9 快，故默认跑）
#   scripts/acceptance.sh --list           # 看门清单，不跑
#   scripts/acceptance.sh --only G3,G4     # 只跑指定门
#   scripts/acceptance.sh --only G9        # 只跑「ACL 不干扰」（真 daemon 功能预期）
#   scripts/acceptance.sh --with-asan      # 追加 G5（ASan+UBSan 复跑，重）
#   scripts/acceptance.sh --with-isolated  # 追加 G6（宿主零污染隔离跑，重）
#   scripts/acceptance.sh --all-gates      # G1..G6 与 G9 全跑
#   scripts/acceptance.sh --skip-android   # 无 NDK 时跳过 G2（计为 SKIP 而非 PASS）
#
# 报告落 .acceptance/<时间戳>/：每门一份日志 + summary.txt 汇总。
#
# 退出码：0 全部 PASS；1 存在 FAIL；2 存在 SKIP 但无 FAIL（验收不完整，需人工确认）。
# SKIP 不计通过——这是本仓库的一贯约定（见 docs/testing.md §2），别把 2 当成绿。
#
# 两条脚本代劳不了的门（G7 判别性、G8 层级诚实）在 summary 末尾以清单形式提示，
# 需人工确认后才算验收完成。
set -uo pipefail

cd "$(dirname "$0")/.."
ROOT="$(pwd)"

STAMP="$(date +%Y%m%d-%H%M%S)"
OUT="$ROOT/.acceptance/$STAMP"
mkdir -p "$OUT"

# ── 宿主垫片剥离（见 docs/testing.md §7）──────────────────────────────
# WorkBuddy/CodeBuddy CLI 注入的 PYTHONPATH（sitecustomize 把 unlink/rmtree 重定向
# 到回收站）与 BASH_ENV（safe-bin 垫 PATH）会让删文件的套件假失败。测试一律在剥离
# 后的环境里跑，否则 G4 会以 PermissionError: /.Trash-1000 失败，看着像产品缺陷。
CLEAN_ENV=(env -u PYTHONPATH -u BASH_ENV
           PATH="/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin")

GNU_DIR="${GNU_BUILD_DIR:-build_gnu}"
ANDROID_DIR="${ANDROID_BUILD_DIR:-build_android}"
ASAN_DIR="${ASAN_BUILD_DIR:-build_asan2}"

RUN_GATES="G1 G2 G3 G4 G9"
WITH_ASAN=0
WITH_ISOLATED=0
SKIP_ANDROID=0
ONLY=""

usage() { sed -n '2,30p' "$0" | sed 's/^# \?//'; }

while [ $# -gt 0 ]; do
    case "$1" in
        --list)
            printf '%s\n' \
                "G1  构建-GNU         $GNU_DIR 全量重建 + 零新增代码告警" \
                "G2  构建-Android     NDK 交叉构建 + zygisk .so 无 libc++_shared" \
                "G3  文档/台账一致性   tests/test_docs_sync.py" \
                "G4  全量测试         tests/run.py --all --strict" \
                "G9  ACL 不干扰       真 daemon 挂载视图的功能预期（ACL 不得误拦）" \
                "G5  内存安全(可选)    $ASAN_DIR 下复跑核心套件（--with-asan）" \
                "G6  宿主隔离(可选)    scripts/test-isolated.sh（--with-isolated）" \
                "G7  判别性(人工)      新用例须在旧实现上失败" \
                "G8  层级诚实(人工)    结论写清覆盖到哪层"
            exit 0 ;;
        --only)     ONLY="${2:-}"; shift 2 ;;
        --only=*)   ONLY="${1#*=}"; shift ;;
        --with-asan)     WITH_ASAN=1; shift ;;
        --with-isolated) WITH_ISOLATED=1; shift ;;
        --all-gates)     WITH_ASAN=1; WITH_ISOLATED=1; shift ;;
        --skip-android)  SKIP_ANDROID=1; shift ;;
        -h|--help)  usage; exit 0 ;;
        *) echo "未知参数：$1（--help 看用法）" >&2; exit 1 ;;
    esac
done

[ "$WITH_ASAN" = 1 ]     && RUN_GATES="$RUN_GATES G5"
[ "$WITH_ISOLATED" = 1 ] && RUN_GATES="$RUN_GATES G6"
if [ -n "$ONLY" ]; then
    RUN_GATES="$(printf '%s' "$ONLY" | tr ',' ' ')"
fi

wanted() { case " $RUN_GATES " in *" $1 "*) return 0 ;; *) return 1 ;; esac; }

# ── 结果记账 ──────────────────────────────────────────────────────────
declare -A VERDICT NOTE
ORDER=""

record() {  # record <门> <PASS|FAIL|SKIP> <说明>
    VERDICT["$1"]="$2"; NOTE["$1"]="$3"
    case " $ORDER " in *" $1 "*) ;; *) ORDER="$ORDER $1" ;; esac
    local mark
    case "$2" in
        PASS) mark="✅" ;;
        FAIL) mark="❌" ;;
        *)    mark="⏭" ;;
    esac
    printf '%s %-3s %-6s %s\n' "$mark" "$1" "$2" "$3"
}

banner() { printf '\n%s\n▶ %s\n%s\n' "$(printf '━%.0s' {1..66})" "$1" \
                  "$(printf '━%.0s' {1..66})"; }

# 统计本次构建日志里的**代码**告警：排除 lto-wrapper 的 LTRANS 提示与
# subprojects/ 第三方源码（第三方告警不是我们的回归基线，见 docs/testing.md §4）。
count_code_warnings() {
    grep -E '(warning:|警告：)' "$1" 2>/dev/null \
        | grep -v 'lto-wrapper' \
        | grep -v '/subprojects/' \
        | grep -cv '^$' || true
}

# ── G1 构建-GNU ───────────────────────────────────────────────────────
if wanted G1; then
    banner "G1 构建-GNU（$GNU_DIR 全量重建，零新增代码告警）"
    LOG="$OUT/G1-build-gnu.log"
    if ! command -v meson >/dev/null 2>&1; then
        record G1 SKIP "缺 meson"
    else
        {
            if [ -d "$GNU_DIR" ]; then
                echo "== 已有构建目录，清理后重建（告警需在完整重建下统计）"
                ninja -C "$GNU_DIR" -t clean || true
            else
                echo "== 首次配置 $GNU_DIR"
                meson setup "$GNU_DIR" -Dtarget_os=gnu
            fi
            ninja -C "$GNU_DIR"
        } >"$LOG" 2>&1
        rc=$?
        W="$(count_code_warnings "$LOG")"
        if [ "$rc" -ne 0 ]; then
            record G1 FAIL "构建失败（rc=$rc），见 $(basename "$LOG")"
        elif [ "$W" -gt 0 ]; then
            record G1 FAIL "$W 条代码告警（基线应为 0），见 $(basename "$LOG")"
            grep -E '(warning:|警告：)' "$LOG" | grep -v lto-wrapper \
                | grep -v '/subprojects/' | head -15
        else
            record G1 PASS "构建成功，零代码告警"
        fi
    fi
fi

# ── G2 构建-Android + zygisk ABI 检查 ────────────────────────────────
if wanted G2; then
    banner "G2 构建-Android（NDK 交叉 + zygisk .so 不得链 libc++_shared）"
    LOG="$OUT/G2-build-android.log"
    if [ "$SKIP_ANDROID" = 1 ]; then
        record G2 SKIP "--skip-android 显式跳过"
    else
        scripts/android-build.sh "$ANDROID_DIR" >"$LOG" 2>&1
        rc=$?
        if [ "$rc" -ne 0 ]; then
            if grep -qiE 'NDK|未找到|not found' "$LOG"; then
                record G2 SKIP "NDK 不可用（见 $(basename "$LOG")）"
            else
                record G2 FAIL "交叉构建失败（rc=$rc），见 $(basename "$LOG")"
            fi
        else
            W="$(count_code_warnings "$LOG")"
            # zygisk 双 ABI 必须无 C++ 运行时依赖：它注入 zygote 子进程，
            # 禁 STL（-nostdlib++）。链上 libc++_shared.so 会在目标进程里炸。
            bad=""
            found=0
            for so in "$ANDROID_DIR"/src/zygisk/*.so; do
                [ -e "$so" ] || continue
                found=$((found + 1))
                if readelf -d "$so" 2>/dev/null | grep -q 'libc++_shared'; then
                    bad="$bad $(basename "$so")"
                fi
            done
            if [ "$found" -eq 0 ]; then
                record G2 FAIL "未找到 $ANDROID_DIR/src/zygisk/*.so（产物不齐）"
            elif [ -n "$bad" ]; then
                record G2 FAIL "zygisk .so 链到 libc++_shared：$bad"
            elif [ "$W" -gt 0 ]; then
                record G2 FAIL "$W 条代码告警，见 $(basename "$LOG")"
            else
                record G2 PASS "产物齐全（$found 个 zygisk .so），readelf 无 libc++_shared"
            fi
        fi
    fi
fi

# ── G3 文档/台账一致性 ───────────────────────────────────────────────
if wanted G3; then
    banner "G3 文档/台账一致性（tests/test_docs_sync.py）"
    LOG="$OUT/G3-docs-sync.log"
    "${CLEAN_ENV[@]}" python3 tests/test_docs_sync.py >"$LOG" 2>&1
    rc=$?
    tail -n 24 "$LOG"
    if [ "$rc" -eq 0 ]; then
        record G3 PASS "文档陈述与代码/台账一致"
    else
        record G3 FAIL "rc=$rc，见 $(basename "$LOG")"
    fi
fi

# ── G4 全量测试 ──────────────────────────────────────────────────────
if wanted G4; then
    banner "G4 全量测试（run.py --all --strict）"
    LOG="$OUT/G4-tests.log"
    "${CLEAN_ENV[@]}" python3 tests/run.py --all --strict >"$LOG" 2>&1
    rc=$?
    sed -n '/测试汇总/,$p' "$LOG" | head -60
    if [ "$rc" -eq 0 ]; then
        record G4 PASS "全量全绿，gap=0"
    else
        n_fail="$(grep -c '^  ❌' "$LOG" || true)"
        n_gap="$(grep -c '^  ⏭' "$LOG" || true)"
        record G4 FAIL "rc=$rc（失败 $n_fail、gap $n_gap），见 $(basename "$LOG")"
    fi
fi

# ── G9 ACL 不干扰 ─────────────────────────────────────────────────────
# 判别点：ACL 层的正当性是「补齐 Android 语义」而不是改功能——真 daemon 上以
# 普通应用 uid 做真实文件操作，被误拦的普通读写/REDIRECT/RO 读/ALLOW/沙盒镜像
# 会当场失败。跑得快（无构建、单 daemon），故进默认门集合。
if wanted G9; then
    banner "G9 ACL 不干扰（真 daemon 挂载视图的功能预期）"
    LOG="$OUT/G9-acl-nonintrusive.log"
    "${CLEAN_ENV[@]}" python3 tests/test_acl_nonintrusive.py >"$LOG" 2>&1
    rc=$?
    tail -n 24 "$LOG"
    if [ "$rc" -eq 0 ]; then
        record G9 PASS "功能预期全部成立（$(grep -c '^  ✅' "$LOG" || true) 项）"
    elif [ "$rc" -eq 77 ]; then
        reason="$(grep -m1 '^SKIP:' "$LOG" | sed 's/^SKIP: //')"
        record G9 SKIP "${reason:-环境不具备（见 $(basename "$LOG")）}"
    else
        record G9 FAIL "rc=$rc（$(grep -c '^  ❌' "$LOG" || true) 项功能预期被破坏），见 $(basename "$LOG")"
    fi
fi

# ── G5 内存安全（ASan + UBSan）────────────────────────────────────────
if wanted G5; then
    banner "G5 内存安全复跑（$ASAN_DIR，ASan+UBSan）"
    LOG="$OUT/G5-asan.log"
    if [ ! -d "$ASAN_DIR" ]; then
        record G5 SKIP "$ASAN_DIR 不存在（见 docs/testing.md §5 的 meson setup 命令）"
    else
        # sanitizer 标志必须同时进编译与链接：只进 link_flags 会「链接了运行时但零
        # 插桩」，全绿但什么都没测。核对 compile_commands.json 里确有 -fsanitize。
        if [ -f "$ASAN_DIR/compile_commands.json" ] && \
           ! grep -q 'fsanitize' "$ASAN_DIR/compile_commands.json"; then
            record G5 FAIL "$ASAN_DIR 的 compile_commands.json 无 -fsanitize：零插桩，结果不可信"
        else
            rm -f /tmp/asanrep.* /tmp/ubsanrep.* 2>/dev/null || true
            # 落盘报告是必需的：套件把 daemon 的 stderr 重定向走，sanitizer 报错会被吞。
            # 后端对象有意 immortal（ftp_backend_add：条目永不 free）→ detect_leaks=0。
            cat >"$OUT/g5-run.sh" <<EOF
set -u
export FUSE_DAEMON="$ROOT/$ASAN_DIR/fuse_daemon"
export FTP_MODULE_SO="$ROOT/$ASAN_DIR/ftp_module.so"
export LOG_CTL="$ROOT/$ASAN_DIR/log_ctl"
export LOG_MONITOR="$ROOT/$ASAN_DIR/log_monitor"
export ASAN_OPTIONS="log_path=/tmp/asanrep:detect_leaks=0:print_stacktrace=1:allocator_release_to_os_interval_ms=-1"
export UBSAN_OPTIONS="log_path=/tmp/ubsanrep:print_stacktrace=1"
cd "$ROOT"
python3 tests/run.py --strict \\
    test_rules.py test_functional.py test_decision_enforce.py \\
    test_negative_timeout.py test_modules.py test_backend_lifecycle.py \\
    test_log_pipeline.py
EOF
            # 落盘脚本再 sh 执行：env 赋值若出现在外层命令行里，会被套件的
            # `pkill -f fuse_daemon` 连带杀掉（见 docs/testing.md §7）。
            "${CLEAN_ENV[@]}" sh "$OUT/g5-run.sh" >"$LOG" 2>&1
            rc=$?
            # 只认 interceptor 报告；本环境的 munmap error code 22 是 ASan 噪声。
            rep="$(grep -lE 'heap-buffer-overflow|heap-use-after-free|stack-buffer-overflow|use-after-free|LeakSanitizer|runtime error' \
                   /tmp/asanrep.* /tmp/ubsanrep.* 2>/dev/null | head -5)"
            if [ -n "$rep" ]; then
                cp /tmp/asanrep.* /tmp/ubsanrep.* "$OUT/" 2>/dev/null || true
                record G5 FAIL "sanitizer 报告：$(echo "$rep" | tr '\n' ' ')（已复制到报告目录）"
            elif [ "$rc" -ne 0 ]; then
                record G5 FAIL "套件 rc=$rc（无 sanitizer 报告，属功能失败），见 $(basename "$LOG")"
            else
                record G5 PASS "核心套件全绿，无 interceptor 报告"
            fi
        fi
    fi
fi

# ── G6 宿主零污染隔离 ────────────────────────────────────────────────
if wanted G6; then
    banner "G6 宿主零污染隔离跑（scripts/test-isolated.sh）"
    LOG="$OUT/G6-isolated.log"
    if ! unshare --user --map-root-user true 2>/dev/null; then
        record G6 SKIP "userns 不可用"
    else
        scripts/test-isolated.sh >"$LOG" 2>&1
        rc=$?
        tail -n 20 "$LOG"
        case "$rc" in
            0) record G6 PASS "全绿且宿主三项不变量零变化" ;;
            1) record G6 FAIL "宿主被污染（mountinfo / /var/fuse-proxy / FTP 树）" ;;
            2) record G6 FAIL "测试失败（宿主未污染）" ;;
            3) record G6 FAIL "测试失败且宿主被污染" ;;
            *) record G6 FAIL "rc=$rc，见 $(basename "$LOG")" ;;
        esac
    fi
fi

# ── 汇总 ──────────────────────────────────────────────────────────────
SUM="$OUT/summary.txt"
{
    echo "Fuse-Proxy 验收报告"
    echo "时间：$(date '+%F %T %Z')"
    echo "提交：$(git rev-parse --short HEAD 2>/dev/null || echo '(非 git 仓库)')"
    if ! git diff --quiet 2>/dev/null || [ -n "$(git status --porcelain 2>/dev/null)" ]; then
        echo "工作区：**有未提交改动**（验收对象是工作区当前状态）"
    else
        echo "工作区：干净"
    fi
    echo "门清单：$RUN_GATES"
    echo
    printf '%-4s %-6s %s\n' "门" "结果" "说明"
    printf '%-4s %-6s %s\n' "---" "----" "---"
    for g in $ORDER; do
        printf '%-4s %-6s %s\n' "$g" "${VERDICT[$g]}" "${NOTE[$g]}"
    done
    echo
    echo "人工确认门（脚本无法代劳，必须逐条回答）："
    echo "  G7 判别性：新增回归用例是否已实测在旧实现上失败？判别信号是什么？"
    echo "             （套路：FTP_BACKEND_SRC= / FW_CONFIG_SRC= / FDQ_SRC= /"
    echo "               PROBE_VARIANT=old 指向旧源码，或直编旧副本 + --wrap 注入失败）"
    echo "  G8 层级诚实：本次覆盖到哪一层？L2 通过不等于 Android 运行时已验证；"
    echo "               SELinux/Bionic/vold/Zygisk/多用户须 L3-L4，未做就写未做。"
    if [ "$(git config --get core.hooksPath 2>/dev/null)" != ".githooks" ] ||
       [ "$(git config --get commit.template 2>/dev/null)" != ".gitmessage" ]; then
        echo
        echo "提示（不计门）：本 clone 未装配提交信息钩子/模板——跑 scripts/setup-hooks.sh"
    fi
} >"$SUM"

n_fail=0; n_skip=0
for g in $ORDER; do
    [ "${VERDICT[$g]}" = FAIL ] && n_fail=$((n_fail + 1))
    [ "${VERDICT[$g]}" = SKIP ] && n_skip=$((n_skip + 1))
done

banner "验收汇总"
cat "$SUM"
echo
echo "报告目录：$OUT"

if [ "$n_fail" -gt 0 ]; then
    echo "结论：❌ 不通过（$n_fail 门失败）——按 CONTRIBUTING.md 要求全绿方可提交"
    exit 1
fi
if [ "$n_skip" -gt 0 ]; then
    echo "结论：⏭ 不完整（$n_skip 门跳过）——跳过不计通过，须逐条确认非产品缺陷"
    exit 2
fi
echo "结论：✅ 自动门全部通过（G7/G8 仍需人工确认）"
exit 0
