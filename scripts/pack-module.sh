#!/usr/bin/env bash
# =============================================================================
# pack-module.sh —— Fuse-Proxy 模块一键打包脚本
#
# 功能：
#   1. 从 Android 交叉构建目录同步最新二进制到模块骨架目录
#   2. 同步模块 .rules 规则类型注册文件与 conf 配置
#   3. 设置可执行权限（0755）
#   4. 自动写入版本号到 module.prop（非发布模式一律写当前仓库提交哈希；
#      --release 发布模式用 -v 指定的版本号，默认 2.0）
#   5. 打包为模块 zip（保留可执行权限位，无系统 zip 依赖）
#   6. 打包后自动验证（文件数/关键文件/权限位）
#
# 用法：
#   scripts/pack-module.sh                        # 使用默认路径（版本自动为 2.0）
#   scripts/pack-module.sh -m <模块目录> -b <构建目录> -o <输出zip>
#
# 选项：
#   -m, --module-dir <dir>   模块骨架目录（含 bin/ conf/ zygisk/ 等，默认 /home/bdy/nsp_module）
#   -b, --build-dir <dir>    Android 交叉构建目录（默认 $REPO/build_android）
#   -r, --rules-dir <dir>    模块 .rules 注册文件源目录（默认 $REPO/src/modules）
#   -c, --conf-dir <dir>     conf 配置源目录（默认 $REPO/conf）
#   -o, --out <file>         输出 zip 路径（默认 /home/bdy/ftp/upload/Namespace-Proxy-<git校验码>.zip）
#   -v, --version <str>      版本号（仅发布模式生效，默认 2.0；非发布模式
#                            version 一律写当前仓库提交哈希，-v 被忽略）
#   -s, --symbols-dir <dir>  unstripped 符号构建目录（默认 $REPO/build_android_sym；
#                            存在则额外产出 <输出名>-symbols.zip，供崩溃 addr2line 归因）
#   --skip-symbols           跳过符号包（即使符号目录存在也不打包）
#   --release                发布模式：输出名用版本号（默认非发布用 git 提交校验码）
#   -h, --help               显示本帮助
#
# 符号构建目录制备（与主构建同 cross-file、同源码，仅保留符号）：
#   meson setup build_android_sym --cross-file android-aarch64.ini \
#     -Dfuse3_root=<静态库根> -Dcurl_dir=<预构建 libcurl 根> -Dbuildtype=release \
#     -Db_lto=false -Dstrip=false -Dc_args='-g' -Dc_link_args=''
#   ninja -C build_android_sym
# 注意：主构建默认 -Wl,-s 会剥离符号，strip 后无法恢复，故符号包必须来自独立构建目录。
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# ---- 默认参数 ----
MODULE_DIR="${MODULE_DIR:-/home/bdy/nsp_module}"
BUILD_DIR="${BUILD_DIR:-$REPO_DIR/build_android}"
RULES_DIR="${RULES_DIR:-$REPO_DIR/src/modules}"
CONF_DIR_SRC="${CONF_DIR_SRC:-$REPO_DIR/conf}"
OUT_ZIP="${OUT_ZIP:-}"               # 输出 zip 路径（未指定时自动生成）
[[ -n "${MODULE_VERSION:-}" ]] && MODULE_VERSION_SET=1  # 环境变量显式给了 MODULE_VERSION 也视为显式指定
MODULE_VERSION="${MODULE_VERSION:-2.0}"  # 模块版本号：发布模式写入 module.prop；非发布模式强制用提交哈希
RELEASE_MODE="${RELEASE_MODE:-0}"    # 发布模式（--release）：输出名用版本号；默认用 git 提交校验码
SYMBOLS_DIR="${SYMBOLS_DIR:-$REPO_DIR/build_android_sym}"  # unstripped 符号构建目录
SKIP_SYMBOLS="${SKIP_SYMBOLS:-0}"    # --skip-symbols 置 1 跳过符号包

usage() {
    sed -n '2,/^[^#]/p' "${BASH_SOURCE[0]}" | head -n -1 | sed 's/^# \{0,1\}//'
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -m|--module-dir) MODULE_DIR="$2"; shift 2 ;;
        -b|--build-dir)  BUILD_DIR="$2";  shift 2 ;;
        -r|--rules-dir)  RULES_DIR="$2";  shift 2 ;;
        -c|--conf-dir)   CONF_DIR_SRC="$2"; shift 2 ;;
        -o|--out)        OUT_ZIP="$2";    shift 2 ;;
        -v|--version)    MODULE_VERSION="$2"; MODULE_VERSION_SET=1; shift 2 ;;
        -s|--symbols-dir) SYMBOLS_DIR="$2";   shift 2 ;;
        --skip-symbols)  SKIP_SYMBOLS=1;      shift ;;
        --release)       RELEASE_MODE=1; shift ;;
        -h|--help)       usage ;;
        *) echo "未知参数: $1" >&2; usage ;;
    esac
done

# 非发布模式：module.prop 的 version 一律写当前仓库提交哈希（-v 被忽略）
if [[ "$RELEASE_MODE" != "1" ]]; then
    GIT_SHA="$(git -C "$REPO_DIR" rev-parse HEAD 2>/dev/null || echo unknown)"
    [[ -n "${MODULE_VERSION_SET:-}" && "$MODULE_VERSION" != "$GIT_SHA" ]] && \
        echo "警告: 非发布模式下 -v/$MODULE_VERSION 被忽略，version 使用提交哈希" >&2
    MODULE_VERSION="$GIT_SHA"
fi

# 输出名：显式 -o 优先；未指定时——
#   发布模式（--release）：Namespace-Proxy-<版本号>.zip
#   默认（非发布）：Namespace-Proxy-<git 提交校验码>.zip（git rev-parse --short HEAD）
if [[ -z "$OUT_ZIP" ]]; then
    if [[ "$RELEASE_MODE" == "1" ]]; then
        OUT_ZIP="/home/bdy/ftp/upload/Namespace-Proxy-$MODULE_VERSION.zip"
    else
        OUT_ZIP="/home/bdy/ftp/upload/Namespace-Proxy-$(git -C "$REPO_DIR" rev-parse --short HEAD 2>/dev/null || echo unknown).zip"
    fi
fi

# ============================ 前置校验 ============================
for d in "$MODULE_DIR" "$BUILD_DIR" "$RULES_DIR" "$CONF_DIR_SRC"; do
    [[ -d "$d" ]] || { echo "错误: 目录不存在: $d" >&2; exit 1; }
done
[[ -f "$MODULE_DIR/module.prop" ]] || { echo "错误: $MODULE_DIR 不是有效模块骨架（缺 module.prop）" >&2; exit 1; }

echo "== 模块骨架: $MODULE_DIR"
echo "== 构建目录: $BUILD_DIR"
echo "== 版本号:   $MODULE_VERSION"
echo "== 输出:     $OUT_ZIP"

# ============================ 1. 同步二进制 ============================
# 主二进制（rule_server/injector/fuse_daemon/log_*）与模块 so 一并同步，
# 与第 5 步"关键二进制齐全"验证清单保持一致，避免骨架残留旧产物
echo "== 同步 Android 产物到 bin/ ..."
for bin in rule_server injector fuse_daemon log_monitor log_ctl ftp_module.so; do
    src="$BUILD_DIR/$bin"
    if [[ -f "$src" ]]; then
        case "$bin" in
            ftp_module.so) dst="$MODULE_DIR/bin/modules/ftp_module/ftp_module.so" ;;
            *)             dst="$MODULE_DIR/bin/$bin" ;;
        esac
        cp -f "$src" "$dst"
        echo "   - $bin"
    else
        echo "   - $bin (构建目录无此产物，跳过)"
    fi
done

# ============================ 2. 同步 .rules 与 conf ============================
echo "== 同步 .rules 规则类型注册文件 ..."
# 模块目录映射：<源目录>|<模块目录>。源目录名与模块目录名可能不同
# （ftp_module.rules 位于 src/modules/ftp/）；规则能力已内建（V4），
# 只剩后端模块自带 .rules。第 2.1 步的白名单与这里同源，避免两处漂移。
# 该文件同时承载模块配置 schema（[conf] 段），故只需同步这一份——
# 新增模块配置项改声明文件即可，不必改 C 或动打包脚本。
MODULE_PAIRS=("ftp|ftp_module")
for pair in "${MODULE_PAIRS[@]}"; do
    src_mod="${pair%%|*}"
    dst_mod="${pair##*|}"
    src="$RULES_DIR/$src_mod/$dst_mod.rules"
    dst="$MODULE_DIR/bin/modules/$dst_mod/$dst_mod.rules"
    if [[ -f "$src" ]]; then
        cp -f "$src" "$dst"
        echo "   - $dst_mod.rules"
    else
        echo "   - $dst_mod.rules (缺失，跳过)"
    fi
done

# ===================== 2.1 清理骨架中已不再产出的模块目录 =====================
# 骨架是增量同步目录（只 cp 不删），已删除的目标会一直躺在 bin/modules/ 里随包
# 分发——basic_rules 内建进框架后就是这样残留的。后果不是"多个无用文件"：
# 加载器 dlopen 后按 abi_version 判定，旧 ABI 的 .so 每次启动都打一条
# "模块 X ABI 不匹配" ERROR（对正在用 sys.log 排查的人纯属噪音），其 .rules
# 还会被 rule_server 当作有效规则类型注册。故按白名单清理，使包内容与本次
# 产物一致。
echo "== 清理骨架中已不再产出的模块 ..."
KNOWN_MODULES=""
for pair in "${MODULE_PAIRS[@]}"; do
    KNOWN_MODULES="$KNOWN_MODULES ${pair##*|}"
done
for d in "$MODULE_DIR"/bin/modules/*/; do
    [[ -d "$d" ]] || continue
    name="$(basename "$d")"
    case " $KNOWN_MODULES " in
        *" $name "*) ;;
        *)
            rm -rf "$d"
            echo "   - 移除陈旧模块: $name"
            ;;
    esac
done

echo "== 同步 conf 配置 ..."
for f in injector.conf; do
    if [[ -f "$CONF_DIR_SRC/$f" ]]; then
        cp -f "$CONF_DIR_SRC/$f" "$MODULE_DIR/conf/$f"
        echo "   - $f"
    fi
done
# 模块自有配置：<CONFIG_DIR>/modules/<模块名>/<模块名>.conf —— 框架读取后经
# 扁平视图下发给模块（模块不读文件、不跑 inotify，见 docs/modules.md §6.1.1）。
# 源码树里的 conf/modules/ 与设备上的 <CONFIG_DIR>/modules/ 同构，故整棵照搬。
if [[ -d "$CONF_DIR_SRC/modules" ]]; then
    mkdir -p "$MODULE_DIR/conf/modules"
    cp -a "$CONF_DIR_SRC/modules/." "$MODULE_DIR/conf/modules/"
    echo "   - modules/（模块自有配置）"
fi
# 旧版 <CONFIG_DIR>/ftp.conf 已不再是读取路径：留在骨架里会让人以为它生效。
# 只删本脚本上一版会写出的那个位置，用户自建的其它文件不动。
if [[ -f "$MODULE_DIR/conf/ftp.conf" ]]; then
    rm -f "$MODULE_DIR/conf/ftp.conf"
    echo "   - 移除陈旧 conf/ftp.conf（已迁到 conf/modules/ftp_module/ftp_module.conf）"
fi

# ===================== 2.2 同步 Zygisk 模块（双 ABI，必须齐全） =====================
# injector 收到首次 IPC 通知即转被动模式停止周期扫描，缺 32 位会让跑在
# 32 位 zygote 上的应用既无通知也无扫描，静默漏注入——故两个 ABI 缺一不可。
echo "== 同步 Zygisk 模块 ..."
mkdir -p "$MODULE_DIR/zygisk"
for abi in arm64-v8a armeabi-v7a; do
    src="$BUILD_DIR/src/zygisk/$abi.so"
    if [[ -f "$src" ]]; then
        cp -f "$src" "$MODULE_DIR/zygisk/$abi.so"
        echo "   - $abi.so"
    else
        echo "错误: 缺少 Zygisk 模块 $src（应用创建通知将失效）" >&2
        exit 1
    fi
done

# ============================ 2.5 许可证 =====================
# 许可证与附加声明（LICENSE / module-exception / THIRD-PARTY-NOTICES）均不再入包，
# 义务履行改由源码仓库/发布页承担。
echo "== 跳过许可证同步（已移除） =="

# ============================ 3. 权限 ============================
echo "== 设置可执行权限 (0755) ..."
chmod 755 "$MODULE_DIR"/bin/* 2>/dev/null || true
chmod 755 "$MODULE_DIR"/bin/modules/*/*.so 2>/dev/null || true
chmod 755 "$MODULE_DIR"/customize.sh "$MODULE_DIR"/service.sh \
         "$MODULE_DIR"/uninstall.sh "$MODULE_DIR"/zygisk/*.so 2>/dev/null || true

# ============================ 3.5 自动写入版本号 ============================
echo "== 自动设置模块版本号: $MODULE_VERSION ..."
sed -i "s#^version=.*#version=$MODULE_VERSION#" "$MODULE_DIR/module.prop"
grep -q '^version=' "$MODULE_DIR/module.prop" || { echo "错误: module.prop 缺少 version 行" >&2; exit 1; }

# versionCode 实时跟随仓库提交数量（git rev-list --count HEAD），缺失则追加
VERCODE="$(git -C "$REPO_DIR" rev-list --count HEAD 2>/dev/null || echo 1)"
if grep -q '^versionCode=' "$MODULE_DIR/module.prop"; then
    sed -i "s#^versionCode=.*#versionCode=$VERCODE#" "$MODULE_DIR/module.prop"
else
    echo "versionCode=$VERCODE" >> "$MODULE_DIR/module.prop"
fi
echo "== versionCode=$VERCODE (仓库提交数)"

# name 字段：非发布模式追加 -Test，发布模式还原（区分测试包与发布包，幂等）
if [[ "$RELEASE_MODE" == "1" ]]; then
    if grep -q '^name=.*-Test$' "$MODULE_DIR/module.prop"; then
        sed -i 's#^name=\(.*\)-Test$#name=\1#' "$MODULE_DIR/module.prop"
        echo "== name 已还原（发布模式）"
    fi
else
    if grep -q '^name=' "$MODULE_DIR/module.prop" && ! grep -q '^name=.*-Test$' "$MODULE_DIR/module.prop"; then
        sed -i 's#^name=\(.*\)#name=\1-Test#' "$MODULE_DIR/module.prop"
        echo "== name 已追加 -Test（非发布模式）"
    fi
fi

# ============================ 4. 打包 ============================
echo "== 打包 zip ..."
mkdir -p "$(dirname "$OUT_ZIP")"
rm -f "$OUT_ZIP"
python3 - "$MODULE_DIR" "$OUT_ZIP" <<'PYEOF'
import os
import sys
import zipfile

src_dir, out_zip = sys.argv[1], sys.argv[2]

def collect(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for f in sorted(filenames):
            yield os.path.join(dirpath, f)

with zipfile.ZipFile(out_zip, "w", zipfile.ZIP_DEFLATED) as z:
    for path in collect(src_dir):
        rel = os.path.relpath(path, src_dir)
        st = os.stat(path)
        perm = 0o755 if (st.st_mode & 0o111) else 0o644
        zi = zipfile.ZipInfo(rel, (1980, 1, 1, 0, 0, 0))
        zi.external_attr = (perm & 0xFFFF) << 16
        with open(path, "rb") as f:
            z.writestr(zi, f.read())

print(f"打包完成: {out_zip} ({os.path.getsize(out_zip)} bytes)")
PYEOF

# ============================ 5. 验证 ============================
echo "== 验证 zip ..."
python3 - "$OUT_ZIP" <<'PYEOF'
import sys
import zipfile

z = zipfile.ZipFile(sys.argv[1])
names = z.namelist()
ok = True

def check(label, cond):
    global ok
    print(f"  {'✅' if cond else '❌'} {label}")
    if not cond:
        ok = False

check("module.prop 存在", "module.prop" in names)
check("customize.sh 存在", "customize.sh" in names)
check("service.sh 存在", "service.sh" in names)
check("rule_server 存在", any("bin/rule_server" in n for n in names))
check("injector 存在", any("bin/injector" in n for n in names))
check("fuse_daemon 存在", any("bin/fuse_daemon" in n for n in names))
check("ftp_module.rules 存在", any(n.endswith("ftp_module/ftp_module.rules") for n in names))
# 骨架是增量同步目录，已删除的目标（如内建化后的 basic_rules）若残留会随包
# 分发：旧 ABI 的 .so 每次启动打一条 "ABI 不匹配" ERROR。此处钉住白名单。
mod_dirs = sorted({n.split("/")[2] for n in names
                   if n.startswith("bin/modules/") and n.count("/") >= 3})
check("bin/modules 下只有当前模块 (%s)" % (",".join(mod_dirs) or "空"), mod_dirs == ["ftp_module"])
check("zygisk 存在", any(n.startswith("zygisk/") and n.endswith(".so") for n in names))
check("zygisk arm64-v8a 存在", "zygisk/arm64-v8a.so" in names)
check("zygisk armeabi-v7a 存在", "zygisk/armeabi-v7a.so" in names)
check("webroot 已移除", not any(n.startswith("webroot/") for n in names))
check("reload_rules 无残留", not any("reload_rules" in n for n in names))
check("LICENSE 已移除", "LICENSE" not in names and not any(n.startswith("LICENSE") for n in names))
check("模块 ABI 例外条款已移除", "LICENSE.module-exception" not in names)
check("第三方组件声明已移除", "THIRD-PARTY-NOTICES.md" not in names)
check("build-info 已移除", not any(n.endswith("build-info.txt") for n in names))
check("可执行文件权限 0755",
      all((z.getinfo(n).external_attr >> 16 & 0o777) == 0o755
          for n in names if n.endswith((".so", ".sh")) or "bin/rule_server" in n))

# 关键二进制必须存在
missing = [n for n in ("bin/rule_server", "bin/injector", "bin/fuse_daemon",
                       "bin/log_monitor", "bin/log_ctl")
           if n not in names]
check("关键二进制齐全", not missing)

print(f"文件数: {len(names)}")
if ok:
    print("全部通过 ✅")
else:
    print("存在失败 ❌")
    sys.exit(1)
PYEOF

echo
echo "完成: $OUT_ZIP"

# ============================ 6. unstripped 符号包 ============================
# 崩溃 backtrace 是 ASLR 绝对地址，需同提交 unstripped ELF 做
# `llvm-addr2line -e symbols/fuse_daemon -f -C <offset>`（offset 取
# fuse_crash.log 中 "-> offset +0x..."）。主构建 -Wl,-s 已剥离符号，
# strip 后不可恢复，故符号包必须来自独立符号构建目录。
if [[ "$SKIP_SYMBOLS" == "1" ]]; then
    echo "== 符号包：已按 --skip-symbols 跳过"
else
    SYM_ZIP="${OUT_ZIP%.zip}-symbols.zip"
    [[ "$SYM_ZIP" == "$OUT_ZIP" ]] && SYM_ZIP="$OUT_ZIP-symbols.zip"
    SYM_FILES=()
    for bin in rule_server injector fuse_daemon log_monitor log_ctl ftp_module.so; do
        [[ -f "$SYMBOLS_DIR/$bin" ]] && SYM_FILES+=("$bin")
    done
    if [[ ${#SYM_FILES[@]} -eq 0 ]]; then
        echo "== 符号包：跳过（符号目录无产物: $SYMBOLS_DIR）"
        echo "   制备命令（与主构建同 cross-file/依赖，仅保留符号）："
        echo "   meson setup $SYMBOLS_DIR --cross-file android-aarch64.ini \\"
        echo "     -Dfuse3_root=<静态库根> -Dcurl_dir=<预构建 libcurl 根> \\"
        echo "     -Dbuildtype=release -Db_lto=false -Dstrip=false \\"
        echo "     -Dc_args='-g' -Dc_link_args='' && ninja -C $SYMBOLS_DIR"
    else
        echo "== 打包符号包: $SYM_ZIP"
        if command -v file >/dev/null 2>&1; then
            for bin in "${SYM_FILES[@]}"; do
                if file "$SYMBOLS_DIR/$bin" | grep -q "not stripped"; then
                    echo "   ✅ $bin (not stripped)"
                else
                    echo "   ⚠ $bin (疑似已剥离：$(file -b "$SYMBOLS_DIR/$bin" | cut -c1-60))"
                fi
            done
        fi
        python3 - "$SYMBOLS_DIR" "$SYM_ZIP" "${SYM_FILES[*]}" <<'PYEOF'
import os, sys, zipfile
sym_dir, out_zip, files = sys.argv[1], sys.argv[2], sys.argv[3].split()
with zipfile.ZipFile(out_zip, "w", zipfile.ZIP_DEFLATED) as z:
    for name in files:
        src = os.path.join(sym_dir, os.path.basename(name))
        zi = zipfile.ZipInfo("symbols/" + os.path.basename(name), (1980, 1, 1, 0, 0, 0))
        zi.external_attr = (0o644 & 0xFFFF) << 16
        with open(src, "rb") as f:
            z.writestr(zi, f.read())
    hint = ("addr2line 用法（NDK llvm-addr2line）：\n"
            "  llvm-addr2line -e symbols/fuse_daemon -f -C <offset>\n"
            "offset 取 fuse_crash.log 中 '-> offset +0x...'（如 +0x30c1c）。\n")
    zi = zipfile.ZipInfo("symbols/README", (1980, 1, 1, 0, 0, 0))
    zi.external_attr = (0o644 & 0xFFFF) << 16
    z.writestr(zi, hint)
print(f"符号包完成: {out_zip} ({os.path.getsize(out_zip)} bytes)")
PYEOF
        echo "   sha256: $(sha256sum "$SYM_ZIP" | cut -d' ' -f1)"
    fi
fi
