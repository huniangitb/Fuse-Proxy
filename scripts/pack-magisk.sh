#!/usr/bin/env bash
# =============================================================================
# pack-magisk.sh —— Fuse-Proxy Magisk 模块一键打包脚本
#
# 功能：
#   1. 从 Android 交叉构建目录同步最新二进制到模块骨架目录
#   2. 同步模块 .rules 规则类型注册文件与 conf 配置
#   3. 设置可执行权限（0755）
#   4. 打包为 Magisk 模块 zip（保留可执行权限位，无系统 zip 依赖）
#   5. 打包后自动验证（文件数/关键文件/权限位）
#
# 用法：
#   scripts/pack-magisk.sh                        # 使用默认路径
#   scripts/pack-magisk.sh -m <模块目录> -b <构建目录> -o <输出zip>
#
# 选项：
#   -m, --module-dir <dir>   模块骨架目录（含 bin/ conf/ zygisk/ 等，默认 /tmp/nsp_module）
#   -b, --build-dir <dir>    Android 交叉构建目录（默认 $REPO/build_android）
#   -r, --rules-dir <dir>    模块 .rules 注册文件源目录（默认 $REPO/src/modules）
#   -c, --conf-dir <dir>     conf 配置源目录（默认 $REPO/conf）
#   -o, --out <file>         输出 zip 路径（默认 /home/bdy/ftp/upload/Namespace-Proxy-v2.0-test.zip）
#   -v, --version <str>      版本号（用于重命名输出，可选）
#   -h, --help               显示本帮助
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# ---- 默认参数 ----
MODULE_DIR="${MODULE_DIR:-/tmp/nsp_module}"
BUILD_DIR="${BUILD_DIR:-$REPO_DIR/build_android}"
RULES_DIR="${RULES_DIR:-$REPO_DIR/src/modules}"
CONF_DIR_SRC="${CONF_DIR_SRC:-$REPO_DIR/conf}"
OUT_ZIP="${OUT_ZIP:-/home/bdy/ftp/upload/Namespace-Proxy-v2.0-test.zip}"
VERSION_STR=""

usage() {
    sed -n '2,24p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -m|--module-dir) MODULE_DIR="$2"; shift 2 ;;
        -b|--build-dir)  BUILD_DIR="$2";  shift 2 ;;
        -r|--rules-dir)  RULES_DIR="$2";  shift 2 ;;
        -c|--conf-dir)   CONF_DIR_SRC="$2"; shift 2 ;;
        -o|--out)        OUT_ZIP="$2";    shift 2 ;;
        -v|--version)    VERSION_STR="$2"; shift 2 ;;
        -h|--help)       usage ;;
        *) echo "未知参数: $1" >&2; usage ;;
    esac
done

# 版本号：若指定则输出文件名带版本
if [[ -n "$VERSION_STR" ]]; then
    OUT_ZIP="$(dirname "$OUT_ZIP")/Namespace-Proxy-$VERSION_STR.zip"
fi

# ============================ 前置校验 ============================
for d in "$MODULE_DIR" "$BUILD_DIR" "$RULES_DIR" "$CONF_DIR_SRC"; do
    [[ -d "$d" ]] || { echo "错误: 目录不存在: $d" >&2; exit 1; }
done
[[ -f "$MODULE_DIR/module.prop" ]] || { echo "错误: $MODULE_DIR 不是有效模块骨架（缺 module.prop）" >&2; exit 1; }

echo "== 模块骨架: $MODULE_DIR"
echo "== 构建目录: $BUILD_DIR"
echo "== 输出:     $OUT_ZIP"

# ============================ 1. 同步二进制 ============================
echo "== 同步 Android 产物到 bin/ ..."
for bin in rule_server basic_rules.so ftp_module.so; do
    src="$BUILD_DIR/$bin"
    if [[ -f "$src" ]]; then
        case "$bin" in
            basic_rules.so) dst="$MODULE_DIR/bin/modules/basic_rules/basic_rules.so" ;;
            ftp_module.so)  dst="$MODULE_DIR/bin/modules/ftp_module/ftp_module.so" ;;
            *)              dst="$MODULE_DIR/bin/$bin" ;;
        esac
        cp -f "$src" "$dst"
        echo "   - $bin"
    else
        echo "   - $bin (构建目录无此产物，跳过)"
    fi
done

# ============================ 2. 同步 .rules 与 conf ============================
echo "== 同步 .rules 规则类型注册文件 ..."
# 源目录名与模块目录名可能不同（ftp_module.rules 位于 src/modules/ftp/）
# 格式：<源目录>|<模块目录>
for pair in "basic_rules|basic_rules" "ftp|ftp_module"; do
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

echo "== 同步 conf 配置 ..."
for f in injector.conf ftp.conf monitor_ignore.conf; do
    if [[ -f "$CONF_DIR_SRC/$f" ]]; then
        cp -f "$CONF_DIR_SRC/$f" "$MODULE_DIR/conf/$f"
        echo "   - $f"
    fi
done

# ============================ 3. 权限 ============================
echo "== 设置可执行权限 (0755) ..."
chmod 755 "$MODULE_DIR"/bin/* 2>/dev/null || true
chmod 755 "$MODULE_DIR"/bin/modules/*/*.so 2>/dev/null || true
chmod 755 "$MODULE_DIR"/customize.sh "$MODULE_DIR"/service.sh \
         "$MODULE_DIR"/uninstall.sh "$MODULE_DIR"/zygisk/*.so 2>/dev/null || true

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
check("basic_rules.rules 存在", any(n.endswith("basic_rules/basic_rules.rules") for n in names))
check("ftp_module.rules 存在", any(n.endswith("ftp_module/ftp_module.rules") for n in names))
check("zygisk 存在", any(n.startswith("zygisk/") and n.endswith(".so") for n in names))
check("webroot 存在", any(n.startswith("webroot/") for n in names))
check("reload_rules 无残留", not any("reload_rules" in n for n in names))
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
