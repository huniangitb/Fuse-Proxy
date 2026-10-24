#!/usr/bin/env bash
# 离线构建 6 个 NSP 设备验证探针 APK（无 gradle、无网络、无 adb）。
#
# 用法:
#   device-verify/probes/build-probes.sh
#   ANDROID_SDK=/path/to/Sdk device-verify/probes/build-probes.sh
#   SKIP_CHECK=1 device-verify/probes/build-probes.sh    # 只构建，不跑自检
#
# 产物:
#   device-verify/dist/apks/nsp.probe.{ftp,sftp,hide,iso,plain,race}.apk
#   device-verify/dist/apks/BUILD-CHECK.txt               # 自检摘要（默认跑）
#   device-verify/dist/keys/debug.keystore                # 首次生成，之后复用
#
# 说明:
#   * 幂等：每次重建 device-verify/probes/build/ 中间目录，覆盖 dist 产物。
#   * applicationId 通过 aapt2 link --rename-manifest-package 按场景改写；
#     manifest 里的类名均为全限定名，故不会被改写。
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEVICE_VERIFY_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

ANDROID_SDK="${ANDROID_SDK:-$HOME/Android/Sdk}"
export ANDROID_SDK
PLATFORM_DIR_NAME="android-36"
MIN_SDK=31
TARGET_SDK=36

SRC_DIR="$SCRIPT_DIR/src"
MANIFEST="$SCRIPT_DIR/AndroidManifest.xml"
WORK_DIR="$SCRIPT_DIR/build"
DIST_APKS="$DEVICE_VERIFY_DIR/dist/apks"
DIST_KEYS="$DEVICE_VERIFY_DIR/dist/keys"
KEYSTORE="$DIST_KEYS/debug.keystore"
KS_ALIAS="androiddebugkey"
KS_PASS="android"
CASES=(ftp sftp hide iso plain unlink race)

log() { printf '[build-probes] %s\n' "$*"; }
die() { printf '[build-probes] ERROR: %s\n' "$*" >&2; exit 1; }

# --- 安全护栏: WORK_DIR 必须是本脚本目录下的 build/，避免 rm -rf 误伤 ---
case "$WORK_DIR" in
    "$SCRIPT_DIR"/build) ;;
    *) die "refusing to clean unexpected work dir: $WORK_DIR" ;;
esac

# --- 工具链定位 ---
[ -d "$ANDROID_SDK" ] || die "ANDROID_SDK not found: $ANDROID_SDK"
ANDROID_JAR="$ANDROID_SDK/platforms/$PLATFORM_DIR_NAME/android.jar"
[ -f "$ANDROID_JAR" ] || die "missing platform jar: $ANDROID_JAR"
[ -d "$ANDROID_SDK/build-tools" ] || die "missing build-tools dir: $ANDROID_SDK/build-tools"

LATEST_BUILD_TOOLS="$(find "$ANDROID_SDK/build-tools" -mindepth 1 -maxdepth 1 \
    \( -type d -o -type l \) -printf '%f\n' | sort -V | tail -n 1)"
[ -n "$LATEST_BUILD_TOOLS" ] || die "no build-tools version under $ANDROID_SDK/build-tools"
BUILD_TOOLS_DIR="$ANDROID_SDK/build-tools/$LATEST_BUILD_TOOLS"
AAPT2="$BUILD_TOOLS_DIR/aapt2"
D8="$BUILD_TOOLS_DIR/d8"
ZIPALIGN="$BUILD_TOOLS_DIR/zipalign"
APKSIGNER="$BUILD_TOOLS_DIR/apksigner"
for tool in "$AAPT2" "$D8" "$ZIPALIGN" "$APKSIGNER"; do
    [ -x "$tool" ] || die "missing executable: $tool"
done
for tool in javac keytool zip; do
    command -v "$tool" >/dev/null 2>&1 || die "$tool not found in PATH"
done

log "ANDROID_SDK=$ANDROID_SDK"
log "platform=$PLATFORM_DIR_NAME build-tools=$LATEST_BUILD_TOOLS"
log "javac: $(javac -version 2>&1 | head -n 1)"

# --- 清理 & 建目录 ---
rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR/classes" "$WORK_DIR/dex" "$DIST_APKS" "$DIST_KEYS"

# --- debug keystore（幂等）---
if [ -f "$KEYSTORE" ]; then
    log "reuse keystore: $KEYSTORE"
else
    log "generate keystore: $KEYSTORE"
    keytool -genkeypair \
        -keystore "$KEYSTORE" -storetype JKS -alias "$KS_ALIAS" \
        -storepass "$KS_PASS" -keypass "$KS_PASS" \
        -dname "CN=Android Debug,O=Android,C=US" \
        -keyalg RSA -keysize 2048 -validity 10000 -noprompt >/dev/null
fi

# --- javac（Java 8 字节码，Android framework API only）---
mapfile -t JAVA_SOURCES < <(find "$SRC_DIR" -type f -name '*.java' | sort)
[ "${#JAVA_SOURCES[@]}" -gt 0 ] || die "no .java sources under $SRC_DIR"
log "javac --release 8 (${#JAVA_SOURCES[@]} sources)"
javac --release 8 -Xlint:-options -encoding UTF-8 -classpath "$ANDROID_JAR" \
    -d "$WORK_DIR/classes" "${JAVA_SOURCES[@]}"

# --- d8 -> classes.dex ---
mapfile -t CLASS_FILES < <(find "$WORK_DIR/classes" -type f -name '*.class' | sort)
[ "${#CLASS_FILES[@]}" -gt 0 ] || die "javac produced no .class files"
log "d8 --release --min-api $MIN_SDK (${#CLASS_FILES[@]} classes)"
"$D8" --lib "$ANDROID_JAR" --release --min-api "$MIN_SDK" \
    --output "$WORK_DIR/dex" "${CLASS_FILES[@]}"
[ -f "$WORK_DIR/dex/classes.dex" ] || die "d8 did not produce classes.dex"

# --- 逐场景: aapt2 link -> 打进 classes.dex -> zipalign -> apksigner ---
for c in "${CASES[@]}"; do
    pkg="nsp.probe.$c"
    log "building $pkg"

    "$AAPT2" link \
        -o "$WORK_DIR/$pkg.unsigned.apk" \
        --manifest "$MANIFEST" \
        -I "$ANDROID_JAR" \
        --min-sdk-version "$MIN_SDK" \
        --target-sdk-version "$TARGET_SDK" \
        --rename-manifest-package "$pkg"

    cp "$WORK_DIR/$pkg.unsigned.apk" "$WORK_DIR/$pkg.withdex.apk"
    ( cd "$WORK_DIR/dex" && zip -q -X "$WORK_DIR/$pkg.withdex.apk" classes.dex )

    "$ZIPALIGN" -f 4 "$WORK_DIR/$pkg.withdex.apk" "$WORK_DIR/$pkg.aligned.apk"

    # 关掉 v4（.idsig）: 设备验证用普通安装，不需要 incremental install 旁文件。
    "$APKSIGNER" sign \
        --ks "$KEYSTORE" \
        --ks-key-alias "$KS_ALIAS" \
        --ks-pass "pass:$KS_PASS" \
        --key-pass "pass:$KS_PASS" \
        --v4-signing-enabled false \
        --out "$DIST_APKS/$pkg.apk" \
        "$WORK_DIR/$pkg.aligned.apk"
done

log "APKs written to $DIST_APKS"
ls -l "$DIST_APKS"/*.apk

# --- 静态自检（落盘 BUILD-CHECK.txt）---
if [ "${SKIP_CHECK:-0}" = "1" ]; then
    log "SKIP_CHECK=1: skipping self-check"
else
    "$SCRIPT_DIR/check-probes.sh"
fi

# 成功路径清掉中间产物；失败时（set -e）保留以便排查。KEEP_WORK=1 可强制保留。
if [ "${KEEP_WORK:-0}" = "1" ]; then
    log "keeping work dir: $WORK_DIR"
else
    rm -rf "$WORK_DIR"
fi
