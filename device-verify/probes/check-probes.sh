#!/usr/bin/env bash
# 探针 APK 离线静态自检：包名 / minSdk / targetSdk / launcher / application 类名 /
# 签名 / zip 内容 / dex 内日志契约字面量。结果落盘 device-verify/dist/apks/BUILD-CHECK.txt。
# 不安装、不调用 adb、不执行 APK。
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEVICE_VERIFY_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ANDROID_SDK="${ANDROID_SDK:-$HOME/Android/Sdk}"
PLATFORM_DIR_NAME="android-36"
DIST_APKS="$DEVICE_VERIFY_DIR/dist/apks"
OUT="$DIST_APKS/BUILD-CHECK.txt"
TMP_OUT="$DIST_APKS/.BUILD-CHECK.txt.tmp"
CASES=(ftp sftp hide iso plain unlink race)

fail_count=0
pass_count=0

line() { printf '%s\n' "$*" >>"$TMP_OUT"; printf '%s\n' "$*"; }
fail() { line "  FAIL: $*"; fail_count=$((fail_count + 1)); }
ok()   { line "  ok: $*"; }
die()  { printf '[check-probes] ERROR: %s\n' "$*" >&2; exit 1; }

# 检查失败时也把已收集内容留下，便于排查（成功路径会先 mv 再 exit）。
trap 'rm -f "$TMP_OUT"' EXIT

[ -d "$ANDROID_SDK" ] || die "ANDROID_SDK not found: $ANDROID_SDK"
ANDROID_JAR="$ANDROID_SDK/platforms/$PLATFORM_DIR_NAME/android.jar"
[ -f "$ANDROID_JAR" ] || die "missing platform jar: $ANDROID_JAR"
LATEST_BUILD_TOOLS="$(find "$ANDROID_SDK/build-tools" -mindepth 1 -maxdepth 1 \
    \( -type d -o -type l \) -printf '%f\n' | sort -V | tail -n 1)"
[ -n "$LATEST_BUILD_TOOLS" ] || die "no build-tools version found"
BUILD_TOOLS_DIR="$ANDROID_SDK/build-tools/$LATEST_BUILD_TOOLS"
AAPT2="$BUILD_TOOLS_DIR/aapt2"
APKSIGNER="$BUILD_TOOLS_DIR/apksigner"
ZIPALIGN="$BUILD_TOOLS_DIR/zipalign"
for tool in "$AAPT2" "$APKSIGNER" "$ZIPALIGN" unzip strings sha256sum; do
    command -v "$tool" >/dev/null 2>&1 || die "missing tool: $tool"
done
mkdir -p "$DIST_APKS"
: >"$TMP_OUT"

line "NSP probe APK static build check"
line "generated_at_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
line "host: $(uname -srm)"
line "workspace: $DEVICE_VERIFY_DIR"
line "android_sdk: $ANDROID_SDK"
line "platform: $PLATFORM_DIR_NAME"
line "android_jar_sha256: $(sha256sum "$ANDROID_JAR" | awk '{print $1}')"
line "build_tools: $LATEST_BUILD_TOOLS"
line "aapt2: $("$AAPT2" version 2>&1 | head -n 1)"
line "d8: $("$BUILD_TOOLS_DIR/d8" --version 2>&1 | head -n 1)"
line "apksigner: $("$APKSIGNER" version 2>&1 | head -n 1)"
line "javac: $(javac -version 2>&1 | head -n 1)"
line "keystore: ${KEYSTORE_REL:-device-verify/dist/keys/debug.keystore} (alias androiddebugkey)"
line "note: static checks only; no adb and no device execution were performed."
line ""

# dex 里必须存在的日志契约 / 路径字面量（每个 APK 共用同一份 classes.dex）。
DEX_LITERALS=(
    "NSP_PROBE"
    "NSP_PROBE:"
    "case="
    "|step="
    "|detail="
    "/sdcard/nsp_verify"
    "REAL_CANARY.txt"
    "probe_"
    "NSP_HIDE_CANARY"
    "content_match="
    "hide/secret.txt"
    "fuse_daemon"
    "timeout_ms="
    "phase_a"
    "phase_b"
    "write_denied"
    "enoent"
    "unexpected_success"
    "list_returned_null"
    "Download/nsp_probe_sandbox.txt"
    "Pictures/nsp_probe_sandbox.jpg"
    "plain.txt"
    "nsp_probe_unlink"
    "nsp_verify/unlink"
    ".fuse_hidden"
    "hidden_open"
    "hidden_legacy"
    ".fuse_hidden0000000000000001"
    "nsp_race_a"
    "nsp_race_b"
    "NSP_RACE_A:"
    "NSP_RACE_B:"
    "first_fuse_ms="
    "attempts="
    "nsp/probe/ProbeApp"
    "nsp/probe/ProbeActivity"
)

idx=0
total=${#CASES[@]}
for c in "${CASES[@]}"; do
    idx=$((idx + 1))
    pkg="nsp.probe.$c"
    apk="$DIST_APKS/$pkg.apk"
    apk_fail_start=$fail_count

    line "[$idx/$total] $pkg"
    line "  path: ${apk#"$DEVICE_VERIFY_DIR"/}"
    if [ ! -f "$apk" ]; then
        fail "APK not found: $apk"
        line "  RESULT: FAIL"
        continue
    fi

    line "  size_bytes: $(stat -c %s "$apk")"
    line "  sha256: $(sha256sum "$apk" | awk '{print $1}')"

    badging="$("$AAPT2" dump badging "$apk")"
    pkg_line="$(printf '%s\n' "$badging" | grep -m1 '^package:' || true)"
    min_line="$(printf '%s\n' "$badging" | grep -m1 -E '^(minSdkVersion|sdkVersion):' || true)"
    target_line="$(printf '%s\n' "$badging" | grep -m1 '^targetSdkVersion:' || true)"
    act_line="$(printf '%s\n' "$badging" | grep -m1 '^launchable-activity:' || true)"
    line "  badging.package: ${pkg_line#package: }"
    line "  badging.minSdkVersion: ${min_line#*: }"
    line "  badging.targetSdkVersion: ${target_line#targetSdkVersion: }"
    line "  badging.launchable-activity: ${act_line#launchable-activity: }"

    if printf '%s\n' "$pkg_line" | grep -Fq "name='$pkg'"; then
        ok "badging package name == $pkg"
    else
        fail "badging package name != $pkg"
    fi
    if printf '%s\n' "$min_line" | grep -Fq "'31'"; then
        ok "badging minSdkVersion == 31"
    else
        fail "badging minSdkVersion != 31"
    fi
    if printf '%s\n' "$target_line" | grep -Fq "targetSdkVersion:'36'"; then
        ok "badging targetSdkVersion == 36"
    else
        fail "badging targetSdkVersion != 36"
    fi
    if printf '%s\n' "$act_line" | grep -Fq "name='nsp.probe.ProbeActivity'"; then
        ok "launcher activity == nsp.probe.ProbeActivity"
    else
        fail "launcher activity mismatch"
    fi

    xmltree="$("$AAPT2" dump xmltree --file AndroidManifest.xml "$apk")"
    if printf '%s\n' "$xmltree" | grep -Fq "package=\"$pkg\""; then
        ok "manifest package attr == $pkg"
    else
        fail "manifest package attr != $pkg"
    fi
    if printf '%s\n' "$xmltree" | grep -Fq '"nsp.probe.ProbeApp"'; then
        ok "application android:name == nsp.probe.ProbeApp"
    else
        fail "application android:name mismatch"
    fi
    if printf '%s\n' "$xmltree" | grep -Fq '"nsp.probe.ProbeActivity"'; then
        ok "activity android:name == nsp.probe.ProbeActivity"
    else
        fail "activity android:name mismatch"
    fi

    verify_rc=0
    verify_out="$("$APKSIGNER" verify --verbose --print-certs "$apk" 2>&1)" || verify_rc=$?
    if [ "$verify_rc" -eq 0 ]; then
        ok "apksigner verify (exit 0)"
    else
        fail "apksigner verify exit=$verify_rc"
    fi
    schemes="$(printf '%s\n' "$verify_out" | grep -E '^Verified using v[0-9]+ scheme' | tr '\n' ';' || true)"
    line "  apksigner.schemes: $schemes"
    line "  apksigner.cert: $(printf '%s\n' "$verify_out" | grep -m1 'certificate DN' || true)"
    if printf '%s\n' "$verify_out" | grep -Eq '^Verified using v[0-9]+ scheme.*: true'; then
        ok "signature scheme verified"
    else
        fail "no verified signature scheme"
    fi

    entries="$(unzip -Z1 "$apk")"
    if printf '%s\n' "$entries" | grep -Fxq 'classes.dex'; then
        ok "zip root contains classes.dex"
    else
        fail "missing classes.dex at zip root"
    fi
    if printf '%s\n' "$entries" | grep -Fxq 'AndroidManifest.xml'; then
        ok "zip root contains AndroidManifest.xml"
    else
        fail "missing AndroidManifest.xml at zip root"
    fi

    if "$ZIPALIGN" -c -v 4 "$apk" >/dev/null 2>&1; then
        ok "zipalign -c 4 passed"
    else
        fail "zipalign -c 4 failed"
    fi

    dex_strings="$(unzip -p "$apk" classes.dex | strings)"
    missing=""
    for lit in "${DEX_LITERALS[@]}"; do
        # dex 字符串池用 uleb128 长度前缀，短串在 strings 输出里可能带前导控制字节，
        # 类描述符又形如 "Lnsp/probe/ProbeApp;"，故用子串匹配而非整行匹配。
        if ! printf '%s\n' "$dex_strings" | grep -Fq -- "$lit"; then
            missing="$missing [$lit]"
        fi
    done
    if [ -z "$missing" ]; then
        ok "dex contains all ${#DEX_LITERALS[@]} expected literals"
    else
        fail "dex missing literals:$missing"
    fi

    if [ "$fail_count" -eq "$apk_fail_start" ]; then
        line "  RESULT: PASS"
        pass_count=$((pass_count + 1))
    else
        line "  RESULT: FAIL"
    fi
    line ""
done

line "== probe log contract (runtime, logcat tag NSP_PROBE) =="
line "line: case=<ftp|sftp|hide|iso|plain|unlink|race>|step=<name>|ok=<0|1>|detail=<...>  (detail never contains '|')"
line "ftp/sftp: start, mkdir, write, read, list, canary, done"
line "hide:     start, phase_a OR (phase_b, write_denied), list, done"
line "iso:      start, download, pictures, android_root, android_list, android_obb_own, android_media_own, android_allow, done"
line "plain:    start, write, read, done"
line "unlink:   start, delete, hidden_open, fstat, read, hidden_closed, exists_closed, hidden_legacy, done"
line "race:     start, attempt×N (i/ms/fuse/a/b), summary, done  -- no FUSE readiness wait by design"
line "done:     final sentinel (ok=1 on completion, ok=0 after step=exception)"
line ""

if [ "$fail_count" -eq 0 ] && [ "$pass_count" -eq "$total" ]; then
    line "RESULT: PASS ($pass_count/$total APKs)"
    mv "$TMP_OUT" "$OUT"
    printf '[check-probes] PASS: %s\n' "$OUT"
    exit 0
fi

line "RESULT: FAIL ($fail_count failed checks, $pass_count/$total APKs passed)"
mv "$TMP_OUT" "$OUT"
printf '[check-probes] FAIL: %s\n' "$OUT" >&2
exit 1
