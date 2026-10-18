#!/usr/bin/env bash
# 为 Android 交叉编译 SFTP 依赖：mbedTLS + libssh2（静态，arm64-v8a）。
#
# 为什么需要它：NDK 既不带 libssh2 也不带 OpenSSL/mbedTLS，而 libcurl 的 SFTP
# 后端（libssh2）需要一个密码学库。本脚本产出「预构建根」供 meson 消费：
#
#   scripts/build-libssh2-android.sh [输出目录]      # 默认 $HOME/.cache/fuse-proxy-android/sftp
#   （输出目录须在**项目源码树之外**：meson 的 cmake 子项目会忽略源码树内、
#     子项目外的 include 路径，curl 会以「libssh2.h not found」失败）
#   scripts/android-build.sh build_android -Dsftp=enabled \
#       -Dlibssh2_dir="$PWD/.deps/android-libssh2"
#
# 产出布局（meson 的 -Dlibssh2_dir 约定）：
#   <根>/include/libssh2*.h
#   <根>/lib/libssh2.a  +  libmbedtls.a / libmbedx509.a / libmbedcrypto.a
# meson 侧把 libssh2.a 交给 curl 的 cmake（-DLIBSSH2_LIBRARY），并把 lib/ 下
# 已知名（mbedtls/mbedx509/mbedcrypto/ssl/crypto/...）的库一并静态链接进
# ftp_module.so。
#
# 版本：mbedTLS 3.6.2（LTS）+ libssh2 1.11.1（两者搭配已在 NDK r29 / API 29 实测）。
# 源码获取：优先用 ANDROID_SFTP_SRC=<目录>（内含 mbedtls/ 与 libssh2/ 子目录，
# 便于离线/复用），否则 git clone 到临时目录（mbedTLS 需 --recurse-submodules）。
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$(pwd)"
# 显式传空串也要能识别：":-" 形式会把空串当未提供而落回默认，危险路径检查就失效
OUT_ARG="${1-$HOME/.cache/fuse-proxy-android/sftp}"

# ── 输出目录白名单（必须在任何 mkdir / rm -rf 之前）─────────────────────────
# 脚本末尾会对输出目录执行 rm -rf。rm 只保护 /（--preserve-root），不保护
# $HOME、用户数据目录或项目根——参数传错一次就是整个目录被删。故先校验再动手：
#   1) 非空、非 /、非 $HOME、非项目根（规范化后再查一次，防 .. 绕过）；
#   2) 最后一级含可识别前缀（sftp / fuse-proxy-android），挡住误传 $HOME/xxx；
#   3) 仍拒绝项目源码树内（meson 的 cmake 子项目会忽略其中的 include 路径）。
out_reject() {
  echo "error: 拒绝危险的输出目录：$1" >&2
  echo "       $2" >&2
  echo "       本脚本会对输出目录执行 rm -rf；请显式指定专属目录，例如：" >&2
  echo "       scripts/build-libssh2-android.sh \"\$HOME/.cache/fuse-proxy-android/sftp\"" >&2
  exit 1
}
[ -n "$OUT_ARG" ] || out_reject "(空)" "输出目录不能为空。"
[ "$OUT_ARG" != "/" ] || out_reject "$OUT_ARG" "不能是根目录。"
[ "$OUT_ARG" != "$HOME" ] || out_reject "$OUT_ARG" "不能是 HOME 本身。"
[ "$OUT_ARG" != "$ROOT" ] || out_reject "$OUT_ARG" "不能是项目根。"
out_base="$(basename "$OUT_ARG")"
case "$out_base" in
  *sftp* | *fuse-proxy-android*) : ;;
  *) out_reject "$OUT_ARG" "最后一级须含 sftp 或 fuse-proxy-android（实际：$out_base）。" ;;
esac
mkdir -p "$(dirname "$OUT_ARG")"
OUT="$(cd "$(dirname "$OUT_ARG")" && pwd)/$(basename "$OUT_ARG")"
# 规范化后再校验一次：.. 等写法可能把最终路径落回危险位置
[ "$OUT" != "/" ] || out_reject "$OUT" "规范化后是根目录。"
[ "$OUT" != "$HOME" ] || out_reject "$OUT" "规范化后是 HOME。"
[ "$OUT" != "$ROOT" ] || out_reject "$OUT" "规范化后是项目根。"
# 预构建**不能落在项目源码树内**：meson 的 cmake 子项目转换会把「根项目内、子项目
# 外」的 include 路径判为不可用并静默忽略，症状是 curl 编译到 libssh2.h 才报
# file not found（错误指不到真因）。meson.build 侧也有同样的守卫。
case "$OUT/" in
  "$ROOT"/*)
    out_reject "$OUT" "输出目录不能位于项目源码树内：meson 的 cmake 子项目会忽略源码树内、子项目外的 include 路径。";;
esac
API="${ANDROID_API:-29}"
MBEDTLS_TAG="${MBEDTLS_TAG:-v3.6.2}"
LIBSSH2_TAG="${LIBSSH2_TAG:-libssh2-1.11.1}"

echo "==> [1/4] 搜索 NDK"
NDK=""
for cand in "${ANDROID_NDK_HOME:-}" "${ANDROID_NDK_ROOT:-}"; do
  if [ -n "$cand" ] && [ -d "$cand/toolchains/llvm/prebuilt/linux-x86_64/bin" ]; then
    NDK="$cand"; break
  fi
done
if [ -z "$NDK" ]; then
  for base in "$HOME/android-ndk" "$HOME/Android/Sdk/ndk" \
              /opt/android-sdk/ndk /opt/android-sdk \
              /usr/local/android-sdk/ndk /usr/local/android-sdk; do
    [ -d "$base" ] || continue
    for d in $(ls -1d "$base"/*/ 2>/dev/null | sort -V); do
      if [ -d "${d}toolchains/llvm/prebuilt/linux-x86_64/bin" ]; then NDK="$d"; fi
    done
    [ -n "$NDK" ] && break
    if [ -d "$base/toolchains/llvm/prebuilt/linux-x86_64/bin" ]; then NDK="$base"; break; fi
  done
fi
[ -n "$NDK" ] || { echo "error: 未找到 Android NDK，请设置 ANDROID_NDK_HOME" >&2; exit 1; }
NDK="$(cd "$NDK" && pwd)"
TC="$NDK/build/cmake/android.toolchain.cmake"
[ -f "$TC" ] || { echo "error: $TC 不存在" >&2; exit 1; }
echo "    NDK：$NDK（API $API，ABI arm64-v8a）"

echo "==> [2/4] 准备源码"
WORK=""
cleanup() {
  # 必须显式收尾成 0：EXIT trap 最后一条命令的状态会成为脚本退出码，而
  # `[ -n "$WORK" ] && rm -rf "$WORK"` 在 WORK 为空（ANDROID_SFTP_SRC 复用
  # 本地源码那条路）时返回 1 → 预构建明明成功，脚本却以 1 退出。
  if [ -n "$WORK" ]; then rm -rf "$WORK"; fi
}
trap cleanup EXIT
if [ -n "${ANDROID_SFTP_SRC:-}" ]; then
  SRC="$(cd "$ANDROID_SFTP_SRC" && pwd)"
  [ -d "$SRC/mbedtls" ] && [ -d "$SRC/libssh2" ] || {
    echo "error: ANDROID_SFTP_SRC=$SRC 下需有 mbedtls/ 与 libssh2/ 两个目录" >&2; exit 1; }
  echo "    复用 $SRC"
else
  WORK="$(mktemp -d)"
  SRC="$WORK"
  echo "    clone mbedTLS $MBEDTLS_TAG（含子模块）+ libssh2 $LIBSSH2_TAG → $WORK"
  git clone -q --depth 1 --recurse-submodules --shallow-submodules \
      --branch "$MBEDTLS_TAG" https://github.com/Mbed-TLS/mbedtls.git "$SRC/mbedtls"
  git clone -q --depth 1 --branch "$LIBSSH2_TAG" \
      https://github.com/libssh2/libssh2.git "$SRC/libssh2"
fi

echo "==> [3/4] 交叉编译 mbedTLS（静态）"
# NDK r30 的 clang 21 对 mbedTLS 3.6.2 的 TLS 1.3 label 表
# （library/ssl_tls13_keys.c:44，有意 nonstring 的初始化）报
# -Wunterminated-string-initialization；mbedTLS 默认 MBEDTLS_FATAL_WARNINGS=ON
# 把它变成 -Werror，交叉编译直接失败。只把这一条降级为告警：其余告警仍按
# -Werror 处理（-DMBEDTLS_FATAL_WARNINGS=OFF 也能过，但会把第三方告警全放行）。
cmake -S "$SRC/mbedtls" -B "$SRC/mbedtls/build" \
  -DCMAKE_TOOLCHAIN_FILE="$TC" -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM="android-$API" \
  -DENABLE_PROGRAMS=OFF -DENABLE_TESTING=OFF \
  -DUSE_SHARED_MBEDTLS_LIBRARY=OFF -DUSE_STATIC_MBEDTLS_LIBRARY=ON \
  -DCMAKE_C_FLAGS="-Wno-error=unterminated-string-initialization" \
  -DCMAKE_BUILD_TYPE=Release >/dev/null
cmake --build "$SRC/mbedtls/build" -j"$(nproc)" >/dev/null

echo "==> [4/4] 交叉编译 libssh2（CRYPTO_BACKEND=mbedTLS）"
cmake -S "$SRC/libssh2" -B "$SRC/libssh2/build" \
  -DCMAKE_TOOLCHAIN_FILE="$TC" -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM="android-$API" \
  -DCRYPTO_BACKEND=mbedTLS \
  -DMBEDTLS_INCLUDE_DIR="$SRC/mbedtls/include" \
  -DMBEDTLS_LIBRARY="$SRC/mbedtls/build/library/libmbedtls.a" \
  -DMBEDX509_LIBRARY="$SRC/mbedtls/build/library/libmbedx509.a" \
  -DMBEDCRYPTO_LIBRARY="$SRC/mbedtls/build/library/libmbedcrypto.a" \
  -DBUILD_SHARED_LIBS=OFF -DBUILD_EXAMPLES=OFF -DBUILD_TESTING=OFF \
  -DCMAKE_BUILD_TYPE=Release >/dev/null
cmake --build "$SRC/libssh2/build" -j"$(nproc)" >/dev/null

rm -rf "$OUT"
mkdir -p "$OUT/include" "$OUT/lib"
cp "$SRC"/libssh2/include/*.h "$OUT/include/"
cp "$SRC"/libssh2/build/src/libssh2.a "$OUT/lib/"
cp "$SRC"/mbedtls/build/library/libmbedtls.a \
   "$SRC"/mbedtls/build/library/libmbedx509.a \
   "$SRC"/mbedtls/build/library/libmbedcrypto.a "$OUT/lib/"

echo
echo "==> 完成：$OUT"
ls -la "$OUT/lib"
echo
echo "接着用（二选一）："
echo "  scripts/android-build.sh build_android -Dsftp=enabled -Dlibssh2_dir=\"$OUT\""
echo "  meson setup build_android --cross-file android-aarch64.ini \\"
echo "      -Dsftp=enabled -Dlibssh2_dir=\"$OUT\" -Dandroid_ndk_root=\"$NDK\""
