#!/usr/bin/env bash
# Fuse-Proxy Android 一键构建脚本（NDK 交叉编译）。
#
# 自动搜索 NDK（无需硬编码路径），顺序：
#   ANDROID_NDK_HOME > ANDROID_NDK_ROOT > ~/android-ndk/* >
#   ~/Android/Sdk/ndk/*（取最新）> /opt/android-sdk > /usr/local/android-sdk
# API 级别默认 35（项目兼容 API 33~35），经 ANDROID_API 覆盖。
# libfuse/json-c/libcurl 默认走子模块随主项目编译，无需手动准备预构建。
#
# 用法：scripts/android-build.sh [构建目录] [额外 meson 参数...]
#   例：scripts/android-build.sh build_android
#       ANDROID_API=34 scripts/android-build.sh build_android
#       ANDROID_NDK_HOME=/opt/ndk scripts/android-build.sh build_android -Denable_debug=true
set -euo pipefail

cd "$(dirname "$0")/.."
BUILD_DIR="${1:-build_android}"
shift 2>/dev/null || true
API="${ANDROID_API:-35}"

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
    # 子目录按版本升序取最后一个命中的（即最新）；都没有再试本级目录
    for d in $(ls -1d "$base"/*/ 2>/dev/null | sort -V); do
      if [ -d "${d}toolchains/llvm/prebuilt/linux-x86_64/bin" ]; then
        NDK="$d"
      fi
    done
    [ -n "$NDK" ] && break
    if [ -d "$base/toolchains/llvm/prebuilt/linux-x86_64/bin" ]; then
      NDK="$base"; break
    fi
  done
fi
if [ -z "$NDK" ]; then
  echo "error: 未找到 Android NDK，请设置 ANDROID_NDK_HOME" >&2
  exit 1
fi
NDK="$(cd "$NDK" && pwd)"
BIN="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin"
if [ ! -x "$BIN/aarch64-linux-android${API}-clang" ]; then
  echo "error: NDK $NDK 不含 API $API 工具链，可用：" >&2
  ls "$BIN" | grep -oE "aarch64-linux-android[0-9]+" | grep -oE "[0-9]+" | sort -nu | tr '\n' ' ' >&2
  echo >&2; echo "      可经 ANDROID_API=<级别> 覆盖" >&2
  exit 1
fi
echo "    NDK：$NDK"
echo "    API：$API"

echo "==> [2/4] 初始化子模块（libfuse/json-c/curl）"
git submodule update --init --recursive subprojects/libfuse subprojects/json-c subprojects/curl

echo "==> [3/4] meson 配置（${BUILD_DIR}）"
export PATH="$BIN:$PATH"
export ANDROID_NDK_ROOT="$NDK"
if [ -f "${BUILD_DIR}/build.ninja" ]; then
  meson setup --reconfigure "${BUILD_DIR}" -Dandroid_ndk_root="$NDK" "$@"
else
  meson setup "${BUILD_DIR}" --cross-file android-aarch64.ini -Dandroid_ndk_root="$NDK" "$@"
fi

echo "==> [4/4] 编译"
ninja -C "${BUILD_DIR}"

echo
echo "==> 构建完成：${BUILD_DIR}/"
echo "    产物：fuse_daemon / injector / log_monitor / log_ctl / rule_server / basic_rules.so / ftp_module.so"
echo "    依赖：libfuse/json-c/libcurl 均随主项目编译（静态链接），详见 meson 配置日志"
