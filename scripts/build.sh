#!/usr/bin/env bash
# Fuse-Proxy 一键构建脚本（GNU/Linux 本机构建）。
#
# libfuse 按平台隔离（-Dlibfuse_source，默认 auto）：
#   - auto（默认）：系统主线 libfuse3（pkg-config）优先，缺失时回退编译
#     项目内子模块 subprojects/libfuse（master-Android，与 ~/libfuse 同源，
#     GNU 下可正常协商）——clone 后一键编译成功；
#   - system：强制系统库：scripts/build.sh build_gnu -Dlibfuse_source=system
#   - custom：~/libfuse 的 GNU 预构建：scripts/build.sh build_gnu_custom \
#       -Dlibfuse_source=custom -Dcustom_libfuse_root=$HOME/libfuse-install
#   - subproject：强制子模块：scripts/build.sh build_gnu_sp -Dlibfuse_source=subproject
#   GNU 下 json-c 与 libcurl：系统 pkg-config 优先，缺失自动回退 cmake 子模块
#   （subprojects/json-c@上游0.19 / subprojects/curl@8.22.0 pin 版，无需选项）。
# Android：libfuse/json-c/libcurl 默认走项目内子模块随主项目 NDK 交叉编译
#  （-Dandroid_libfuse=prebuilt / -Dandroid_json_c=prebuilt /
#   -Dandroid_curl=prebuilt 可分别切回预构建，见 android-aarch64.ini，
#   与本脚本无关）。
#
# 用法：scripts/build.sh [构建目录] [额外 meson 参数...]
#   例：scripts/build.sh build_gnu -Denable_debug=true
set -euo pipefail

cd "$(dirname "$0")/.."
BUILD_DIR="${1:-build_gnu}"
shift 2>/dev/null || true

echo "==> [1/3] 初始化子模块（libfuse/json-c/curl，供 auto 回退 / subproject 使用）"
git submodule update --init --recursive subprojects/libfuse subprojects/json-c subprojects/curl

echo "==> [2/3] meson 配置（${BUILD_DIR}）"
if [ -f "${BUILD_DIR}/build.ninja" ]; then
  meson setup --reconfigure "${BUILD_DIR}" "$@"
else
  meson setup "${BUILD_DIR}" -Dtarget_os=gnu "$@"
fi

echo "==> [3/3] 编译"
ninja -C "${BUILD_DIR}"

echo
echo "==> 构建完成：${BUILD_DIR}/"
echo "    产物：fuse_daemon（含内建规则引擎 fw_rules）/ log_monitor / log_ctl / rule_server / ftp_module.so / global_replace_ctl"
if [ -f "${BUILD_DIR}/meson-info/intro-projectinfo.json" ] && grep -q '"libfuse"' "${BUILD_DIR}/meson-info/intro-projectinfo.json" 2>/dev/null; then
  echo "    libfuse3 来源：项目内子模块 subprojects/libfuse"
else
  echo "    libfuse3 来源：系统 pkg-config / 定制预构建（见 meson 配置日志）"
fi
echo "    测试：python3 tests/test_functional.py（需 fusermount3 与 /dev/fuse）"
