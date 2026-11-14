#ifndef NSP_BUILD_INFO_H
#define NSP_BUILD_INFO_H
/*
 * build_info.h — 构建水印与设备环境采集（sys.log 头 + crash 归因）
 *
 * 背景：线下日志包曾无法对应到代码提交（崩溃 backtrace 仅 2 帧绝对地址，
 * stripped 产物无符号），排查靠猜。本模块把三类信息打进 sys.log：
 *   1. 构建水印：git 提交哈希（vcs_tag 构建期生成 NSP_GIT_HASH）+ 项目版本 +
 *      编译日期/编译器/target（android/gnu）+ debug/release；
 *   2. 内核/系统：uname（sysname/release/version/machine）；
 *   3. 硬件：/proc/cpuinfo（Hardware/model name 首见 + processor 计数）、
 *      /proc/meminfo（MemTotal/Available），Android 另读
 *      ro.build.version.release/sdk、ro.product.model/brand/device、
 *      ro.build.display.id/fingerprint（__system_property_get，无 binder）。
 *
 * 线程/信号安全：采集函数仅在进程启动普通上下文调用（允许 fopen/getenv）；
 * crash_handler 内只用 NSP_GIT_HASH 等编译期宏 + safe_printf，不调本模块。
 */
#include <stddef.h>

/* 构建水印头由 meson 的 vcs_tag 在**构建期**生成（ninja 每次刷新，见 meson.build）；
   直接 gcc 编译（测试夹具 / 第三方）时没有这个头，走下面的回退 */
#ifdef __has_include
#if __has_include("nsp_git_hash.h")
#include "nsp_git_hash.h"
#endif
#endif
/* meson 未注入时（如第三方直接 gcc）的回退，保证头文件自包含可编译 */
#ifndef NSP_GIT_HASH
#define NSP_GIT_HASH "unknown"
#endif
#ifndef NSP_BUILD_MODE
#define NSP_BUILD_MODE "unknown"
#endif
#ifndef NSP_PROJECT_VERSION
#define NSP_PROJECT_VERSION "unknown"
#endif

/* 每行上限（含终止符），与调用方栈缓冲对齐 */
#define NSP_BUILD_LINE_MAX 256
/* 环境行上限：cpuinfo/fingerprint 可能较长，采集侧截断 */
#define NSP_BUILD_LINES_MAX 16

const char* nsp_git_hash(void);

/* 构建头行：[0..n)，每行如 "build: git=<short> version=1.0.0 ..."（不带
 * [proc] 前缀：LOG() 路径由帧协议自动加，直推 log_monitor 的调用方自行拼）。
 * proc 参数保留供未来扩展，当前实现忽略。返回写入行数（0 表示非法）。 */
int nsp_collect_build_headers(const char* proc, char out[][NSP_BUILD_LINE_MAX],
                              int max_lines);
/* 设备环境头行：每行如 "env: uname=Linux ..."。同上。 */
int nsp_collect_env_headers(const char* proc, char out[][NSP_BUILD_LINE_MAX],
                            int max_lines);

/* 快捷：经 LOG()（common.h）逐行输出构建 + 环境头（injector/fuse_daemon
 * 在 log_init 后调用；日志经 UDS 进 sys.log）。 */
void nsp_log_build_info(const char* proc);

#endif /* NSP_BUILD_INFO_H */
