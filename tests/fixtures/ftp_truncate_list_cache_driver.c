/*
 * tests/fixtures/ftp_truncate_list_cache_driver.c
 *
 * 「truncate 清 LIST 缓存」的确定性回归（tests/test_ftp_truncate_list.py 有背景）。
 *
 * 背景（本用例守护的修复，src/modules/ftp/ftp_backend_libcurl.c）：
 *   readdir 拉取 LIST 后会把每个子项的 size 预填进 stat 缓存（优化 3：列举后
 *   getattr 零网络）。故 truncate 只清 stat 缓存是不够的——若不清 LIST 缓存，
 *   下一次列举会命中旧 LIST、把**截断前**的 size 重新预填回 stat 缓存，应用
 *   于是永远看到旧大小（旧实现正是如此；修复加 ftp_list_cache_clear）。
 *
 * 做法：直接编入实际源码 ftp_backend_libcurl.c（-DFTP_BACKEND_SRC），把控制面
 * 的 mux（ftp_mux_* / ftp_easy_new）与 libcurl 的 easy 选项/取值/执行全部桩化：
 *  - LIST 请求（URL 以 / 结尾）→ 回调写入合成 LIST 正文，size 取自模拟的
 *    服务端状态 g_remote_size；
 *  - STOR 上传（CURLOPT_UPLOAD + INFILESIZE=0，即 size==0 的 truncate）→ 把
 *    g_remote_size 置 0。
 * 于是「列举 → 截断 → 再列举 → stat」全走真实代码路径，而服务端状态完全可控。
 *
 * 覆盖：
 *   A. 截断前：列举预取使 getattr 返回 LIST 里的 size=10。
 *   B. 截断（size=0）后再次列举：LIST 缓存已失效 → 重新拉取 → size=0；
 *      且确实发生了新的 LIST 请求（可判别：不清 LIST 时不会重新拉取）。
 *   C. 对照：未被截断的邻居条目仍取新 LIST 的大小，未被误伤。
 *
 * 退出码 0 = 全过；1 = 有失败。移除 ftp_backend_truncate 里的
 * ftp_list_cache_clear 后 B 必失败。
 */
#define _GNU_SOURCE
#include <curl/curl.h>
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "nsp_module.h"
#include "ftp_conf.h"
#include "ftp_mux.h"

#ifndef FTP_BACKEND_SRC
#define FTP_BACKEND_SRC "ftp_backend_libcurl.c"
#endif

/* ============ 框架运行时桩（不链接 common.c；nsp_util.c 提供真实原语） ============ */
LogLevel g_min_log_level = LOG_ERROR;
void log_internal(LogLevel level, const char* format, ...) {
    (void)level;
    (void)format;
}

/* ============ 模拟服务端状态与当前任务 ============ */
static long g_remote_size = 10;      /* LIST 报告的文件大小 */
static int g_list_performs = 0;      /* LIST 请求计数 */
static int g_stor_performs = 0;      /* 上传请求计数 */

/* 当前 easy 任务（本用例串行执行，故单槽足够） */
static char g_cur_url[2048];
static bool g_cur_upload;
static long g_cur_infilesize;
static curl_write_callback g_cur_wf;
static void* g_cur_wd;

/* ============ mux 桩（不链接 ftp_mux.c） ============ */
static char g_dummy_mux[64];
FtpMux* ftp_mux_new(void) { return (FtpMux*)(void*)g_dummy_mux; }
FtpMux* ftp_mux_ref(FtpMux* m) { return m; }
void ftp_mux_unref(FtpMux* m) { (void)m; }
void ftp_mux_shutdown(FtpMux* m) { (void)m; }
void ftp_mux_invalidate(FtpMux* m) { (void)m; }

static char g_dummy_easy[64];
CURL* ftp_easy_new(const FtpServerCfg* cfg) {
    (void)cfg;
    g_cur_url[0] = '\0';
    g_cur_upload = false;
    g_cur_infilesize = -1;
    g_cur_wf = NULL;
    g_cur_wd = NULL;
    return (CURL*)(void*)g_dummy_easy;
}

/* 合成一页 FTP LIST 正文（含固定条目 f 与邻居 keep） */
static size_t emit_list_body(void) {
    char body[512];
    int n = snprintf(body, sizeof body,
                     "-rw-r--r-- 1 user group %ld Jan  1 00:00 f\r\n"
                     "-rw-r--r-- 1 user group 33 Jan  1 00:00 keep\r\n",
                     g_remote_size);
    size_t wrote = 0;
    if (g_cur_wf && g_cur_wd && n > 0)
        wrote = g_cur_wf(body, 1, (size_t)n, g_cur_wd);
    return wrote;
}

CURLcode ftp_mux_perform(FtpMux* m, CURL* easy) {
    (void)m;
    (void)easy;
    size_t ulen = strlen(g_cur_url);
    if (g_cur_upload) {
        g_stor_performs++;
        g_remote_size = g_cur_infilesize > 0 ? g_cur_infilesize : 0;
        return CURLE_OK;
    }
    if (ulen > 0 && g_cur_url[ulen - 1] == '/') {
        g_list_performs++;
        emit_list_body();
        return CURLE_OK;
    }
    /* 单文件 LIST/STAT（URL 不以 / 结尾）：本用例不经此路径 */
    return CURLE_OK;
}

/* ============ libcurl easy 桩 ============ */
CURLcode mock_easy_setopt(CURL* handle, CURLoption option, ...) {
    (void)handle;
    va_list ap;
    va_start(ap, option);
    switch (option) {
        case CURLOPT_URL:
            snprintf(g_cur_url, sizeof g_cur_url, "%s", va_arg(ap, const char*));
            break;
        case CURLOPT_UPLOAD: g_cur_upload = va_arg(ap, long) != 0; break;
        case CURLOPT_INFILESIZE: g_cur_infilesize = (long)va_arg(ap, long); break;
        case CURLOPT_WRITEFUNCTION: g_cur_wf = va_arg(ap, curl_write_callback); break;
        case CURLOPT_WRITEDATA: g_cur_wd = va_arg(ap, void*); break;
        default: break; /* 其余选项参数不读取：可变实参无需清理 */
    }
    va_end(ap);
    return CURLE_OK;
}

CURLcode mock_easy_perform(CURL* handle) {
    (void)handle;
    return ftp_mux_perform(NULL, NULL);
}

CURLcode mock_easy_getinfo(CURL* handle, CURLINFO info, ...) {
    (void)handle;
    va_list ap;
    va_start(ap, info);
    void* out = va_arg(ap, void*);
    switch (info) {
        case CURLINFO_RESPONSE_CODE:
            if (out) *(long*)out = 226;
            break;
        case CURLINFO_FILETIME:
            if (out) *(long*)out = -1;
            break;
        case CURLINFO_CONTENT_LENGTH_DOWNLOAD_T:
            if (out) *(curl_off_t*)out = (curl_off_t)g_remote_size;
            break;
        default: break;
    }
    va_end(ap);
    return CURLE_OK;
}

void mock_easy_cleanup(CURL* handle) { (void)handle; }

/* typecheck-gcc.h 把 curl_easy_setopt 定义成函数式宏，须先 undef 再接管 */
#undef curl_easy_setopt
#undef curl_easy_perform
#undef curl_easy_getinfo
#undef curl_easy_cleanup
#define curl_easy_setopt  mock_easy_setopt
#define curl_easy_perform mock_easy_perform
#define curl_easy_getinfo mock_easy_getinfo
#define curl_easy_cleanup mock_easy_cleanup
#include FTP_BACKEND_SRC

/* ============ 用例 ============ */
static int g_fail;
static void ck(bool ok, const char* name, const char* detail) {
    printf("  %s %s", ok ? "[PASS]" : "[FAIL]", name);
    if (!ok && detail && *detail) printf(" — %s", detail);
    printf("\n");
    if (!ok) g_fail = 1;
}

static long list_dir_once(const char* dir, const char* want_first) {
    NspDirEntry entries[16];
    memset(entries, 0, sizeof entries);
    int n = ftp_backend_readdir(dir, entries, 16, 0);
    if (n <= 0) return -1;
    for (int i = 0; i < n; i++)
        if (strcmp(entries[i].name, want_first) == 0) return n;
    return -1;
}

int main(void) {
    printf("── FTP truncate 清 LIST 缓存（失败注入） ──\n");

    FtpServerCfg cfg;
    memset(&cfg, 0, sizeof cfg);
    snprintf(cfg.name, sizeof cfg.name, "ftproot");
    snprintf(cfg.host, sizeof cfg.host, "127.0.0.1");
    cfg.port = 2121;
    snprintf(cfg.user, sizeof cfg.user, "anonymous");
    cfg.remote_dir[0] = '\0';
    if (ftp_backend_add(&cfg) != 0) {
        ck(false, "后端注册", "ftp_backend_add 失败");
        return 1;
    }

    const char* dir = "/ftproot/dir";
    const char* file = "/ftproot/dir/f";

    /* A. 首次列举 → 预取 stat 缓存 → getattr 取到 LIST 的 size */
    g_remote_size = 10;
    long n = list_dir_once(dir, "f");
    ck(n >= 0, "A1 首次列举得到条目 f", "readdir 未返回 f");
    struct stat st;
    memset(&st, 0, sizeof st);
    bool g1 = ftp_backend_getattr(file, &st) == 0 && st.st_size == 10;
    ck(g1, "A2 截断前 size=10（列举预取生效）", "getattr 未返回 LIST 里的 size");
    ck(g_list_performs == 1, "A3 首次列举恰好一次 LIST 请求", "LIST 请求计数异常");

    /* B. truncate(0) → 再列举 → size 必须为 0（不被旧 LIST 回灌） */
    int lists_before = g_list_performs;
    int trc = ftp_backend_truncate(file, 0);
    ck(trc == 0, "B1 truncate(0) 成功", "truncate 返回非 0");
    ck(g_stor_performs == 1, "B2 截断经一次 STOR 上传", "上传请求计数异常");
    ck(g_remote_size == 0, "B3 服务端大小已置 0", "");
    n = list_dir_once(dir, "f");
    ck(n >= 0, "B4 截断后仍能列举", "readdir 未返回 f");
    bool refetched = g_list_performs > lists_before;
    ck(refetched, "B5 截断后列举重新拉取 LIST（缓存已失效）",
       "命中旧 LIST 缓存，未重新拉取");
    memset(&st, 0, sizeof st);
    bool g2 = ftp_backend_getattr(file, &st) == 0 && st.st_size == 0;
    ck(g2, "B6 截断后 size=0（旧 LIST 未回灌 stat 缓存）",
       "getattr 返回了截断前的旧 size");

    /* C. 对照：邻居条目仍取新 LIST 的大小（未被误伤） */
    memset(&st, 0, sizeof st);
    bool g3 = ftp_backend_getattr("/ftproot/dir/keep", &st) == 0 && st.st_size == 33;
    ck(g3, "C1 邻居条目 size 未被误伤（33）", "邻居条目 size 异常");

    printf("%s\n", g_fail ? "结果: 存在失败" : "结果: 全部通过");
    return g_fail;
}
