/*
 * tests/fixtures/ftp_upload_lock_driver.c
 *
 * 「ftp_backend_upload 泄漏 f_lock」的判别性回归（tests/test_ftp_upload_lock.py）。
 *
 * 背景（本用例守护的修复，src/modules/ftp/ftp_backend_libcurl.c）：
 *   乱序改写已流式上传的前缀（off < up_upto）会置 retransmit，close() 触发
 *   FLUSH → ftp_write_sync 走 ftp_backend_upload 全量 STOR 覆盖。旧实现里
 *   ftp_backend_upload 只给三条提前返回解锁，主路径（全量 STOR 成功/失败）
 *   直接 `return rc`，**锁随句柄泄漏**——存活 fd 的下一次 write 与最终
 *   release 永久阻塞（应用表现为「写完 close，再写就卡死」）。
 *
 * 做法：直接编入实际源码（-DFTP_BACKEND_SRC），把控制面 mux（ftp_mux_* /
 * ftp_easy_new）与 libcurl easy（setopt/perform/getinfo/cleanup）全部桩化，
 * 并用桩模拟一个**极简 FTP 服务器**：STOR 覆盖远端内容、APPE 追加远端内容。
 * 于是 write → 流式 STOR/APPE → 乱序改写 → FLUSH 全量 STOR 全走真实代码路径。
 *
 * 覆盖（旧实现上 A1 必失败；去掉看门狗则 B 会挂死）：
 *   A1 FLUSH 后 f_lock 未被泄漏（trylock 必须成功）——锁泄漏的直接证据
 *   A2 乱序改写后全量重传的远端内容与本地一致（'Z'*16 + 'A'*rest）
 *   B1 FLUSH 之后的续写不挂起（看门狗 8s 内返回）
 *   B2 FLUSH 之后的 release 不挂起
 *   B3 续写的数据确实落远端（远端长度与字节正确）
 *
 * 退出码 0 = 全过；1 = 有失败（含看门狗超时，直接 _exit(1) 避免挂死）。
 */
#define _GNU_SOURCE
#include <curl/curl.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
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

/* ============ 桩模拟的「极简 FTP 服务器」状态 ============ */
#define REMOTE_CAP (1u << 21) /* 2MB，够 256KB 用例 */
static char g_remote[REMOTE_CAP];
static size_t g_remote_len = 0;
static int g_stor_performs = 0; /* 上传请求计数 */

/* 当前 easy 任务（本用例串行执行，单槽足够） */
static char g_cur_url[2048];
static bool g_cur_upload;
static bool g_cur_append;
static long g_cur_infilesize;
static curl_read_callback g_cur_rf;
static void* g_cur_rd;

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
    g_cur_append = false;
    g_cur_infilesize = -1;
    g_cur_rf = NULL;
    g_cur_rd = NULL;
    return (CURL*)(void*)g_dummy_easy;
}

/* 模拟服务端接收一次上传：STOR（append=false）截断覆盖、APPE 追加 */
static CURLcode serve_upload(void) {
    char tmp[4096];
    if (!g_cur_append) g_remote_len = 0;
    for (;;) {
        size_t n = g_cur_rf ? g_cur_rf(tmp, 1, sizeof tmp, g_cur_rd) : 0;
        if (n == 0) break;
        if (g_remote_len + n > REMOTE_CAP) n = REMOTE_CAP - g_remote_len;
        memcpy(g_remote + g_remote_len, tmp, n);
        g_remote_len += n;
        if (g_remote_len >= REMOTE_CAP) break;
    }
    g_stor_performs++;
    return CURLE_OK;
}

CURLcode ftp_mux_perform(FtpMux* m, CURL* easy) {
    (void)m;
    (void)easy;
    if (g_cur_upload) return serve_upload();
    return CURLE_OK; /* 本用例不经控制面 */
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
        case CURLOPT_APPEND: g_cur_append = va_arg(ap, long) != 0; break;
        case CURLOPT_INFILESIZE: g_cur_infilesize = (long)va_arg(ap, long); break;
        case CURLOPT_READFUNCTION: g_cur_rf = va_arg(ap, curl_read_callback); break;
        case CURLOPT_READDATA: g_cur_rd = va_arg(ap, void*); break;
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
            if (out) *(curl_off_t*)out = (curl_off_t)g_remote_len;
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
#define FILE_SIZE (256 * 1024)

static int g_fail;
static void ck(bool ok, const char* name, const char* detail) {
    printf("  %s %s", ok ? "[PASS]" : "[FAIL]", name);
    if (!ok && detail && *detail) printf(" — %s", detail);
    printf("\n");
    if (!ok) g_fail = 1;
}

/* 等待流式上传线程追平到 >= want（超时返回 false） */
static bool wait_upto(uint64_t h, off_t want, double timeout_s) {
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (;;) {
        FtpBackendFile* f = ftp_handle_get(h);
        if (!f) return false;
        pthread_mutex_lock(&f->f_lock);
        off_t up = f->up_upto;
        pthread_mutex_unlock(&f->f_lock);
        if (up >= want) return true;
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        if ((now.tv_sec - t0.tv_sec) + (now.tv_nsec - t0.tv_nsec) / 1e9 > timeout_s)
            return false;
        usleep(20 * 1000);
    }
}

typedef struct {
    uint64_t h;
    int rc_write;
    int rc_release;
} TailArgs;

static void* tail_thread(void* arg) {
    TailArgs* t = arg;
    size_t w = 0;
    t->rc_write = ftp_backend_write(t->h, "Y", 1, 1000, &w);
    t->rc_release = ftp_backend_release(t->h);
    return NULL;
}

int main(void) {
    printf("── FTP 上传锁泄漏（乱序改写→close→再写） ──\n");

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

    uint64_t h = 0;
    if (ftp_backend_open("/ftproot/dir/f", O_WRONLY | O_CREAT | O_TRUNC, &h) != 0 || h == 0) {
        ck(false, "写模式打开", "ftp_backend_open 失败");
        return 1;
    }

    /* 1. 顺序写满 256KB：流式上传线程推送（首块 STOR + 后续 APPE） */
    char* big = malloc(FILE_SIZE);
    memset(big, 'A', FILE_SIZE);
    size_t wrote = 0;
    if (ftp_backend_write(h, big, FILE_SIZE, 0, &wrote) != 0 || wrote != FILE_SIZE) {
        ck(false, "顺序写 256KB", "write 返回异常");
        return 1;
    }
    free(big);
    ck(wait_upto(h, FILE_SIZE, 10.0), "P0 流式上传追平（up_upto == file_end）",
       "上传线程未在 10s 内追平（前置失败，后续断言不可信）");

    /* 2. 乱序改写已上传前缀（off < up_upto）→ 置 retransmit */
    if (ftp_backend_write(h, "ZZZZZZZZZZZZZZZZ", 16, 0, &wrote) != 0 || wrote != 16) {
        ck(false, "乱序改写 16 字节 @0", "write 返回异常");
        return 1;
    }

    /* 3. FLUSH：走 ftp_write_sync → ftp_backend_upload 全量 STOR 覆盖。
          旧实现此处泄漏 f_lock。 */
    int frc = ftp_backend_flush(h);
    ck(frc == 0, "P1 FLUSH 返回 0", "flush 返回非 0");

    /* A1. 锁泄漏的直接证据：FLUSH 返回后 f_lock 必须处于未持有状态 */
    FtpBackendFile* f = ftp_handle_get(h);
    if (!f) {
        ck(false, "A1 FLUSH 后 f_lock 未被泄漏", "句柄已失效");
    } else {
        int tr = pthread_mutex_trylock(&f->f_lock);
        if (tr == 0) pthread_mutex_unlock(&f->f_lock);
        ck(tr == 0, "A1 FLUSH 后 f_lock 未被泄漏（trylock 成功）",
           "trylock 返回 EBUSY —— ftp_backend_upload 主路径漏解锁");
    }

    /* A2. 全量重传的远端内容 == 本地内容（'Z'*16 + 'A'*rest） */
    bool content_ok = (g_remote_len == FILE_SIZE) &&
                      memcmp(g_remote, "ZZZZZZZZZZZZZZZZ", 16) == 0;
    if (content_ok)
        for (size_t i = 16; i < FILE_SIZE; i++)
            if (g_remote[i] != 'A') { content_ok = false; break; }
    ck(content_ok, "A2 乱序改写后全量重传内容正确",
       "远端内容与本地不一致（前缀 'Z'*16 + 'A'*rest）");

    /* B. FLUSH 之后从存活 fd 续写 + release：旧实现永久挂起 */
    pthread_t th;
    TailArgs ta = {h, -999, -999};
    if (pthread_create(&th, NULL, tail_thread, &ta) != 0) {
        ck(false, "B 续写看门狗线程创建", "pthread_create 失败");
        return 1;
    }
    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += 8;
    int jr = pthread_timedjoin_np(th, NULL, &deadline);
    if (jr != 0) {
        ck(false, "B1 FLUSH 后续写不挂起", "8s 内未返回 —— 写永久挂起（锁泄漏）");
        printf("%s\n", "结果: 存在失败");
        fflush(stdout);
        _exit(1); /* 线程已卡死，正常退出会挂住：直接结束进程 */
    }
    ck(ta.rc_write == 0, "B1 FLUSH 后续写不挂起", "write 返回非 0");
    ck(ta.rc_release == 0, "B2 FLUSH 后 release 不挂起", "release 返回非 0");
    ck(g_remote_len == FILE_SIZE && g_remote[1000] == 'Y',
       "B3 续写数据落远端（长度不变、offset 1000 为 'Y'）",
       "远端长度或内容不符");

    printf("%s\n", g_fail ? "结果: 存在失败" : "结果: 全部通过");
    return g_fail;
}
