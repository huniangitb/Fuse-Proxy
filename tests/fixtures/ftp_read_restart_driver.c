/*
 * test_ftp_read_restart.py 专用 C 驱动：确定性复现「随机跳变 vs 在途下载」
 * 竞态并守护修复（tests/test_ftp_read_restart.py 有完整背景说明）。
 *
 * 做法：直接编入实际源码 ftp_backend_libcurl.c（经 FTP_BACKEND_SRC 宏指定
 * 路径），只把下载线程用到的 curl_easy_perform / curl_easy_setopt 替换为
 * mock；ftp_dl_thread、ftp_backend_read、write_cb 全部走真实实现。
 * 时序完全由 mock 与主线程协调，不依赖网络与 FUSE：
 *   ① 下载线程进入 perform（旧偏移）并被 mock 阻塞；
 *   ② 主线程发起 read（新偏移）→ 真实 read 路径置 dl_restart 复位缓冲；
 *   ③ mock 此时才让旧传输返回（EOF 或真错误）——即竞态窗口；
 *   ④ 断言 read 仍取满请求字节，且重试下载落在新偏移。
 * 场景 C 为对照：无跳变时真实 EOF 必须仍被采纳（防修复过度丢弃）。
 *
 * 注意：FtpBackendFile 等类型随实际源码定义，故涉及 f_lock/download 状态的
 * mock_wait_jump 与测试骨架一律放在 #include 之后；mock 只经前置声明调用它。
 */
#define _GNU_SOURCE
#include <curl/curl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>

#include "nsp_module.h"

#ifndef FTP_BACKEND_SRC
#define FTP_BACKEND_SRC "ftp_backend_libcurl.c"
#endif

/* ================= 框架运行时桩（本驱动不链接 common.c；nsp_util.c 参与
   编译提供真实通用原语，仅 log_internal 仍桩化） ================= */
LogLevel g_min_log_level = LOG_ERROR;
void log_internal(LogLevel level, const char* format, ...) {
    (void)level;
    (void)format;
}

/* ================= curl mock ================= */

enum { SCEN_STALE_EOF = 0, SCEN_STALE_ERROR = 1, SCEN_CONTROL = 2 };

static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_cv = PTHREAD_COND_INITIALIZER;
static int g_perform_count = 0;
static int g_scenario = SCEN_STALE_EOF;
static char g_pending_range[64]; /* 最近一次 setopt(CURLOPT_RANGE) 取值 */
static char g_range[8][64];      /* 各次 perform 实际使用的 RANGE */
static curl_write_callback g_wf;
static void* g_wd;

/* 定义在 #include 之后（需 FtpBackendFile 类型）：等待 read 侧跳变置位。
   返回 true = 等到了 dl_restart（竞态场景成立）。 */
static bool mock_wait_jump(int ms);

CURLcode mock_easy_setopt(CURL* handle, CURLoption option, ...) {
    (void)handle;
    va_list ap;
    va_start(ap, option);
    pthread_mutex_lock(&g_mu);
    switch (option) {
        case CURLOPT_RANGE: {
            const char* r = va_arg(ap, const char*);
            snprintf(g_pending_range, sizeof g_pending_range, "%s", r ? r : "");
            break;
        }
        case CURLOPT_WRITEFUNCTION: g_wf = va_arg(ap, curl_write_callback); break;
        case CURLOPT_WRITEDATA: g_wd = va_arg(ap, void*); break;
        default: break; /* 其余选项参数不读取：可变实参无需清理 */
    }
    pthread_mutex_unlock(&g_mu);
    va_end(ap);
    return CURLE_OK;
}

CURLcode mock_easy_perform(CURL* handle) {
    (void)handle;
    pthread_mutex_lock(&g_mu);
    int n = ++g_perform_count;
    if (n <= (int)(sizeof g_range / sizeof g_range[0]))
        snprintf(g_range[n - 1], sizeof g_range[0], "%s", g_pending_range);
    curl_write_callback wf = g_wf;
    void* wd = g_wd;
    pthread_cond_broadcast(&g_cv);
    pthread_mutex_unlock(&g_mu);

    if (n == 1) {
        if (g_scenario == SCEN_CONTROL) return CURLE_OK; /* 对照：真 EOF */
        if (!mock_wait_jump(5000)) return CURLE_OK;      /* 兜底：跳变未发生 */
        return g_scenario == SCEN_STALE_ERROR ? CURLE_COULDNT_CONNECT : CURLE_OK;
    }
    /* 重试 attempt：经真实 write_cb 把数据写入滑动缓冲（证明重启落在新偏移） */
    if (wf && wd) {
        static char data[4096];
        memset(data, 0xA5, sizeof data);
        wf(data, 1, sizeof data, wd);
    }
    return CURLE_WRITE_ERROR; /* 背压式收束：不再置 eof/error */
}

/* typecheck-gcc.h 把 curl_easy_setopt 定义成函数式宏，须先 undef 再接管 */
#undef curl_easy_setopt
#define curl_easy_setopt  mock_easy_setopt
#define curl_easy_perform mock_easy_perform
#include FTP_BACKEND_SRC

/* ================= 测试骨架（在真实类型可见后定义） ================= */

static FtpBackendFile* g_f; /* 被测对象（mock 等 dl_restart 用） */

static bool mock_wait_jump(int ms) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += ms / 1000;
    ts.tv_nsec += (long)(ms % 1000) * 1000000L;
    if (ts.tv_nsec >= 1000000000L) {
        ts.tv_sec++;
        ts.tv_nsec -= 1000000000L;
    }
    bool jumped = false;
    pthread_mutex_lock(&g_f->f_lock);
    while (!g_f->dl_restart) {
        if (pthread_cond_timedwait(&g_f->dl_cond, &g_f->f_lock, &ts) == ETIMEDOUT) break;
    }
    jumped = g_f->dl_restart;
    pthread_mutex_unlock(&g_f->f_lock);
    return jumped;
}

static int g_pass = 0;
static int g_fail = 0;
static void ck(bool ok, const char* name) {
    printf("%s %s\n", ok ? "PASS" : "FAIL", name);
    if (ok)
        g_pass++;
    else
        g_fail++;
}

static void reset_mock(int scenario) {
    pthread_mutex_lock(&g_mu);
    g_scenario = scenario;
    g_perform_count = 0;
    g_pending_range[0] = '\0';
    memset(g_range, 0, sizeof g_range);
    g_wf = NULL;
    g_wd = NULL;
    pthread_mutex_unlock(&g_mu);
}

static bool wait_perform(int n, int ms) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += ms / 1000;
    ts.tv_nsec += (long)(ms % 1000) * 1000000L;
    if (ts.tv_nsec >= 1000000000L) {
        ts.tv_sec++;
        ts.tv_nsec -= 1000000000L;
    }
    bool ok = false;
    pthread_mutex_lock(&g_mu);
    while (g_perform_count < n) {
        if (pthread_cond_timedwait(&g_cv, &g_mu, &ts) == ETIMEDOUT) break;
    }
    ok = g_perform_count >= n;
    pthread_mutex_unlock(&g_mu);
    return ok;
}

static void range_of(int idx, char* out, size_t sz) {
    pthread_mutex_lock(&g_mu);
    snprintf(out, sz, "%s",
             (idx >= 0 && idx < (int)(sizeof g_range / sizeof g_range[0])) ? g_range[idx] : "");
    pthread_mutex_unlock(&g_mu);
}

static void setup_file(FtpBackendFile* f, FtpBackend* bk, off_t start_off) {
    memset(f, 0, sizeof *f);
    memset(bk, 0, sizeof *bk);
    pthread_mutex_init(&bk->lock, NULL);
    f->bk = bk;
    f->tmp_fd = -1;
    f->file_size = 1u << 20;
    f->read_curl = (CURL*)&bk->mux; /* 非 NULL 即可：perform/setopt 已 mock */
    pthread_mutex_init(&f->f_lock, NULL);
    pthread_cond_init(&f->dl_cond, NULL);
    f->rbuf_cap = FTP_RBUF_MIN;
    f->rbuf = malloc(f->rbuf_cap);
    f->rbuf_off = f->rbuf_base = start_off;
    g_f = f;
}

static void teardown_file(FtpBackendFile* f, uint64_t h) {
    if (h) ftp_handle_free(h);
    pthread_mutex_lock(&f->f_lock);
    f->dl_stop = true;
    pthread_cond_broadcast(&f->dl_cond);
    pthread_mutex_unlock(&f->f_lock);
    pthread_join(f->dl_tid, NULL);
    free(f->rbuf);
    pthread_cond_destroy(&f->dl_cond);
    pthread_mutex_destroy(&f->f_lock);
    pthread_mutex_destroy(&f->bk->lock);
    g_f = NULL;
}

struct ReaderArg {
    uint64_t h;
    off_t off;
    size_t size;
    char* buf;
    int rc;
    size_t got;
};

static void* reader_thread(void* arg) {
    struct ReaderArg* ra = arg;
    ra->rc = ftp_backend_read(ra->h, ra->buf, ra->size, ra->off, &ra->got);
    return NULL;
}

/* 竞态场景：旧偏移 942276 的下载在途，read 跳到 31128。
   陈旧结果被采纳与否取决于 perform 返回后「下载线程复位缓冲」与「read 醒来
   复查」谁先拿到 f_lock（真实竞态），故多轮重复并以并发读者放大窗口：
   修复后每轮都必须干净，旧实现在有限轮次内必然出现假 EOF/伪 -EIO。 */
#define OLD_OFF    942276
#define NEW_OFF    31128
#define CASE_ITERS 200
/* 同一新偏移的并发读者数：陈旧结果被采纳时，广播唤醒的多个读者中只要有一个
   先于下载线程下一轮迭代拿到 f_lock，就会看到陈旧 EOF 并静默返回 0 —— 用并发
   放大这一窗口，使旧实现在有限轮次内必然暴露（单读者时窗口过窄）。 */
#define CASE_READERS 6

static bool one_stale_round(int scenario, bool* out_range_ok, bool* out_stale_clear,
                            const char** fail_what) {
    static FtpBackendFile f;
    static FtpBackend bk;
    static char buf[CASE_READERS][4096];
    static struct ReaderArg ra[CASE_READERS];
    static pthread_t rt[CASE_READERS];
    reset_mock(scenario);
    setup_file(&f, &bk, OLD_OFF);
    uint64_t h = ftp_handle_alloc(&f);
    if (!h) {
        *fail_what = "句柄分配失败";
        return false;
    }
    pthread_create(&f.dl_tid, NULL, ftp_dl_thread, &f);
    if (!wait_perform(1, 3000)) {
        *fail_what = "在途下载未进入 perform";
        teardown_file(&f, h);
        return false;
    }
    char r0[64], want0[64];
    range_of(0, r0, sizeof r0);
    snprintf(want0, sizeof want0, "%d-", OLD_OFF);
    if (strcmp(r0, want0) != 0) {
        *fail_what = "首次 perform 未使用旧偏移（场景不成立）";
        teardown_file(&f, h);
        return false;
    }

    /* read 随机跳变：真实 read 路径置 dl_restart；mock 随后让旧传输返回 */
    for (int i = 0; i < CASE_READERS; i++) {
        memset(buf[i], 0, sizeof buf[i]);
        ra[i] = (struct ReaderArg){.h = h, .off = NEW_OFF, .size = sizeof buf[i], .buf = buf[i]};
        pthread_create(&rt[i], NULL, reader_thread, &ra[i]);
    }
    for (int i = 0; i < CASE_READERS; i++) pthread_join(rt[i], NULL);

    bool readers_ok = true, data_ok = true;
    for (int i = 0; i < CASE_READERS; i++) {
        if (ra[i].rc != 0 || ra[i].got != sizeof buf[i]) readers_ok = false;
        for (size_t k = 0; k < sizeof buf[i]; k++)
            if ((unsigned char)buf[i][k] != 0xA5) data_ok = false;
    }

    char r1[64], want1[64];
    range_of(1, r1, sizeof r1);
    snprintf(want1, sizeof want1, "%d-", NEW_OFF);
    *out_range_ok = (strcmp(r1, want1) == 0);
    pthread_mutex_lock(&f.f_lock);
    *out_stale_clear = !f.rbuf_eof && !f.dl_error;
    pthread_mutex_unlock(&f.f_lock);
    teardown_file(&f, h);

    if (!readers_ok)
        *fail_what = "read 未取满请求字节（假 EOF/伪 -EIO）";
    else if (!data_ok)
        *fail_what = "read 数据非新偏移重下内容";
    else if (!*out_range_ok)
        *fail_what = "重试下载未落在新偏移";
    else if (!*out_stale_clear)
        *fail_what = "陈旧结果污染缓冲状态";
    return readers_ok && data_ok && *out_range_ok && *out_stale_clear;
}

static void run_stale_result_case(int scenario, const char* title) {
    int bad = 0;
    const char* first_fail = "";
    for (int i = 0; i < CASE_ITERS && bad == 0; i++) {
        bool range_ok = false, stale_clear = false;
        const char* what = "";
        if (!one_stale_round(scenario, &range_ok, &stale_clear, &what)) {
            bad++;
            first_fail = what;
        }
    }
    /* 单条汇总断言：40 轮全部干净才算通过（失败信息给出首轮原因） */
    ck(bad == 0, bad ? title : title);
    if (bad) printf("     首轮失败原因: %s\n", first_fail);
}

/* 对照：无跳变时真实 EOF 必须仍被采纳 */
static void run_control_eof_case(void) {
    static FtpBackendFile f;
    static FtpBackend bk;
    reset_mock(SCEN_CONTROL);
    setup_file(&f, &bk, 0);
    uint64_t h = ftp_handle_alloc(&f);
    pthread_create(&f.dl_tid, NULL, ftp_dl_thread, &f);
    ck(wait_perform(1, 3000), "对照：下载线程进入 perform");
    bool eof = false;
    for (int i = 0; i < 300 && !eof; i++) {
        pthread_mutex_lock(&f.f_lock);
        eof = f.rbuf_eof;
        pthread_mutex_unlock(&f.f_lock);
        if (!eof) usleep(10000);
    }
    ck(eof, "对照：无跳变时真实 EOF 仍被采纳（未过度丢弃）");
    teardown_file(&f, h);
}

int main(void) {
    printf("── A. 在途 EOF 撞上随机跳变（%d 轮）──\n", CASE_ITERS);
    run_stale_result_case(SCEN_STALE_EOF, "A 陈旧 EOF 未污染新缓冲（全部轮次干净）");
    printf("── B. 在途真错误撞上随机跳变（%d 轮）──\n", CASE_ITERS);
    run_stale_result_case(SCEN_STALE_ERROR, "B 陈旧错误未污染新缓冲（全部轮次干净）");
    printf("── C. 无跳变对照（真 EOF 仍生效）──\n");
    run_control_eof_case();
    printf("SUMMARY pass=%d fail=%d\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
