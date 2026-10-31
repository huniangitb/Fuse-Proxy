/* SPDX-License-Identifier: GPL-3.0-or-later */
/* 版权所有 (C) 2026 huniangitb <3361107168@qq.com> */
/*
 * tests/fixtures/ipc_binding.c — injector IPC 请求身份绑定（R8）直编用例
 * ====================================================================
 *
 * 被测对象是**实际源码** src/injector/ipc_server.c（另直编 inject_target.c /
 * uid_map.c / fast_pid.c / nsp_util.c）。只把「配置查表 / 挂载·还原派发 /
 * 系统包表」做成桩——鉴权与派发决策本身全部走真实实现，映射落盘也是真实的
 * uid_map_upsert。
 *
 * 进程模型（无任何凭据包装）：
 *   用例进程以 uid 10123 运行（驱动侧 unshare --user --map-user=10123），
 *   fork+exec 出 argv[0]=<pkg> 的「假应用」子进程；由子进程写请求、父进程调
 *   handle_ipc_client_readable。于是 SO_PEERCRED 的 pid/uid 与 /proc/<pid> 的
 *   uid/cmdline 都是内核给出的真实值。两个必要条件：
 *   - 走真实 connect(2)/accept(2)：socketpair 的 SO_PEERCRED 报的是**创建**
 *     该 socket 对的进程凭据，不是写请求那一端的；
 *   - 驱动在 pid ns 内运行（--pid --fork --mount-proc）：宿主 pid 可超过
 *     Android 的 1048576 上限，会被 ipc_server 既有的 pid 输入校验直接拒绝。
 *
 * 驱动（tests/test_inject_method.py）把 include/ 复制到临时目录后定向替换两个
 * 平台根常量：NSP_CONFIG_DIR → 私有 conf（uid.map 落盘断言不碰系统配置根）、
 * NSP_ANDROID_EMULATED_ROOT → 私有目录（目标分支的 access() 门在普通主机上
 * 不存在）。除此之外被测源码零改动。
 *
 * 用例矩阵（每条独立 socketpair；断言 ACK + uid.map + 派发计数 + 被动模式）：
 *   P1 合法目标应用自身请求              → OK，uid.map 更新，无还原派发
 *   P2 合法非目标应用自身请求（v2）      → OK，uid.map 更新 + 还原派发（不误伤）
 *   N1 同 uid 但自报 pid=1（不是对端）   → ERR，uid.map 原样，零派发，不切被动
 *   N2 包名与 /proc/<pid>/cmdline 不符   → ERR，同上（伪造非目标包）
 *   N3 伪造**目标**包名（cmdline 是别的应用）→ ERR，uid.map 原样，不得标注入
 *   N4 非 root 对端发 REPORT（companion 专用通道）→ ERR，零派发
 *
 * 判别性：旧实现（IPC_SERVER_SRC 指向 HEAD 副本）对 N1–N4 全部 ACK，并按伪
 * pid/pkg 写 uid.map、派发还原 → 本用例必失败。
 *
 * 退出码：0 全部通过；1 存在失败。
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include "common.h"
#include "config_parser.h"
#include "injector.h"
#include "inject_target.h"
#include "ipc_server.h"
#include "ns_utils.h" /* NSP_READINESS_QUIET：后台通道的负值哨兵 */
#include "nsp_log.h"
#include "nsp_util.h"
#include "uid_map.h"

/* ================= 被链接源码所需的全局 ================= */

AppConfig g_global_cfg; /* 非全局注入：判定完全由应用段决定 */
AppConfig** g_app_cfgs = NULL;
int g_app_cfg_count = 0;
int g_active_users[MAX_USERS];
int g_active_user_count = 0;
InjectMethod g_inject_method = INJECT_METHOD_V2; /* 走 v2：非目标 → 还原派发 */
volatile sig_atomic_t g_passive_mode = 0;

/* ================= 配置查表桩（只有应用段，无类别/通配段） ================= */

static AppConfig g_cfg_target = {.pkg_name = "com.real.target", .user_id = -1, .inject_enable = true};
static AppConfig g_cfg_other = {.pkg_name = "com.other.app", .user_id = -1, .inject_enable = false};
static AppConfig g_cfg_forged = {
    .pkg_name = "com.forged.non_target", .user_id = -1, .inject_enable = false};

void config_lock_read(void) {}
void config_unlock_read(void) {}
void config_lock_write(void) {}
void config_unlock_write(void) {}

AppConfig* find_app_cfg_locked(const char* pkg, int user_id) {
    (void)user_id;
    char base[128];
    snprintf(base, sizeof base, "%s", pkg);
    char* colon = strchr(base, ':');
    if (colon) *colon = '\0';
    if (strcmp(base, "com.real.target") == 0) return &g_cfg_target;
    if (strcmp(base, "com.other.app") == 0) return &g_cfg_other;
    if (strcmp(base, "com.forged.non_target") == 0) return &g_cfg_forged;
    return NULL;
}
AppConfig* find_category_cfg_locked(bool is_system_app, int user_id) {
    (void)is_system_app;
    (void)user_id;
    return NULL;
}
bool category_has_rules_locked(bool is_system_app, int user_id) {
    (void)is_system_app;
    (void)user_id;
    return false;
}
bool has_wildcard_enabled_locked(int user_id) {
    (void)user_id;
    return false;
}

/* ================= 系统包表桩（用例不依赖 pm 缓存） ================= */

void sys_pkg_init(bool allow) { (void)allow; }
void sys_pkg_cleanup(void) {}
bool sys_pkg_is_system(const char* pkg) {
    (void)pkg;
    return false;
}

/* ================= 挂载 / 还原派发桩：只记账 ================= */

static _Atomic int g_restore_calls;
static _Atomic int g_mount_calls;
/* A1 用例：同步挂载桩 + 放行门（见 run_ack_order_case 的判别设计） */
static _Atomic int g_sync_mount_calls;
static char g_ack_gate[PATH_MAX];
static _Atomic int g_last_restore_pid;
static _Atomic int g_last_restore_uid;
static char g_last_restore_pkg[256];

const char* get_active_mnt_src(void) { return "/mock/fuse"; }
/* 配置热对账（audit_running_apps）新增依赖的桩：本用例不触达这两条路径 */
void invalidate_app_mount_cache(int pid) { (void)pid; }
bool app_has_active_rules(const char* pkg, uid_t uid) {
    (void)pkg;
    (void)uid;
    return true;
}
bool is_project_fuse_cached(int pid, const char* target_path) {
    (void)pid;
    (void)target_path;
    return false;
}
int perform_app_mount(const char* pkg, int pid, uid_t uid, const char* mnt_src,
                      const char* trigger) {
    (void)pkg;
    (void)pid;
    (void)uid;
    (void)mnt_src;
    (void)trigger;
    atomic_fetch_add(&g_mount_calls, 1);
    return 0;
}

/* 同步挂载桩（ACK 时序 / 就绪预算用例专用）：可被放行门阻塞，从而让"ACK 必须
   晚于挂载完成"这一契约可被确定性观测；返回值可被用例置为非 0（模拟"视图尚未
   就绪"），用于验证 DEFER 分支。未设门时立即返回，不影响其它用例。 */
static _Atomic int g_sync_mount_readiness = -1; /* 最近一次收到的就绪预算（ms） */
static _Atomic int g_sync_mount_result = 0;     /* 桩的返回值（0=成功） */

int perform_app_mount_sync(const char* pkg, int pid, uid_t uid, const char* mnt_src,
                           int readiness_ms) {
    (void)pkg;
    (void)pid;
    (void)uid;
    (void)mnt_src;
    atomic_fetch_add(&g_sync_mount_calls, 1);
    atomic_store(&g_sync_mount_readiness, readiness_ms);
    for (int i = 0; i < 200; i++) {
        if (g_ack_gate[0] == '\0' || access(g_ack_gate, F_OK) == 0) break;
        usleep(10 * 1000);
    }
    return atomic_load(&g_sync_mount_result);
}
/* A3 用例：还原桩的"放行门"（门未创建时桩一直等待，模拟还原较慢/注入器繁忙） */
static char g_restore_gate[PATH_MAX];

int perform_app_restore(const char* pkg, int pid, uid_t uid) {
    snprintf(g_last_restore_pkg, sizeof g_last_restore_pkg, "%s", pkg);
    atomic_store(&g_last_restore_pid, pid);
    atomic_store(&g_last_restore_uid, (int)uid);
    atomic_fetch_add(&g_restore_calls, 1);
    for (int i = 0; i < 300; i++) {
        if (g_restore_gate[0] == '\0' || access(g_restore_gate, F_OK) == 0) break;
        usleep(10 * 1000);
    }
    return 0;
}
void print_active_rules(const char* pkg, int pid, uid_t uid, const char* trigger_source) {
    (void)pkg;
    (void)pid;
    (void)uid;
    (void)trigger_source;
}
/* 挂载失败重试队列：由 injector.c 提供实现，本直编组只记账（不重试） */
static _Atomic int g_retry_calls;
void schedule_retry_mount(const char* pkg, int pid) {
    (void)pkg;
    (void)pid;
    atomic_fetch_add(&g_retry_calls, 1);
}
/* 挂载成功清账（真实现随 injector.c 编入，本直编组不链接它） */
void retry_mount_succeeded(int pid) { (void)pid; }

/* ns_* 桩：inject_target.c 的 cleanup_app_mounts 引用（本用例不触达） */
int ns_bind_mount(int pid, const char* source, const char* target) {
    (void)pid;
    (void)source;
    (void)target;
    return -1;
}
int ns_bind_mount_cross(int pid, const char* source, const char* target) {
    (void)pid;
    (void)source;
    (void)target;
    return -1;
}
int ns_find_family_root(int pid, uid_t app_uid, char* out, size_t outsz) {
    (void)pid;
    (void)app_uid;
    if (out && outsz) out[0] = '\0';
    return -1;
}
int ns_is_mounted(int pid, const char* target_mount, const char* match_fs_name) {
    (void)pid;
    (void)target_mount;
    (void)match_fs_name;
    return 0;
}
int ns_umount_recursive(int pid, const char* target) {
    (void)pid;
    (void)target;
    return 0;
}

/* 日志桩：本用例不校验日志，只需符号 */
void log_internal(LogLevel level, const char* format, ...) {
    (void)level;
    (void)format;
}
void log_batch_begin(void) {}
void log_batch_end(void) {}

/* ================= 用例框架 ================= */

static int g_pass;
static int g_fail;

static void report(bool okv, const char* label, const char* detail) {
    if (okv) {
        g_pass++;
        printf("  PASS %s\n", label);
    } else {
        g_fail++;
        printf("  FAIL %s — %s\n", label, detail);
    }
}

static bool read_text(const char* path, char* out, size_t outsz) {
    FILE* fp = fopen(path, "re");
    if (!fp) return false;
    size_t n = fread(out, 1, outsz - 1, fp);
    out[n] = '\0';
    fclose(fp);
    return true;
}

static bool write_text(const char* path, const char* text) {
    FILE* fp = fopen(path, "we");
    if (!fp) return false;
    fputs(text, fp);
    fclose(fp);
    return true;
}

static void seed_uid_map(void) { write_text(CONFIG_DIR "/uid.map", "10123 com.stale.old\n"); }

typedef struct {
    const char* label;
    const char* child_pkg; /* argv[0] → /proc/<pid>/cmdline 首段 */
    const char* verb;      /* REQ / REPORT */
    const char* req_pkg;
    int pid_sel;           /* 0=子进程自身, 1=init(1), 2=父进程 */
    bool expect_ok;
    bool expect_restore;
    bool expect_injected;  /* 目标分支是否应 mark_injected（/storage 缺失时不可观测） */
    const char* expect_map; /* NULL = 必须与播种内容逐字相同 */
} Case;

/* 子进程：argv[0]=pkg，argv[1]="app"，argv[2]=监听 socket 路径，argv[3]=请求，
   argv[4]=回传 fd。
   必须走真实 connect/accept（而不是 socketpair）：SO_PEERCRED 对 socketpair
   报的是**创建该 socket 对的进程**凭据，只有 connect(2) 建立的连接才携带
   连接方自身的 pid/uid。 */
static int app_main(int argc, char** argv) {
    if (argc < 5) return 90;
    const char* path = argv[2];
    const char* req = argv[3];
    int rep_fd = atoi(argv[4]);
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return 91;
    struct sockaddr_un addr = {.sun_family = AF_UNIX};
    snprintf(addr.sun_path, sizeof addr.sun_path, "%s", path);
    if (connect(fd, (struct sockaddr*)&addr, sizeof addr) != 0) return 92;
    ssize_t w = write(fd, req, strlen(req));
    (void)w;
    char ack[32] = {0};
    ssize_t r = read(fd, ack, sizeof ack - 1);
    if (r < 0) r = 0;
    ack[r] = '\0';
    w = write(rep_fd, ack, strlen(ack));
    (void)w;
    close(fd);
    close(rep_fd);
    /* 保持存活到父进程断言完成：还原派发线程会先 kill(pid,0) 判活，
       进程已死就跳过派发（会让 P2 的判别失去意义） */
    sleep(5);
    return 0;
}

static int run_case(const Case* c) {
    char detail[1600];
    seed_uid_map();
    char map_before[512] = {0};
    read_text(CONFIG_DIR "/uid.map", map_before, sizeof map_before);
    g_passive_mode = 0;
    /* 派发计数按用例归零（上一条用例的异步还原线程可能已跑完） */
    atomic_store(&g_restore_calls, 0);
    atomic_store(&g_mount_calls, 0);
    atomic_store(&g_last_restore_pid, 0);
    atomic_store(&g_last_restore_uid, 0);
    g_last_restore_pkg[0] = 0;

    /* 每条用例一个监听 socket：连接方（假应用子进程）的 SO_PEERCRED 才是它的
       真实 pid/uid——socketpair 报的是创建该 socket 对的进程凭据，不能用。 */
    char sock_path[108];
    /* 私有配置根下（驱动已把 CONFIG_DIR 指向本次运行的临时目录）：并发跑套件时
       不与其他实例的 /tmp 固定名冲突 */
    snprintf(sock_path, sizeof sock_path, "%s/ipc.sock", CONFIG_DIR);
    unlink(sock_path);
    int lfd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un laddr = {.sun_family = AF_UNIX};
    snprintf(laddr.sun_path, sizeof laddr.sun_path, "%s", sock_path);
    int rp[2] = {-1, -1};
    if (lfd < 0 || bind(lfd, (struct sockaddr*)&laddr, sizeof laddr) != 0 ||
        listen(lfd, 4) != 0 || pipe(rp) != 0) {
        snprintf(detail, sizeof detail, "监听 socket/pipe 失败: %s", strerror(errno));
        report(false, c->label, detail);
        if (lfd >= 0) close(lfd);
        return -1;
    }
    pid_t child = fork();
    if (child < 0) {
        snprintf(detail, sizeof detail, "fork 失败: %s", strerror(errno));
        report(false, c->label, detail);
        close(lfd);
        return -1;
    }
    if (child == 0) {
        close(lfd);
        close(rp[0]);
        char rp_s[16], req[512];
        snprintf(rp_s, sizeof rp_s, "%d", rp[1]);
        int target_pid = (c->pid_sel == 0) ? (int)getpid()
                         : (c->pid_sel == 1) ? 1
                                             : (int)getppid();
        int target_uid = (int)getuid();
        snprintf(req, sizeof req, "%s %s %d %d", c->verb, c->req_pkg, target_pid, target_uid);
        char self[PATH_MAX];
        ssize_t n = readlink("/proc/self/exe", self, sizeof self - 1);
        if (n <= 0) _exit(98);
        self[n] = '\0';
        execl(self, c->child_pkg, "app", sock_path, req, rp_s, (char*)NULL);
        _exit(99);
    }
    close(rp[1]);
    int cfd = accept(lfd, NULL, NULL);
    if (cfd < 0) {
        snprintf(detail, sizeof detail, "accept 失败: %s", strerror(errno));
        report(false, c->label, detail);
        close(lfd);
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
        return -1;
    }
    close(lfd);
    unlink(sock_path);
    /* handle_ipc_client_readable 内部会 close(cfd)：此处不得重复 close */
    handle_ipc_client_readable(cfd);
    char ack[32] = {0};
    ssize_t an = read(rp[0], ack, sizeof ack - 1);
    if (an > 0) ack[an] = '\0';
    close(rp[0]);

    /* 派发是异步线程（ipc_restore_thread）：等它跑到桩函数 */
    if (c->expect_restore) {
        for (int i = 0; i < 100 && atomic_load(&g_restore_calls) == 0; i++) usleep(10 * 1000);
    } else {
        usleep(150 * 1000);
    }

    char map_after[512] = {0};
    read_text(CONFIG_DIR "/uid.map", map_after, sizeof map_after);

    bool ok_ack = c->expect_ok ? (strcmp(ack, "OK") == 0) : (strcmp(ack, "ERR") == 0);
    bool ok_restore = (atomic_load(&g_restore_calls) > 0) == c->expect_restore;
    bool ok_map = c->expect_map ? (strcmp(map_after, c->expect_map) == 0)
                                : (strcmp(map_after, map_before) == 0);
    bool ok_injected = c->expect_injected ? is_injected(child) : !is_injected(child);
    bool ok_passive = c->expect_ok ? (g_passive_mode != 0) : (g_passive_mode == 0);
    bool ok_pid = true;
    if (c->expect_restore) {
        ok_pid = (atomic_load(&g_last_restore_pid) == (int)child) &&
                 (atomic_load(&g_last_restore_uid) == (int)getuid()) &&
                 (strcmp(g_last_restore_pkg, c->req_pkg) == 0);
    }

    snprintf(detail, sizeof detail,
             "ack=%s(期望%s) restore=%d(期望%d) map=[%s](期望[%s]) injected=%d passive=%d "
             "last_restore=%d/%u/%s",
             ack[0] ? ack : "(空)", c->expect_ok ? "OK" : "ERR", atomic_load(&g_restore_calls),
             c->expect_restore, map_after, c->expect_map ? c->expect_map : map_before,
             (int)is_injected(child), (int)g_passive_mode, atomic_load(&g_last_restore_pid),
             (unsigned)atomic_load(&g_last_restore_uid), g_last_restore_pkg);
    report(ok_ack && ok_restore && ok_map && ok_injected && ok_passive && ok_pid, c->label,
           detail);

    kill(child, SIGKILL);
    waitpid(child, NULL, 0);
    return 0;
}

/* A1：ACK 必须晚于"视图就绪"（v1 的挂载完成）。
 *
 * 判别设计：把同步挂载桩做成"等放行门"，于是挂载是否完成由测试完全掌控。
 *   - 新实现：挂载线程阻塞在桩里 → 放行门创建前客户端读不到 ACK；
 *   - 旧实现：ACK 在派发挂载线程之前就已写出 → 放行门创建前客户端必然先收到
 *     ACK（且同步桩从未被调用，计数为 0）。
 * 两边都不依赖时序竞速，故可稳定判别。 */
static int run_ack_order_case(void) {
    char detail[1200];
    seed_uid_map();
    g_passive_mode = 0;
    atomic_store(&g_sync_mount_calls, 0);
    atomic_store(&g_mount_calls, 0);
    g_inject_method = INJECT_METHOD_V1; /* 只有 v1 才逐应用挂载 */

    snprintf(g_ack_gate, sizeof g_ack_gate, "%s/ack_gate", CONFIG_DIR);
    unlink(g_ack_gate);

    char sock_path[108];
    snprintf(sock_path, sizeof sock_path, "%s/ipc_ack.sock", CONFIG_DIR);
    unlink(sock_path);
    int lfd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un laddr = {.sun_family = AF_UNIX};
    snprintf(laddr.sun_path, sizeof laddr.sun_path, "%s", sock_path);
    int rp[2] = {-1, -1};
    bool ok = true;
    pid_t child = -1;
    if (lfd < 0 || bind(lfd, (struct sockaddr*)&laddr, sizeof laddr) != 0 || listen(lfd, 4) != 0 ||
        pipe(rp) != 0) {
        snprintf(detail, sizeof detail, "监听 socket/pipe 失败: %s", strerror(errno));
        report(false, "A1 挂载完成前不得 ACK", detail);
        if (lfd >= 0) close(lfd);
        g_inject_method = INJECT_METHOD_V2;
        return -1;
    }
    child = fork();
    if (child < 0) {
        snprintf(detail, sizeof detail, "fork 失败: %s", strerror(errno));
        report(false, "A1 挂载完成前不得 ACK", detail);
        close(lfd);
        g_inject_method = INJECT_METHOD_V2;
        return -1;
    }
    if (child == 0) {
        close(lfd);
        close(rp[0]);
        char rp_s[16], req[512];
        snprintf(rp_s, sizeof rp_s, "%d", rp[1]);
        snprintf(req, sizeof req, "REQ com.real.target %d %d", (int)getpid(), (int)getuid());
        char self[PATH_MAX];
        ssize_t n = readlink("/proc/self/exe", self, sizeof self - 1);
        if (n <= 0) _exit(98);
        self[n] = '\0';
        execl(self, "com.real.target", "app", sock_path, req, rp_s, (char*)NULL);
        _exit(99);
    }
    close(rp[1]);
    int cfd = accept(lfd, NULL, NULL);
    if (cfd < 0) {
        snprintf(detail, sizeof detail, "accept 失败: %s", strerror(errno));
        report(false, "A1 挂载完成前不得 ACK", detail);
        close(lfd);
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
        g_inject_method = INJECT_METHOD_V2;
        return -1;
    }
    close(lfd);
    unlink(sock_path);
    /* 旧实现内部会 close(cfd)；新实现把它交给挂载线程，同样由线程 close */
    handle_ipc_client_readable(cfd);

    /* 放行门前：不得收到 ACK（新实现挂载未完成；旧实现此刻已应答） */
    struct pollfd pfd = {.fd = rp[0], .events = POLLIN};
    bool early_ack = (poll(&pfd, 1, 300) > 0);

    /* 放行挂载：桩返回后线程才发 ACK */
    int gfd = open(g_ack_gate, O_CREAT | O_WRONLY, 0600);
    if (gfd >= 0) close(gfd);

    char ack[32] = {0};
    pfd.revents = 0;
    if (poll(&pfd, 1, 3000) > 0) {
        ssize_t an = read(rp[0], ack, sizeof ack - 1);
        if (an > 0) ack[an] = '\0';
    }
    close(rp[0]);
    unlink(g_ack_gate);
    g_ack_gate[0] = '\0';

    int sync_calls = atomic_load(&g_sync_mount_calls);
    int readiness = atomic_load(&g_sync_mount_readiness);
    bool ok_ack = (strcmp(ack, "OK") == 0);
    /* REQ（应用直连的历史通道）仍是"就地挂载 + 挂载完成后才 ACK"，但就绪预算
       改成 IPC_MOUNT_READINESS_MS（旧值 1000ms 直接落在应用主线程上，冷启动可
       感知；新值只覆盖抖动，等不到就 fail-open 交后台重试）。 */
    ok = ok_ack && !early_ack && sync_calls == 1 && readiness == IPC_MOUNT_READINESS_MS;
    snprintf(detail, sizeof detail,
             "early_ack=%d(期望0) ack=%s(期望OK) sync_mount_calls=%d(期望1) "
             "readiness=%d(期望%d)",
             (int)early_ack, ack[0] ? ack : "(空)", sync_calls, readiness,
             IPC_MOUNT_READINESS_MS);
    report(ok, "A1 挂载完成前不得 ACK（ACK 后才放行 specialize）", detail);

    kill(child, SIGKILL);
    waitpid(child, NULL, 0);
    g_inject_method = INJECT_METHOD_V2;
    return 0;
}

/* A2：v1 挂载通道决策矩阵（两段式补挂载的核心契约）。
 *
 * 真机上的 REPORT/POST 只允许 root companion 对端，普通单测进程无法伪造该
 * 凭据，故这里直接钉住决策纯函数 ipc_plan_channel / ipc_channel_readiness：
 * 哪条通道该挂、等多久。判别点：
 *   - proto>=2 的 pre 探测必须是 IPC_CHAN_DEFER 且预算 0——**pre 阶段绝不能挂载**：
 *     此刻应用还在 zygote 的挂载命名空间里（部分 ROM 该 ns 里就有 /storage/emulated），
 *     在这里挂载会把项目 FUSE 装进 zygote ns，之后 fork 的每个应用（含非目标）
 *     都继承它，且 cleanup 只会在应用自己的 ns 里卸载，这份挂载没人能清；
 *   - POST 必须是 IPC_CHAN_POST（唯一的挂载时机）；
 *   - 旧模块（无 proto）与 REQ 必须是 IPC_CHAN_LEGACY（就地挂载，语义不变）；
 *   - 预算必须短：这段等待发生在应用主线程里，旧值 1800/1000ms 在"视图迟迟不出现"
 *     的设备上等于每次冷启动固定变慢。
 *   - **POST 预算必须远小于 legacy**（IPC_MOUNT_INLINE_MS=20 vs 250）：真机 322 次
 *     挂载里 202 次 >100ms、59 次 >250ms，而 vold 把 /storage/emulated 装配进应用 ns
 *     的实测窗口是 ~135–150ms——POST 阶段视图通常还没出现，等满 250ms 只是替 vold
 *     数秒表，18% 的请求被它打爆且应用仍然拿到原生视图。POST 未就绪就该 fail-open
 *     交后台快重试（20ms 起），而不是把应用冻在 specialize 上。 */
static void run_plan_readiness_cases(void) {
    struct PlanCase {
        const char* label;
        bool is_post;
        bool is_report;
        int proto;
        IpcChannel want_chan;
        int want_ms;
    } cs[] = {
        {"A2 pre(REPORT,proto=2) → DEFER 通道（只裁决、不挂载，预算 0）", false, true, 2,
         IPC_CHAN_DEFER, 0},
        {"A2 POST(proto=2) → POST 通道（唯一挂载时机，预算 20ms 不可感知）", true, false, 2,
         IPC_CHAN_POST, IPC_MOUNT_INLINE_MS},
        {"A2 旧模块(REPORT,无proto) → legacy 通道（就地挂载）", false, true, 0, IPC_CHAN_LEGACY,
         IPC_MOUNT_READINESS_MS},
        {"A2 REQ(应用直连,proto=2) → legacy 通道（历史行为不变）", false, false, 2,
         IPC_CHAN_LEGACY, IPC_MOUNT_READINESS_MS},
        {"A2 POST(无proto) → POST 通道", true, false, 0, IPC_CHAN_POST, IPC_MOUNT_INLINE_MS},
    };
    char detail[400];
    for (size_t i = 0; i < sizeof cs / sizeof cs[0]; i++) {
        IpcChannel ch = ipc_plan_channel(cs[i].is_post, cs[i].is_report, cs[i].proto);
        int ms = ipc_channel_readiness(ch);
        bool ok = (ch == cs[i].want_chan) && (ms == cs[i].want_ms);
        snprintf(detail, sizeof detail, "chan=%d(期望%d) ms=%d(期望%d)", (int)ch,
                 (int)cs[i].want_chan, ms, cs[i].want_ms);
        report(ok, cs[i].label, detail);
    }
    /* 主线程预算必须短：冷启动可感知的量级是几百毫秒以上 */
    report(IPC_MOUNT_READINESS_MS <= 500, "A2 主线程就绪预算 ≤ 500ms（冷启动可感知上限）",
           "预算过大：应用主线程会被拖慢");
    /* POST 通道（有 post 通知可依赖）必须用远小于 legacy 的预算：真机视图 ~140ms
       才出现，等满 legacy 预算等于白等，且 18% 会直接打爆。 */
    report(IPC_MOUNT_INLINE_MS <= 50 && IPC_MOUNT_INLINE_MS < IPC_MOUNT_READINESS_MS,
           "A2 POST 预算 ≤ 50ms 且小于 legacy 预算（不可感知 + fail-open 交后台重试）",
           "POST 预算过大：应用主线程白等且仍拿不到视图");

    /* A2b：v2 非目标还原的时序（事件驱动优先，不靠 10ms 轮询猜时间）。
       新协议 pre 阶段不还原、不轮询——此刻应用 ns 里还没有项目视图（还原只会
       命中「顶层非项目 FUSE→跳过」，旧实现实测要 46–60ms 才落地）；直接回
       DEFER 让模块在 post-specialize 再通知，收到 POST 立刻异步还原并立即 ACK。
       旧模块（无 proto）/ REQ 没有 post 通知可用，退化为「就地派发 + 有界快等」。 */
    struct RestoreCase {
        const char* label;
        bool is_post;
        bool is_report;
        int proto;
        IpcRestorePlan want;
    } rs[] = {
        {"A2b pre(REPORT,proto=2) → 交 post 通知（回 DEFER，不轮询）", false, true, 2,
         IPC_RESTORE_ON_POST},
        {"A2b POST(proto=2) → 立刻异步还原 + 立即放行", true, false, 2, IPC_RESTORE_NOW},
        {"A2b POST(无proto) → 同样立刻还原", true, false, 0, IPC_RESTORE_NOW},
        {"A2b 旧模块(REPORT,无proto) → 就地派发 + 有界快等", false, true, 0,
         IPC_RESTORE_INLINE},
        {"A2b REQ(应用直连) → 就地派发 + 有界快等", false, false, 2, IPC_RESTORE_INLINE},
    };
    for (size_t i = 0; i < sizeof rs / sizeof rs[0]; i++) {
        IpcRestorePlan got = ipc_plan_restore(rs[i].is_post, rs[i].is_report, rs[i].proto);
        char rd[200];
        snprintf(rd, sizeof rd, "plan=%d(期望%d)", (int)got, (int)rs[i].want);
        report(got == rs[i].want, rs[i].label, rd);
    }
}

/* A3：v2 非目标应用还原**不得**把应用冻在 specialize 上（v2 不依赖 zygisk 阻塞）。
 *
 * 判别设计：还原桩挂在"放行门"上（门未创建时桩最长等 3s）。
 *   - 新实现：ACK 与还原解耦（有界快等 IPC_RESTORE_INLINE_MS），门未开也先 ACK；
 *     开门后后台线程跑完（restore_calls ≥ 1）。
 *   - 旧实现：ACK 挂在还原线程末尾 → 门未开时客户端 300ms 内读不到 ACK（必失败）。
 */
static int run_v2_nonblocking_restore_case(void) {
    char detail[800];
    seed_uid_map();
    g_passive_mode = 0;
    atomic_store(&g_restore_calls, 0);
    g_inject_method = INJECT_METHOD_V2;
    char sock_path[108];
    snprintf(sock_path, sizeof sock_path, "%s/ipc2.sock", CONFIG_DIR);
    unlink(sock_path);
    int lfd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un laddr = {.sun_family = AF_UNIX};
    snprintf(laddr.sun_path, sizeof laddr.sun_path, "%s", sock_path);
    int rp[2] = {-1, -1};
    if (lfd < 0 || bind(lfd, (struct sockaddr*)&laddr, sizeof laddr) != 0 ||
        listen(lfd, 4) != 0 || pipe(rp) != 0) {
        snprintf(detail, sizeof detail, "监听 socket/pipe 失败: %s", strerror(errno));
        report(false, "A3 v2 非目标还原不阻塞 ACK（先放行、后台完成）", detail);
        if (lfd >= 0) close(lfd);
        g_inject_method = INJECT_METHOD_V1;
        return -1;
    }
    pid_t child = fork();
    if (child == 0) {
        close(lfd);
        close(rp[0]);
        char rp_s[16], req[512];
        snprintf(rp_s, sizeof rp_s, "%d", rp[1]);
        snprintf(req, sizeof req, "REQ com.other.app %d %d", (int)getpid(), (int)getuid());
        char self[PATH_MAX];
        ssize_t n = readlink("/proc/self/exe", self, sizeof self - 1);
        if (n <= 0) _exit(98);
        self[n] = '\0';
        execl(self, "com.other.app", "app", sock_path, req, rp_s, (char*)NULL);
        _exit(99);
    }
    close(rp[1]);
    int cfd = accept(lfd, NULL, NULL);
    if (cfd < 0) {
        snprintf(detail, sizeof detail, "accept 失败: %s", strerror(errno));
        report(false, "A3 v2 非目标还原不阻塞 ACK（先放行、后台完成）", detail);
        close(lfd);
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
        g_inject_method = INJECT_METHOD_V1;
        return -1;
    }
    close(lfd);
    unlink(sock_path);
    snprintf(g_restore_gate, sizeof g_restore_gate, "%s/restore.gate", CONFIG_DIR);
    unlink(g_restore_gate);
    handle_ipc_client_readable(cfd);
    /* 门未开：ACK 必须在 300ms 内到达（新实现立即放行；旧实现被还原阻塞，读不到） */
    struct pollfd pfd = {.fd = rp[0], .events = POLLIN};
    bool acked_while_blocked = (poll(&pfd, 1, 300) > 0);
    char ack[32] = {0};
    if (acked_while_blocked) {
        ssize_t an = read(rp[0], ack, sizeof ack - 1);
        if (an > 0) ack[an] = '\0';
    }
    /* 开门：后台还原线程继续跑完 */
    int gfd = open(g_restore_gate, O_CREAT | O_WRONLY, 0600);
    if (gfd >= 0) close(gfd);
    bool restored = false;
    for (int i = 0; i < 200; i++) {
        if (atomic_load(&g_restore_calls) > 0) {
            restored = true;
            break;
        }
        usleep(10 * 1000);
    }
    close(rp[0]);
    unlink(g_restore_gate);
    g_restore_gate[0] = '\0';
    bool ok_ack = (strcmp(ack, "OK") == 0);
    snprintf(detail, sizeof detail,
             "acked_while_restore_blocked=%d(期望1) ack=%s(期望OK) restore_after_gate=%d(期望>=1)",
             (int)acked_while_blocked, ack[0] ? ack : "(空)", (int)restored);
    report(acked_while_blocked && ok_ack && restored,
           "A3 v2 非目标还原不阻塞 ACK（先放行、后台完成）", detail);
    kill(child, SIGKILL);
    waitpid(child, NULL, 0);
    g_inject_method = INJECT_METHOD_V1;
    return 0;
}

int main(int argc, char** argv) {
    if (argc >= 2 && strcmp(argv[1], "app") == 0) return app_main(argc, argv);

    printf("IPC 身份绑定用例：uid=%u（期望 >= 10000 才走 uid.map 落盘路径）\n", (unsigned)getuid());
    if (getuid() < NSP_SYSTEM_APP_UID_MIN) {
        printf("FAIL 用例进程 uid 过小：uid.map 落盘路径不可达（请用 unshare --map-user）\n");
        return 1;
    }

    const Case cases[] = {
        /* P1：合法目标应用自身请求（正对照：不得被绑定校验误伤） */
        {"P1 合法目标应用自身请求 → OK + 映射更新 + 标注入", "com.real.target", "REQ",
         "com.real.target", 0, true, false, true, "10123 com.real.target\n"},
        /* P2：合法非目标应用自身请求（v2 应派发还原，参数即自报值） */
        {"P2 合法非目标应用自身请求 → OK + 还原派发", "com.other.app", "REQ", "com.other.app", 0,
         true, true, false, "10123 com.other.app\n"},
        /* N1：同 uid 但自报别人的 pid（旧实现照样 ACK 并按 pid=1 派发还原） */
        {"N1 自报 pid 不是对端进程 → ERR + 映射原样 + 零派发", "com.real.target", "REQ",
         "com.forged.non_target", 1, false, false, false, NULL},
        /* N2：pid/uid 都对，但包名与 /proc/<pid>/cmdline 不符（伪造非目标包） */
        {"N2 包名与 /proc/<pid>/cmdline 不符 → ERR + 映射原样", "com.real.target", "REQ",
         "com.forged.non_target", 0, false, false, false, NULL},
        /* N3：伪造目标包名（cmdline 是别的应用）：旧实现会把该 pid 标成已注入并污染映射 */
        {"N3 伪造目标包名 → ERR + 映射原样 + 不标注入", "com.other.app", "REQ", "com.real.target",
         0, false, false, false, NULL},
        /* N4：REPORT 是 root companion 专用通道，非 root 对端必须拒绝 */
        {"N4 非 root 对端 REPORT → ERR + 映射原样", "com.real.target", "REPORT",
         "com.forged.non_target", 0, false, false, false, NULL},
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) run_case(&cases[i]);
    run_ack_order_case();
    run_v2_nonblocking_restore_case();
    run_plan_readiness_cases();

    printf("\n结果: %d 通过, %d 失败\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
