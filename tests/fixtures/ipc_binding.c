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
#include <limits.h>
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
static _Atomic int g_last_restore_pid;
static _Atomic int g_last_restore_uid;
static char g_last_restore_pkg[256];

const char* get_active_mnt_src(void) { return "/mock/fuse"; }
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
int perform_app_restore(const char* pkg, int pid, uid_t uid) {
    snprintf(g_last_restore_pkg, sizeof g_last_restore_pkg, "%s", pkg);
    atomic_store(&g_last_restore_pid, pid);
    atomic_store(&g_last_restore_uid, (int)uid);
    atomic_fetch_add(&g_restore_calls, 1);
    return 0;
}
void print_active_rules(const char* pkg, int pid, uid_t uid, const char* trigger_source) {
    (void)pkg;
    (void)pid;
    (void)uid;
    (void)trigger_source;
}

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
        {"N3 伪造目标包名 → ERR + 映射原样 + 不标注入", "com.other.app", "REQ",
         "com.real.target", 0, false, false, false, NULL},
        /* N4：REPORT 是 root companion 专用通道，非 root 对端必须拒绝 */
        {"N4 非 root 对端 REPORT → ERR + 映射原样", "com.real.target", "REPORT",
         "com.forged.non_target", 0, false, false, false, NULL},
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) run_case(&cases[i]);

    printf("\n结果: %d 通过, %d 失败\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
