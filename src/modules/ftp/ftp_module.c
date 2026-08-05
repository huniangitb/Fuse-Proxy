#define _GNU_SOURCE
#include "ftp_conf.h"
#include "ftp_backend.h"
#include "nsp_module.h"
#include "nsp_module.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <libgen.h>
#include <pthread.h>
#include <poll.h>
#include <sys/inotify.h>

/*
 * ftp_module.so — FTP 存储后端模块（NSP_MODULE_TYPE_BACKEND，由 fuse_daemon dlopen 加载）
 *
 * 与 basic_rules.so 同构，但**不实现 FUSE**：框架（fuse_daemon）已实现 FUSE，
 * 本模块只提供"目标功能（FTP）的操作方法"（backend_*），框架在路径命中
 * （backend_match）时调用，最终执行仍由框架的 FUSE 回调驱动。
 *
 * 功能：解析 ftp.conf（与规则配置同目录），注册每个 [服务器] 段的虚拟前缀：
 *   虚拟前缀 = /<段名>（如 /云盘）——FUSE 剥离 /0/ 后的原始路径直接命中，
 *   无需 REDIRECT 规则或变量。
 * 支持 ftp.conf 热加载（inotify 监听，变更后重建后端前缀表）；
 * FTP 服务器不可用时由后台线程每 1 分钟重连探活。
 *
 * ftp.conf 位置：与 --rules= 参数同目录（Android 为 /data/Namespace-Proxy/ftp.conf）
 */

#define FTP_MAX_BACKENDS FTP_CONF_MAX_SERVERS

static const NspFrameworkApi* g_api = NULL;
static char g_ftp_conf_path[PATH_MAX] = CONFIG_DIR "/ftp.conf";
static char g_var_names[FTP_MAX_BACKENDS][64];
static char g_var_values[FTP_MAX_BACKENDS][PATH_MAX];

/* ftp.conf 热加载监控线程 */
static pthread_t g_hotload_tid = 0;
static volatile sig_atomic_t g_hotload_stop = 0;

/* FTP 服务器不可用时每 1 分钟重连探活线程 */
/* 持久化会话自动处理重连（ftp_session_ensure + NOOP 保活），无需 retry 线程 */

/* get_vars：向框架注册 FTP_<段名>=<挂载前缀> 变量 */
static int ftp_module_get_vars(const char*** names, const char*** values, int* count) {
    static const char* name_ptrs[FTP_MAX_BACKENDS];
    static const char* value_ptrs[FTP_MAX_BACKENDS];
    int n = ftp_backend_count();
    if (n > FTP_MAX_BACKENDS) n = FTP_MAX_BACKENDS;
    for (int i = 0; i < n; i++) {
        /* g_var_names[i] 已由 reload_ftp_conf 填为 "FTP_<段名>"，勿再格式化
           （重叠 snprintf 同缓冲读写为 UB，且会叠加出 FTP_FTP_ 前缀） */
        name_ptrs[i] = g_var_names[i];
        value_ptrs[i] = g_var_values[i];
    }
    *names = name_ptrs;
    *values = value_ptrs;
    *count = n;
    return 0;
}

/* 重新解析 ftp.conf 并重建后端前缀表（init 与热加载共用） */
static void reload_ftp_conf(void) {
    FtpServerList list;
    if (ftp_conf_load(g_ftp_conf_path, &list) != 0) {
        LOG_WRN("ftp_module: ftp.conf 加载失败（%s），保留原后端", g_ftp_conf_path);
        return;
    }
    ftp_backend_clear();
    memset(g_var_names, 0, sizeof g_var_names);
    memset(g_var_values, 0, sizeof g_var_values);
    /* 独立索引 vi：与 ftp_backend_add 成功数一致，保证 g_var_names/
       g_var_values 与 get_vars 的循环（ftp_backend_count()）对齐 */
    int vi = 0;
    for (int i = 0; i < list.count && i < FTP_MAX_BACKENDS; i++) {
        if (ftp_backend_add(&list.servers[i]) != 0) continue;
        snprintf(g_var_names[vi], sizeof g_var_names[vi], "FTP_%s", list.servers[i].name);
        snprintf(g_var_values[vi], sizeof g_var_values[vi], "/%s", list.servers[i].name);
        LOG("ftp_module: 注册后端 /%s → FTP %s:%d%s (server=%s)",
            list.servers[i].name, list.servers[i].host, list.servers[i].port,
            list.servers[i].remote_dir, list.servers[i].name);
        vi++;
    }
    if (ftp_backend_count() == 0)
        LOG_WRN("ftp_module: 无可用 server，请检查 ftp.conf");
    else
        LOG("ftp_module: 后端就绪，共 %d 个", ftp_backend_count());
}

/* ftp.conf 热加载监控线程：inotify 监听目录，变更后重建后端前缀表 */
static void* ftp_conf_watch_thread(void* arg) {
    (void)arg;
    int fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (fd < 0) {
        LOG_WRN("ftp_module: inotify_init1 失败 (%s)", strerror(errno));
        return NULL;
    }
    char dir[PATH_MAX], fname[128];
    strncpy(dir, g_ftp_conf_path, sizeof dir - 1);
    dir[sizeof dir - 1] = '\0';
    char* slash = strrchr(dir, '/');
    if (slash) {
        strncpy(fname, slash + 1, sizeof fname - 1);
        fname[sizeof fname - 1] = '\0';
        *slash = '\0';
    } else {
        strncpy(fname, dir, sizeof fname - 1);
        fname[sizeof fname - 1] = '\0';
        strncpy(dir, "/", sizeof dir - 1);
    }
    int wd = inotify_add_watch(fd, dir, IN_CLOSE_WRITE | IN_MODIFY | IN_MOVED_TO);
    if (wd < 0) {
        LOG_WRN("ftp_module: inotify_add_watch(%s) 失败 (%s)", dir, strerror(errno));
        close(fd);
        return NULL;
    }
    struct pollfd pfd = { .fd = fd, .events = POLLIN };
    char buf[4096];
    while (!g_hotload_stop) {
        int r = poll(&pfd, 1, 1000);
        if (r <= 0) continue;
        ssize_t n = read(fd, buf, sizeof buf);
        if (n <= 0) continue;
        for (size_t off = 0; off + sizeof(struct inotify_event) <= (size_t)n; ) {
            struct inotify_event* ev = (struct inotify_event*)(buf + off);
            if (ev->len > 0 && strcmp(ev->name, fname) == 0) {
                LOG("ftp_module: 检测到 ftp.conf 变更，热重载");
                reload_ftp_conf();
                break;
            }
            off += sizeof(struct inotify_event) + ev->len;
        }
    }
    close(fd);
    return NULL;
}

static int ftp_module_init(const NspFrameworkApi* api) {
    g_api = api;
    /* ftp.conf 与规则配置同目录：--rules=<dir>/injector.conf → <dir>/ftp.conf */
    if (api && api->get_rules_path) {
        const char* rp = api->get_rules_path();
        if (rp && rp[0]) {
            char dir[PATH_MAX];
            snprintf(dir, sizeof dir, "%s", rp);
            char* slash = strrchr(dir, '/');
            if (slash) {
                *slash = '\0';
                if (dir[0])
                    snprintf(g_ftp_conf_path, sizeof g_ftp_conf_path, "%s/ftp.conf", dir);
            }
        }
    }

    reload_ftp_conf();

    /* 启动 ftp.conf 热加载监控线程 */
    g_hotload_stop = 0;
    if (pthread_create(&g_hotload_tid, NULL, ftp_conf_watch_thread, NULL) != 0) {
        LOG_WRN("ftp_module: 启动 ftp.conf 监控线程失败");
        g_hotload_tid = 0;
    }
    /* 持久化会话自动处理重连（ftp_session_ensure + NOOP 保活），无需 retry 线程 */
    return 0;
}

static void ftp_module_exit(void) {
    g_hotload_stop = 1;
    if (g_hotload_tid) {
        pthread_join(g_hotload_tid, NULL);
        g_hotload_tid = 0;
    }
    /* 无 retry 线程 */
    /* 无 retry 线程不需 join */
    ftp_backend_clear();
}

static const NspModuleOps ftp_module_ops = {
    /* 后端 I/O：只提供方法，执行由框架 FUSE 回调驱动 */
    .backend_match    = ftp_backend_match,
    .backend_getattr  = ftp_backend_getattr,
    .backend_readdir  = ftp_backend_readdir,
    .backend_open     = ftp_backend_open,
    .backend_read     = ftp_backend_read,
    .backend_write    = ftp_backend_write,
    .backend_flush    = ftp_backend_flush,
    .backend_release  = ftp_backend_release,
    .backend_create   = ftp_backend_create,
    .backend_unlink   = ftp_backend_unlink,
    .backend_mkdir    = ftp_backend_mkdir,
    .backend_rmdir    = ftp_backend_rmdir,
    .backend_rename   = ftp_backend_rename,
    .backend_truncate = ftp_backend_truncate,
    .get_vars = ftp_module_get_vars,
};

/* 必须为非 static 动态符号（loader 经 dlsym 查找） */
const NspModuleInfo nsp_module_info = {
    .magic = NSP_MODULE_MAGIC,
    .abi_version = NSP_MODULE_ABI_VERSION,
    .type = NSP_MODULE_TYPE_BACKEND,
    .caps = NSP_CAP_MOUNT_POINT | NSP_CAP_VAR | NSP_CAP_BACKEND_IO,
    .name = "ftp_module",
    .version = "2.0-test",
    .init = ftp_module_init,
    .exit = ftp_module_exit,
    .ops = &ftp_module_ops,
};
