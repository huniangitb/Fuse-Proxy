#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "ftp_conf.h"
#include "ftp_backend.h"
#include "nsp_module.h"
#include "nsp_util.h" /* nsp_set_thread_name（线程语义化命名） */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <libgen.h>
#include <curl/curl.h> /* curl_global_init */
#include <pthread.h>
#include <poll.h>
#include <sys/inotify.h>

/*
 * ftp_module.so — FTP 存储后端模块（由 fuse_daemon dlopen 加载）
 *
 * **不实现 FUSE**：框架（fuse_daemon）已实现 FUSE，
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

/* 后端数量无上限（ftp_backend 指针数组 + 加载器注册表均动态扩充） */

static char g_ftp_conf_path[PATH_MAX] = CONFIG_DIR "/ftp.conf";

/* ftp.conf 热加载监控线程 */
static pthread_t g_hotload_tid = 0;
static volatile sig_atomic_t g_hotload_stop = 0;

/* 运行期能力探测：本 libcurl 是否编入了 SFTP。
   编译期无法从 curl 头判断——CURL_VERSION_LIBSSH2 这个特性位在 curl 8.x 已
   删除（8.22 头文件里不存在），故查 curl_version_info()->protocols 里有没有
   "sftp"。没有时 proto=sftp 的段**整段跳过**（fail-closed）：静默退回明文
   ftp 会把账号密码发到错误的协议上，比连不上更糟。 */
static bool curl_supports_sftp(void) {
    curl_version_info_data* vi = curl_version_info(CURLVERSION_NOW);
    if (!vi || !vi->protocols) return false;
    for (const char* const* p = vi->protocols; *p; p++)
        if (strcmp(*p, "sftp") == 0) return true;
    return false;
}

static bool g_curl_has_sftp = false; /* init 内探测一次（curl_global_init 之后） */

/* 重新解析 ftp.conf 并重建后端前缀表（init 与热加载共用） */
static void reload_ftp_conf(void) {
    FtpServerList list;
    if (ftp_conf_load(g_ftp_conf_path, &list) != 0) {
        LOG_WRN("ftp_module: ftp.conf 加载失败（%s），保留原后端", g_ftp_conf_path);
        return;
    }
    ftp_backend_clear();
    /* 后端表已动态化（加载器注册表 + FTP 后端指针数组均无 16 上限），
       有多少 server 注册多少；单段 add 失败（OOM）仅跳过该段 */
    for (int i = 0; i < list.count; i++) {
        if (list.servers[i].sftp && !g_curl_has_sftp) {
            LOG_ERR("ftp_module: [%s] proto=sftp，但本 libcurl 未编入 SFTP（缺 libssh2），"
                    "该段跳过", list.servers[i].name);
            continue;
        }
        if (list.servers[i].sftp && list.servers[i].host_key_check) {
            /* 主机密钥校验开启却没有可读的 known_hosts：必然连不上，且 libcurl
               的报错（unknown host / failed verification）指不到配置。启动时
               loud 提示一次，给出补文件的命令与关闭开关——不是错误（文件可能
               稍后补齐），故 WRN。 */
            const char* kh = list.servers[i].known_hosts[0] ? list.servers[i].known_hosts
                                                            : CONFIG_DIR "/known_hosts";
            if (access(kh, R_OK) != 0)
                LOG_WRN("ftp_module: [%s] host_key_check 开启但 %s 不可读（%s）——"
                        "主机密钥校验会失败；可执行 ssh-keyscan -p %d %s >> %s，"
                        "或在该段设 host_key_check = off",
                        list.servers[i].name, kh, strerror(errno), list.servers[i].port,
                        list.servers[i].host, kh);
        }
        if (ftp_backend_add(&list.servers[i]) != 0) continue;
        LOG("ftp_module: 注册后端 /%s → %s://%s:%d%s (server=%s)", list.servers[i].name,
            list.servers[i].sftp ? "sftp" : "ftp", list.servers[i].host, list.servers[i].port,
            list.servers[i].remote_dir, list.servers[i].name);
    }
    ftp_conf_free(&list);
    if (ftp_backend_count() == 0)
        LOG_WRN("ftp_module: 无可用 server，请检查 ftp.conf");
    else
        LOG("ftp_module: 后端就绪，共 %d 个", ftp_backend_count());
}

/* ftp.conf 热加载监控线程：inotify 监听目录，变更后重建后端前缀表 */
static void* ftp_conf_watch_thread(void* arg) {
    (void)arg;
    nsp_set_thread_name("nsp_ftpcfg");
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
    struct pollfd pfd = {.fd = fd, .events = POLLIN};
    char buf[4096];
    while (!g_hotload_stop) {
        int r = poll(&pfd, 1, 1000);
        if (r <= 0) continue;
        ssize_t n = read(fd, buf, sizeof buf);
        if (n <= 0) continue;
        for (size_t off = 0; off + sizeof(struct inotify_event) <= (size_t)n;) {
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
    if (!api || api->api_version < NSP_FRAMEWORK_API_VERSION) return -1;
    /* libcurl 全局初始化必须在**任何** curl_easy_init 之前完成：不调则 libcurl
       走隐式初始化，而该路径非线程安全（文档明示），本模块的 easy 句柄由任意
       FUSE worker 线程经 ftp_easy_new 并发创建 → 有竞态。幂等（libcurl 内部
       引用计数，重复调用安全），故热重载重复 init 无碍。
       取舍：exit 侧**不**调 curl_global_cleanup——热重载会 dlclose 本 .so，
       若 cleanup 释放了全局 SSL/解析器状态，而其它仍映射的实例（或框架侧
       残留句柄）还在用，就会踩释放后的映射/状态。进程退出时由 libcurl 的
       析构器统一回收，不泄漏。 */
    curl_global_init(CURL_GLOBAL_DEFAULT);
    /* 能力探测须在 curl_global_init 之后（version_info 依赖全局初始化） */
    g_curl_has_sftp = curl_supports_sftp();
    LOG("ftp_module: libcurl %s（SFTP %s）", curl_version(),
        g_curl_has_sftp ? "可用" : "不可用：未编入 libssh2，proto=sftp 段会被跳过");
    /* ftp.conf 与规则配置同目录：--rules=<dir>/injector.conf → <dir>/ftp.conf */
    if (api && api->get_rules_path) {
        const char* rp = api->get_rules_path();
        if (rp && rp[0]) {
            char dir[PATH_MAX];
            snprintf(dir, sizeof dir, "%s", rp);
            char* slash = strrchr(dir, '/');
            if (slash) {
                *slash = '\0';
                if (dir[0]) snprintf(g_ftp_conf_path, sizeof g_ftp_conf_path, "%s/ftp.conf", dir);
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
    ftp_backend_clear();
    /* 不调 curl_global_cleanup：理由见 ftp_module_init 顶部注释（热重载
       dlclose 场景下清理全局状态会让仍在映射的实例踩空） */
}

static const NspModuleOps ftp_module_ops = {
    /* 后端 I/O：只提供方法，执行由框架 FUSE 回调驱动 */
    .backend_match = ftp_backend_match,     .backend_getattr = ftp_backend_getattr,
    .backend_readdir = ftp_backend_readdir, .backend_open = ftp_backend_open,
    .backend_read = ftp_backend_read,       .backend_write = ftp_backend_write,
    .backend_flush = ftp_backend_flush,     .backend_release = ftp_backend_release,
    .backend_create = ftp_backend_create,   .backend_unlink = ftp_backend_unlink,
    .backend_mkdir = ftp_backend_mkdir,     .backend_rmdir = ftp_backend_rmdir,
    .backend_rename = ftp_backend_rename,   .backend_truncate = ftp_backend_truncate,
};

/* 必须为非 static 动态符号（loader 经 dlsym 查找） */
const NspModuleInfo nsp_module_info = {
    .magic = NSP_MODULE_MAGIC,
    .abi_version = NSP_MODULE_ABI_VERSION,
    .name = "ftp_module",
    .version = "2.0-test",
    .init = ftp_module_init,
    .exit = ftp_module_exit,
    .ops = &ftp_module_ops,
};
