#define _GNU_SOURCE
#include "ftp_conf.h"
#include "ftp_backend.h"
#include "nsp_module.h"
#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

/*
 * ftp_module.so — FTP 存储后端模块（NSP_MODULE_TYPE_BACKEND，由 fuse_daemon dlopen 加载）
 *
 * 与 basic_rules.so 同构，但**不实现 FUSE**：框架（fuse_daemon）已实现 FUSE，
 * 本模块只提供"目标功能（FTP）的操作方法"（backend_*），框架在路径命中
 * （backend_match）时调用，最终执行仍由框架的 FUSE 回调驱动。
 *
 * 功能：解析 ftp.conf（与规则配置同目录），注册每个 [服务器] 段的挂载前缀：
 *   前缀 = <mount_base>/<段名>（mount_base 由 ftp.conf [GLOBAL] 配置，默认 /mnt/nsp_ftp）
 * 路径命中前缀时，框架改调本模块方法（FTP 列目录/读/写/删/建/重命名等）。
 * 另经 get_vars 提供变量 FTP_<段名>=<前缀>，供规则以 $FTP_<段名> 引用。
 *
 * ftp.conf 位置：与 --rules= 参数同目录（Android 为 /data/Namespace-Proxy/ftp.conf）
 */

#define FTP_MAX_BACKENDS FTP_CONF_MAX_SERVERS

static const NspFrameworkApi* g_api = NULL;
static char g_ftp_conf_path[PATH_MAX] = CONFIG_DIR "/ftp.conf";
static char g_mount_base[PATH_MAX] = "/mnt/nsp_ftp";
static char g_var_names[FTP_MAX_BACKENDS][64];
static char g_var_values[FTP_MAX_BACKENDS][PATH_MAX];

/* get_vars：向框架注册 FTP_<段名>=<挂载前缀> 变量 */
static int ftp_module_get_vars(const char*** names, const char*** values, int* count) {
    static const char* name_ptrs[FTP_MAX_BACKENDS];
    static const char* value_ptrs[FTP_MAX_BACKENDS];
    int n = ftp_backend_count();
    if (n > FTP_MAX_BACKENDS) n = FTP_MAX_BACKENDS;
    for (int i = 0; i < n; i++) {
        snprintf(g_var_names[i], sizeof g_var_names[i], "FTP_%s", g_var_names[i]);
        name_ptrs[i] = g_var_names[i];
        value_ptrs[i] = g_var_values[i];
    }
    *names = name_ptrs;
    *values = value_ptrs;
    *count = n;
    return 0;
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

    FtpServerList list;
    if (ftp_conf_load(g_ftp_conf_path, &list) != 0) {
        LOG_WRN("ftp_module: 未找到可用 ftp.conf 或未配置 server（%s），模块空载", g_ftp_conf_path);
        return 0;   /* 加载成功但无后端；补充配置后需重载 */
    }
    strncpy(g_mount_base, list.mount_base, sizeof g_mount_base - 1);

    for (int i = 0; i < list.count && i < FTP_MAX_BACKENDS; i++) {
        if (ftp_backend_add(&list.servers[i], list.mount_base) != 0) {
            LOG_ERR("ftp_module: 注册后端失败 server=%s", list.servers[i].name);
            continue;
        }
        snprintf(g_var_names[i], sizeof g_var_names[i], "FTP_%s", list.servers[i].name);
        snprintf(g_var_values[i], sizeof g_var_values[i], "%s/%s", list.mount_base, list.servers[i].name);
        LOG("ftp_module: 注册后端 %s → FTP %s:%d%s (server=%s)",
            g_var_values[i], list.servers[i].host, list.servers[i].port,
            list.servers[i].remote_dir, list.servers[i].name);
    }
    if (ftp_backend_count() == 0)
        LOG_WRN("ftp_module: 全部 server 注册失败，请检查 ftp.conf 与网络");
    return 0;
}

static void ftp_module_exit(void) {
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
