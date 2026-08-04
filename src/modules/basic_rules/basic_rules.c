#define _GNU_SOURCE
#include "nsp_module.h"
#include "module_loader.h"
#include "common.h"
#include "br_rules.h"

/*
 * basic_rules.c — 基础规则模块入口
 *
 * 注册规则类型：REDIRECT / SANDBOX / HIDE / ALLOW / RO，
 * 并提供 readdir 虚拟目录补充与配置热重载。
 * 决策引擎见 br_rules.c（从 vfs_core.c 适配，规则匹配语义逐行等价）。
 */

static bool g_br_inited = false;
static const NspFrameworkApi* g_api = NULL;

static int br_module_init(const NspFrameworkApi* api) {
    g_api = api;
    if (!api) return -1;
    /* 规则路径与启动标志由框架经 api 提供（--rules= 与 --disable-sandbox） */
    const char* rules_path = NULL;
    if (api->api_version >= 2 && api->get_rules_path)
        rules_path = api->get_rules_path();
    bool disable_sandbox = false;
    if (api->api_version >= 2 && api->get_flags)
        disable_sandbox = (api->get_flags() & NSP_FLAG_DISABLE_SANDBOX) != 0;
    int rc = br_rules_init(rules_path, disable_sandbox);
    if (rc == 0) g_br_inited = true;
    return rc;
}

static void br_module_exit(void) {
    if (g_br_inited) {
        br_rules_exit();
        g_br_inited = false;
    }
}

static int br_module_resolve(const NspQueryCtx* q, NspResolveResult* out) {
    if (!q || !out) return -1;
    BrQuery bq = {
        .path = q->path,
        .uid = q->uid,
        .pid = q->pid,
        .gid = q->gid,
    };
    BrResult r;
    br_resolve(&bq, &r);
    if (!r.valid) {
        out->valid = false;
        return 0;
    }
    out->valid = true;
    out->user_id = r.user_id;
    strncpy(out->sub_path, r.sub_path, sizeof out->sub_path - 1);
    strncpy(out->pkg, r.pkg, sizeof out->pkg - 1);
    out->hidden = r.hidden;
    out->ro = r.ro;
    out->has_redir = r.has_redir;
    strncpy(out->redir_target, r.redir_target, sizeof out->redir_target - 1);
    out->has_sandbox = r.has_sandbox;
    strncpy(out->sandbox_target, r.sandbox_target, sizeof out->sandbox_target - 1);
    strncpy(out->real_path, r.real_path, sizeof out->real_path - 1);
    out->is_redir = r.is_redir;
    out->is_virtual_ancestor = r.is_virtual_ancestor;
    out->is_redirect_target = r.is_redirect_target;
    out->is_other_app_pkg = r.is_other_app_pkg;
    out->is_ftp = r.is_ftp;
    strncpy(out->ftp_backend, r.ftp_backend, sizeof out->ftp_backend - 1);
    out->ftp_backend[sizeof out->ftp_backend - 1] = '\0';
    return 0;
}

static int br_module_probe(const NspQueryCtx* q, NspProbeResult* out) {
    if (!q || !out) return -1;
    BrQuery bq = {
        .path = q->path,
        .uid = q->uid,
        .pid = q->pid,
        .gid = q->gid,
    };
    BrProbeResult r;
    br_probe(&bq, &r);
    if (!r.valid) {
        out->valid = false;
        return 0;
    }
    out->valid = true;
    out->hidden = r.hidden;
    out->is_redirect_target = r.is_redirect_target;
    out->is_virtual_ancestor = r.is_virtual_ancestor;
    out->is_other_app_pkg = r.is_other_app_pkg;
    return 0;
}

static int br_module_readdir_extra(const NspQueryCtx* q, const char* sub_path, int user_id,
                                   const char* pkg, bool is_root, NspDirEntry* out, int max) {
    if (!q || !out || max <= 0) return 0;
    BrQuery bq = {
        .path = sub_path,
        .uid = q->uid,
        .pid = q->pid,
        .gid = q->gid,
    };
    return br_readdir_extra(&bq, sub_path, user_id, pkg, is_root, out, max);
}

static int br_module_reload(void) {
    br_reload_config();
    return 0;
}

static int br_module_get_pkg(uid_t uid, pid_t tid, char* pkg_out, size_t pkg_size) {
    return br_get_pkg(uid, tid, pkg_out, pkg_size);
}

static const NspModuleOps g_br_ops = {
    .resolve = br_module_resolve,
    .probe = br_module_probe,
    .readdir_extra = br_module_readdir_extra,
    .reload = br_module_reload,
    .get_pkg = br_module_get_pkg,
};

/* 模块静态信息：框架 dlopen 后 dlsym(NSP_MODULE_INFO_SYMBOL) 读取 */
const NspModuleInfo nsp_module_info = {
    .magic = NSP_MODULE_MAGIC,
    .abi_version = NSP_MODULE_ABI_VERSION,
    .type = NSP_MODULE_TYPE_RULES,
    .caps = NSP_CAP_REDIRECT | NSP_CAP_SANDBOX | NSP_CAP_HIDE |
            NSP_CAP_ALLOW | NSP_CAP_RO | NSP_CAP_READDIR_EXTRA | NSP_CAP_VIRTUAL_DIR,
    .name = "basic_rules",
    .version = "1.0.0",
    .init = br_module_init,
    .exit = br_module_exit,
    .ops = &g_br_ops,
};
