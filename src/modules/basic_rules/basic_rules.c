#define _GNU_SOURCE
#include "nsp_module.h"
#include "br_rules.h"

/*
 * basic_rules.c — 基础规则模块入口
 *
 * 注册规则类型：REDIRECT / SANDBOX / HIDE / ALLOW / RO，
 * 并提供 readdir 虚拟目录补充与配置热重载。
 * 决策引擎见 br_rules.c（从 vfs_core.c 适配，规则匹配语义逐行等价）。
 */

static bool g_br_inited = false;

/* 本模块申请的规则类型：框架只下发这些类型的记录，其他模块声明的类型
   不会出现在本模块的视图里（模块间规则隔离）。
   VAR = 变量定义行（REDIRECT 目标中的 $name 展开需要）。
   FTP 暂列在内：FTP 规则当前仍由本模块解析为 is_ftp 供框架路由；
   FTP 归属迁移到 ftp_module 后即可从此表移除。 */
static const char* const g_br_subscribe[] = {
    "HIDE",       "RO",           "REDIRECT",   "ALLOW",
    "MONITOR",    "SANDBOX",      "GLOBAL_INJECT", "SKIP_SYSTEM_APPS",
    "FUSE_EXTRA_ARGS", "FTP",     "VAR",
};

/* 框架配置下发监听器：框架在 init 后与每次热重载后按订阅过滤后调用 */
static void br_module_config(const NspModuleConfig* cfg) {
    br_rules_apply_config(cfg);
}

static int br_module_init(const NspFrameworkApi* api) {
    if (!api || api->api_version < NSP_FRAMEWORK_API_VERSION) return -1;
    if (!api->set_config_listener) {
        LOG_ERR("basic_rules: 框架未提供配置下发接口，规则引擎无法工作");
        return -1;
    }
    /* 规则路径与启动标志由框架经 api 提供（--rules= 与 --disable-sandbox）；
       配置本身不再自读——先声明订阅与监听器，框架在 init 返回后立即下发 */
    const char* rules_path = NULL;
    if (api->get_rules_path) rules_path = api->get_rules_path();
    bool disable_sandbox = false;
    if (api->get_flags) disable_sandbox = (api->get_flags() & NSP_FLAG_DISABLE_SANDBOX) != 0;
    if (api->subscribe_rules) {
        api->subscribe_rules(g_br_subscribe,
                             (int)(sizeof g_br_subscribe / sizeof *g_br_subscribe));
    }
    int rc = br_rules_init(rules_path, disable_sandbox);
    if (rc != 0) return rc;
    api->set_config_listener(br_module_config);
    g_br_inited = true;
    return 0;
}

static void br_module_exit(void) {
    if (g_br_inited) {
        br_rules_exit();
        g_br_inited = false;
    }
}

static int br_module_resolve(const NspQueryCtx* q, NspPathDecision* out) {
    if (!q || !out) return -1;
    BrQuery bq = {
        .path = q->path,
        .uid = q->uid,
        .pid = q->pid,
    };
    BrResult r;
    br_resolve(&bq, &r);
    if (!r.valid) {
        out->valid = false;
        return 0;
    }
    /* 逐字段显式拷贝：BrResult 与 NspPathDecision 一一对应（user_id/sub_path
       是本模块内部匹配用，不跨 ABI——框架自算，见 nsp_module.h） */
    out->valid = true;
    out->appear_missing = r.appear_missing;
    out->read_only = r.read_only;
    out->attr_override = r.attr_override;
    out->mode = r.mode;
    out->uid = r.uid;
    out->gid = r.gid;
    strncpy(out->real_path, r.real_path, sizeof out->real_path - 1);
    out->real_path[sizeof out->real_path - 1] = '\0';
    out->virtual_kind = r.virtual_kind;
    out->is_redirect = r.is_redirect;
    out->is_ftp = r.is_ftp;
    return 0;
}

static int br_module_probe(const NspQueryCtx* q, NspProbeResult* out) {
    if (!q || !out) return -1;
    BrQuery bq = {
        .path = q->path,
        .uid = q->uid,
        .pid = q->pid,
    };
    BrProbeResult r;
    br_probe(&bq, &r);
    if (!r.valid) {
        out->valid = false;
        return 0;
    }
    out->valid = true;
    out->appear_missing = r.appear_missing;
    out->virtual_kind = r.virtual_kind;
    out->is_other_app_pkg = r.is_other_app_pkg;
    return 0;
}

static int br_module_readdir_extra(const NspQueryCtx* q, const char* sub_path, int user_id,
                                   const char* pkg, bool is_root, NspDirEntry* out, int max) {
    if (!q || !out || max <= 0 || !sub_path) return 0;
    BrQuery bq = {
        .path = sub_path,
        .uid = q->uid,
        .pid = q->pid,
    };
    return br_readdir_extra(&bq, sub_path, user_id, pkg, is_root, out, max);
}


static const NspModuleOps g_br_ops = {
    .resolve = br_module_resolve,
    .probe = br_module_probe,
    .readdir_extra = br_module_readdir_extra,
};

/* 模块静态信息：框架 dlopen 后 dlsym(NSP_MODULE_INFO_SYMBOL) 读取 */
const NspModuleInfo nsp_module_info = {
    .magic = NSP_MODULE_MAGIC,
    .abi_version = NSP_MODULE_ABI_VERSION,
    .type = NSP_MODULE_TYPE_RULES,
    .caps = NSP_CAP_REDIRECT | NSP_CAP_SANDBOX | NSP_CAP_HIDE | NSP_CAP_ALLOW | NSP_CAP_RO |
            NSP_CAP_READDIR_EXTRA,
    .name = "basic_rules",
    .version = "1.0.0",
    .init = br_module_init,
    .exit = br_module_exit,
    .ops = &g_br_ops,
};
