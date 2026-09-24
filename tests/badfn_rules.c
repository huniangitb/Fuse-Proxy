/* badfn_rules.c — BADFN 测试模块：
 *   - /0/virt/<rest>  → 虚拟重定向（验证模块加载后规则生效）
 *   - readdir_extra   → 未实现（NULL）：验证 BADFN 不触发毒化
 *   - get_pkg         → 未实现（NULL）：验证 BADFN 不触发毒化
 *
 * 编译：gcc -shared -fPIC -O1 -DNSP_MODULE_BUILD -Iinclude badfn_rules.c -o badfn_rules.so
 */
#define _GNU_SOURCE
#include "nsp_module.h"
#include <string.h>
#include <stdlib.h>

static const char* test_storage(void) {
    const char* s = getenv("CIRCUIT_TEST_STORAGE");
    return (s && s[0]) ? s : "/tmp/fuse_circuit_test/storage";
}

static int badfn_resolve(const NspQueryCtx* q, NspResolveResult* out) {
    if (!q || !out || !q->path) return -1;
    memset(out, 0, sizeof *out);
    const char* vp = q->path;
    if (vp[0] == '/' && vp[1] == '0' && vp[2] == '/') vp += 3;
    if (strncmp(vp, "virt/", 5) == 0 || strcmp(vp, "virt") == 0) {
        const char* rest = (vp[4] == '/') ? vp + 5 : "";
        snprintf(out->sub_path, sizeof out->sub_path, "/virt%s", rest);
        snprintf(out->real_path, sizeof out->real_path, "%s/0/real_dir/%s", test_storage(), rest);
        snprintf(out->pkg, sizeof out->pkg, "test");
        out->valid = true;
        out->user_id = 0;
        out->is_redir = true;
        return 0;
    }
    return 0;
}

static int badfn_probe(const NspQueryCtx* q, NspProbeResult* out) {
    if (!q || !out) return -1;
    memset(out, 0, sizeof *out);
    out->valid = false;
    return 0;
}

/* 只实现 resolve + probe，故意不实现 readdir_extra 和 get_pkg
   → nsp_fence_readdir_extra / nsp_fence_get_pkg 返回 NSP_FENCE_BADFN */
static const NspModuleOps badfn_ops = {
    .resolve = badfn_resolve,
    .probe = badfn_probe,
    /* readdir_extra = NULL, get_pkg = NULL */
};

const NspModuleInfo nsp_module_info = {
    .magic = NSP_MODULE_MAGIC,
    .abi_version = NSP_MODULE_ABI_VERSION,
    .type = NSP_MODULE_TYPE_RULES,
    .caps = NSP_CAP_REDIRECT,
    .name = "badfn_rules",
    .version = "1.0",
    .init = NULL,
    .exit = NULL,
    .ops = &badfn_ops,
};
