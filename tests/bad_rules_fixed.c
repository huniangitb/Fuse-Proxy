/* bad_rules_fixed.c — 与 bad_rules 同名（"bad_rules"）的修复版，用于 ban 自愈+槽位复用回归：
 *   - /0/virt/<rest> → 重定向（与 bad_rules 相同，ban 解除后应重新可见）
 *   - 无 errtest 错误路径（不再触发熔断）
 *   - 其余路径 → valid=false（直通）
 *
 * 用法：先加载 bad_rules.so 并触发熔断（落盘 ban），再用本文件内容覆盖
 * <moddir>/bad_rules/bad_rules.so（哈希变化），等待热重载/重启后验证
 * /0/virt/ 重新可见（版本更新自愈）且 daemon 存活（槽位复用，无注册表满）。
 *
 * 编译：gcc -shared -fPIC -O1 -DNSP_MODULE_BUILD -Iinclude bad_rules_fixed.c -o bad_rules_fixed.so
 * 注意：nsp_module_info.name 必须为 "bad_rules"（与目录名一致），产物改名拷贝。
 */
#define _GNU_SOURCE
#include "nsp_module.h"
#include <string.h>
#include <stdlib.h>
#include <errno.h>

static const char* test_storage(void) {
    const char* s = getenv("CIRCUIT_TEST_STORAGE");
    return (s && s[0]) ? s : "/tmp/fuse_circuit_test/storage";
}

static int fixed_resolve(const NspQueryCtx* q, NspResolveResult* out) {
    if (!q || !out || !q->path) return -EINVAL;
    memset(out, 0, sizeof *out);
    const char* vp = q->path;
    if (vp[0] == '/' && vp[1] == '0' && vp[2] == '/') vp += 3;
    if (strncmp(vp, "virt/", 5) == 0 || strcmp(vp, "virt") == 0) {
        const char* rest = (vp[4] == '/') ? vp + 5 : "";
        snprintf(out->sub_path, sizeof out->sub_path, "/virt%s", rest);
        snprintf(out->real_path, sizeof out->real_path, "%s/0/real_dir/%s",
                 test_storage(), rest);
        snprintf(out->redir_target, sizeof out->redir_target, "/virt");
        snprintf(out->pkg, sizeof out->pkg, "test");
        out->valid = true;
        out->user_id = 0;
        out->has_redir = true;
        out->is_redir = true;
        return 0;
    }
    return 0;
}

static int fixed_probe(const NspQueryCtx* q, NspProbeResult* out) {
    if (!q || !out) return -EINVAL;
    memset(out, 0, sizeof *out);
    out->valid = false;
    return 0;
}

static const NspModuleOps fixed_ops = {
    .resolve = fixed_resolve,
    .probe   = fixed_probe,
};

const NspModuleInfo nsp_module_info = {
    .magic       = NSP_MODULE_MAGIC,
    .abi_version = NSP_MODULE_ABI_VERSION,
    .type        = NSP_MODULE_TYPE_RULES,
    .caps        = NSP_CAP_REDIRECT,
    .name        = "bad_rules",
    .version     = "1.1-fixed",
    .init        = NULL,
    .exit        = NULL,
    .ops         = &fixed_ops,
};
