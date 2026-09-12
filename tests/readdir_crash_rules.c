/* readdir_crash_rules.c — readdir_extra 崩溃围栏回归（用户日志 op=readdir_extra path=/Android）：
 *   - /0/virt/<rest> → 重定向（置毒前后行为对比）
 *   - readdir_extra   → 直接 SIGSEGV（围栏 longjmp 恢复，单次即置毒）
 *   - 其余 resolve    → valid=false（直通）
 *
 * 编译：gcc -shared -fPIC -O1 -g -DNSP_MODULE_BUILD -Iinclude readdir_crash_rules.c -o readdir_crash_rules.so
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

static int rc_resolve(const NspQueryCtx* q, NspResolveResult* out) {
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

static int rc_probe(const NspQueryCtx* q, NspProbeResult* out) {
    if (!q || !out) return -EINVAL;
    memset(out, 0, sizeof *out);
    out->valid = false;
    return 0;
}

static int rc_readdir_extra(const NspQueryCtx* q, const char* sub_path, int user_id,
                            const char* pkg, bool is_root, NspDirEntry* out, int max) {
    (void)q; (void)sub_path; (void)user_id; (void)pkg; (void)is_root; (void)out; (void)max;
    volatile int* p = (int*)0;
    *p = 1;                    /* SIGSEGV → 围栏恢复 */
    return 0;
}

static const NspModuleOps rc_ops = {
    .resolve = rc_resolve,
    .probe   = rc_probe,
    .readdir_extra = rc_readdir_extra,
};

const NspModuleInfo nsp_module_info = {
    .magic       = NSP_MODULE_MAGIC,
    .abi_version = NSP_MODULE_ABI_VERSION,
    .type        = NSP_MODULE_TYPE_RULES,
    .caps        = NSP_CAP_REDIRECT | NSP_CAP_READDIR_EXTRA,
    .name        = "readdir_crash_rules",
    .version     = "1.0",
    .init        = NULL,
    .exit        = NULL,
    .ops         = &rc_ops,
};
