/* overflow_rules.c — readdir_extra 超限返回回归（got > max-n 钳制）：
 *   - /0/virt/<rest> → 重定向（熔断前后行为对比）
 *   - readdir_extra   → 填充 min(max,2) 个合法条目，但谎报返回 max+10
 *     （修复前：框架 n+=got 越界，栈数组越界读+filler 垃圾；
 *      修复后：整批丢弃并计熔断错误，daemon 存活，ls 正常）
 *
 * 编译：gcc -shared -fPIC -O1 -DNSP_MODULE_BUILD -Iinclude overflow_rules.c -o overflow_rules.so
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

static int ov_resolve(const NspQueryCtx* q, NspPathDecision* out) {
    if (!q || !out || !q->path) return -EINVAL;
    memset(out, 0, sizeof *out);
    const char* vp = q->path;
    if (vp[0] == '/' && vp[1] == '0' && vp[2] == '/') vp += 3;
    if (strncmp(vp, "virt/", 5) == 0 || strcmp(vp, "virt") == 0) {
        const char* rest = (vp[4] == '/') ? vp + 5 : "";
        snprintf(out->real_path, sizeof out->real_path, "%s/0/real_dir/%s", test_storage(), rest);
        out->valid = true;
        out->is_redirect = true;
        return 0;
    }
    return 0;
}

static int ov_probe(const NspQueryCtx* q, NspProbeResult* out) {
    if (!q || !out) return -EINVAL;
    memset(out, 0, sizeof *out);
    out->valid = false;
    return 0;
}

static int ov_readdir_extra(const NspQueryCtx* q, const char* sub_path, int user_id,
                            const char* pkg, bool is_root, NspDirEntry* out, int max) {
    (void)q;
    (void)sub_path;
    (void)user_id;
    (void)pkg;
    (void)is_root;
    if (!out || max <= 0) return 0;
    /* 只在边界内写 2 个合法条目，但谎报超大计数（不真越界写，避免测试本身踩内存） */
    int fill = max >= 2 ? 2 : max;
    for (int i = 0; i < fill; i++) {
        snprintf(out[i].name, sizeof out[i].name, "ovf%d", i);
        out[i].is_dir = true;
    }
    return max + 10;
}

static const NspModuleOps ov_ops = {
    .resolve = ov_resolve,
    .probe = ov_probe,
    .readdir_extra = ov_readdir_extra,
};

const NspModuleInfo nsp_module_info = {
    .magic = NSP_MODULE_MAGIC,
    .abi_version = NSP_MODULE_ABI_VERSION,
    .type = NSP_MODULE_TYPE_RULES,
    .caps = NSP_CAP_REDIRECT | NSP_CAP_READDIR_EXTRA,
    .name = "overflow_rules",
    .version = "1.0",
    .init = NULL,
    .exit = NULL,
    .ops = &ov_ops,
};
