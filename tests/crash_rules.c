/* crash_rules.c — 测试用规则模块（崩溃围栏链路）：
 *   - /0/virt/<rest>  → 虚拟重定向（同 bad_rules，用于卸载前后行为对比）
 *   - /0/crashtest/*  → resolve 内触发 SIGSEGV（围栏 siglongjmp 恢复点）
 *   - 其余路径        → valid=false（框架直通）
 *
 * 编译：gcc -shared -fPIC -O1 -g -DNSP_MODULE_BUILD -Iinclude crash_rules.c -o crash_rules.so
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

static int crash_resolve(const NspQueryCtx* q, NspPathDecision* out) {
    if (!q || !out || !q->path) return -EINVAL;
    memset(out, 0, sizeof *out);
    const char* vp = q->path;
    if (vp[0] == '/' && vp[1] == '0' && vp[2] == '/') vp += 3;
    /* FUSE 按组件逐级 lookup：stat(/0/crashtest/x) 先查 /0/crashtest（无尾斜杠） */
    if (strncmp(vp, "crashtest", 9) == 0 && (vp[9] == '/' || vp[9] == '\0')) {
        volatile int* p = (int*)0;
        *p = 1; /* SIGSEGV → 围栏恢复（longjmp 回框架） */
    }
    if (strncmp(vp, "virt/", 5) == 0 || strcmp(vp, "virt") == 0) {
        const char* rest = (vp[4] == '/') ? vp + 5 : "";
        snprintf(out->real_path, sizeof out->real_path, "%s/0/real_dir/%s", test_storage(), rest);
        snprintf(out->pkg, sizeof out->pkg, "test");
        out->valid = true;
        out->is_redirect = true;
        return 0;
    }
    return 0;
}

static int crash_probe(const NspQueryCtx* q, NspProbeResult* out) {
    if (!q || !out) return -EINVAL;
    memset(out, 0, sizeof *out);
    out->valid = false;
    return 0;
}

static const NspModuleOps crash_ops = {
    .resolve = crash_resolve,
    .probe = crash_probe,
};

/* 模块导出的是**数据符号**（全局 NspModuleInfo 结构体），loader 经 dlsym
   后直接强转 NspModuleInfo* 读取——不是函数。name 必须与目录名一致。 */
const NspModuleInfo nsp_module_info = {
    .magic = NSP_MODULE_MAGIC,
    .abi_version = NSP_MODULE_ABI_VERSION,
    .type = NSP_MODULE_TYPE_RULES,
    .caps = NSP_CAP_REDIRECT,
    .name = "crash_rules",
    .version = "1.0",
    .init = NULL,
    .exit = NULL,
    .ops = &crash_ops,
};
