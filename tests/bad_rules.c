/* bad_rules.c — 测试用规则模块（熔断链路）：
 *   - /0/virt/<rest>  → 虚拟重定向到 $CIRCUIT_TEST_STORAGE/0/real_dir/<rest>
 *                       （模块加载时 /0/virt/ 可见，卸载/熔断后消失 → 行为化证据）
 *   - /0/errtest/*    → resolve 返回 -EIO（计熔断错误）
 *   - 其余路径        → valid=false（框架直通）
 *
 * 编译：gcc -shared -fPIC -O1 -DNSP_MODULE_BUILD -Iinclude bad_rules.c -o bad_rules.so
 * 第三方模块视角：仅依赖 nsp_module.h（docs/modules.md 契约）。
 */
#define _GNU_SOURCE
#include "nsp_module.h"
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>

static const char* test_storage(void) {
    const char* s = getenv("CIRCUIT_TEST_STORAGE");
    return (s && s[0]) ? s : "/tmp/fuse_circuit_test/storage";
}

static int bad_resolve(const NspQueryCtx* q, NspPathDecision* out) {
    if (!q || !out || !q->path) return -EINVAL;
    memset(out, 0, sizeof *out);
    const char* vp = q->path;
    /* 约定：规则虚拟前缀不含 user_id，FUSE 层路径形如 /<uid>/<虚拟前缀>/... */
    if (vp[0] == '/' && vp[1] == '0' && vp[2] == '/') vp += 3;
    /* FUSE 按组件逐级 lookup：stat(/0/errtest/x) 先查 /0/errtest（无尾斜杠），
       故按组件名整体匹配（"errtest" 或 "errtest/..."） */
    /* 错误路径：计一次熔断错误。注意——内核对失败 lookup 缓存负向 dentry，
       同名路径只触达模块一次；测试用 errtest0..N 不同组件名模拟真实
       错误风暴（每个新组件名都会重新进入 resolve），故按前缀匹配。 */
    if (strncmp(vp, "errtest", 7) == 0) return -EIO;
    if (strncmp(vp, "virt/", 5) == 0 || strcmp(vp, "virt") == 0) {
        const char* rest = (vp[4] == '/') ? vp + 5 : "";
        snprintf(out->real_path, sizeof out->real_path, "%s/0/real_dir/%s", test_storage(), rest);
        snprintf(out->pkg, sizeof out->pkg, "test");
        out->valid = true;
        out->is_redirect = true;
        return 0;
    }
    return 0; /* 其余路径：合法"无命中"（框架直通） */
}

static int bad_probe(const NspQueryCtx* q, NspProbeResult* out) {
    if (!q || !out) return -EINVAL;
    memset(out, 0, sizeof *out);
    out->valid = false; /* 不逐条目过滤 */
    return 0;
}

static const NspModuleOps bad_ops = {
    .resolve = bad_resolve,
    .probe = bad_probe,
};

/* 模块导出的是**数据符号**（全局 NspModuleInfo 结构体），loader 经 dlsym
   后直接强转 NspModuleInfo* 读取——不是函数。name 必须与目录名一致。 */
const NspModuleInfo nsp_module_info = {
    .magic = NSP_MODULE_MAGIC,
    .abi_version = NSP_MODULE_ABI_VERSION,
    .type = NSP_MODULE_TYPE_RULES,
    .caps = NSP_CAP_REDIRECT,
    .name = "bad_rules",
    .version = "1.0",
    .init = NULL,
    .exit = NULL,
    .ops = &bad_ops,
};
