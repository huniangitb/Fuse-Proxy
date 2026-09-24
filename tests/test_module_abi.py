#!/usr/bin/env python3
"""模块 V2 契约回归：固定栈填充值、直通默认值、稀疏输出与 V1 拒绝加载。"""
import os
from pathlib import Path
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]

HARNESS = r'''
#include "module_loader.h"
#include "module_guard.h"
#include "fault_fence.h"
#include "common.h"
#include <assert.h>

static void check_defaults(const NspResolveResult* r) {
    assert(!r->valid && r->user_id == -1);
    assert(!r->hidden && !r->ro && !r->is_redir && !r->is_ftp && !r->monitor_on);
    assert(!r->is_virtual_ancestor && !r->is_redirect_target);
    assert(!r->sub_path[0] && !r->real_path[0] && !r->pkg[0]);
}
int main(int argc, char** argv) {
    assert(argc == 2);
    _Static_assert(NSP_MODULE_ABI_VERSION == 2u, "更新 ABI 契约测试");
    NspResolveResult r;
    memset(&r, 0xa5, sizeof r);
    NspQueryCtx q = {.uid = 1000, .pid = 1, .path = "/0/missing"};
    assert(module_dispatch_resolve(&q, &r) == NSP_DISPATCH_NONE);
    check_defaults(&r);
    memset(&r, 0xa5, sizeof r);
    assert(module_dispatch_resolve(NULL, &r) == NSP_DISPATCH_NONE);
    check_defaults(&r);
    NspResolveGuard guard;
    memset(&guard, 0xa5, sizeof guard);
    nsp_guard_resolve_init(&guard);
    check_defaults(&guard.r);
    assert(nsp_guard_resolve_ok(&guard));
    guard.back++;
    assert(!nsp_guard_resolve_ok(&guard));
    fault_fence_init();
    module_guard_init();
    assert(module_system_init(NULL, argv[1], 0) == 0);
    char names[MAX_MODULES][64];
    assert(module_snapshot(names, MAX_MODULES) == 1);
    assert(strcmp(names[0], "sparse") == 0);
    memset(&r, 0xa5, sizeof r);
    assert(module_dispatch_resolve(&q, &r) == NSP_DISPATCH_OK);
    assert(r.valid && r.hidden);
    assert(!r.ro && !r.is_redir && !r.is_ftp && !r.monitor_on);
    assert(!r.is_virtual_ancestor && !r.is_redirect_target);
    assert(!r.pkg[0] && !r.sub_path[0] && !r.real_path[0]);
    q.path = "/";
    memset(&r, 0xa5, sizeof r);
    assert(module_dispatch_resolve(&q, &r) == NSP_DISPATCH_NONE);
    check_defaults(&r);
    puts("模块 V2 契约检查通过：默认值、空查询、根路径、canary、稀疏输出、V1 拒绝");
    return 0;
}
'''

LEGACY = r'''
#include <stdint.h>
#include <stdlib.h>
/* V1 的信息头布局独立冻结，不能用 V2 头模拟旧结构。 */
struct LegacyInfo {
    uint32_t magic, abi_version, type, caps;
    const char *name, *version;
    int (*init)(const void*);
    void (*exit)(void);
    const void* ops;
};
static int forbidden_init(const void* api) { abort(); }
const struct LegacyInfo nsp_module_info = {
    .magic = 0x4E53504Du, .abi_version = 1, .type = 1, .caps = 4,
    .name = "legacy", .version = "1", .init = forbidden_init,
    .ops = (const void*)1
};
'''

SPARSE = r'''
#include "nsp_module.h"
static int resolve(const NspQueryCtx* q, NspResolveResult* out) {
    out->valid = true;
    out->hidden = true;
    return 0;
}
static const NspModuleOps ops = {.resolve = resolve};
const NspModuleInfo nsp_module_info = {
    .magic = NSP_MODULE_MAGIC, .abi_version = NSP_MODULE_ABI_VERSION,
    .type = NSP_MODULE_TYPE_RULES, .caps = NSP_CAP_HIDE,
    .name = "sparse", .version = "2", .ops = &ops
};
'''


def main():
    cc = shlex.split(os.environ.get("CC", "cc"))
    with tempfile.TemporaryDirectory(prefix="nsp-abi-test-") as tmp:
        tmp = Path(tmp)
        modules = tmp / "modules"
        for name, text in (("legacy", LEGACY), ("sparse", SPARSE)):
            folder = modules / name
            folder.mkdir(parents=True)
            source = tmp / f"{name}.c"
            source.write_text(text)
            subprocess.run(cc + ["-std=c23", "-shared", "-fPIC", "-DNSP_MODULE_BUILD",
                                 "-I" + str(ROOT / "include"), str(source), "-o",
                                 str(folder / f"{name}.so")], check=True)
        source = tmp / "contract.c"
        source.write_text(HARNESS)
        sources = ["src/module/loader.c", "src/module/module_guard.c",
                   "src/module/fault_fence.c", "src/core/common.c", "src/core/nsp_util.c",
                   "src/core/nsp_comm.c", "src/core/sha256.c", "src/core/sha256_hw.c"]
        binary = tmp / "contract"
        subprocess.run(cc + ["-std=c23", "-O2", "-D_GNU_SOURCE", "-DTARGET_GNU=1",
                             "-ftrivial-auto-var-init=pattern", "-I" + str(ROOT / "include"),
                             str(source)] + [str(ROOT / s) for s in sources] +
                       ["-pthread", "-ldl", "-Wl,--export-dynamic", "-o", str(binary)],
                       check=True)
        subprocess.run([str(binary), str(modules)], check=True, timeout=20)


if __name__ == "__main__":
    main()
