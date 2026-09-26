#!/usr/bin/env python3
"""模块 ABI 契约回归：固定栈填充值、直通默认值、稀疏输出、V1/V2/V3 拒绝加载。"""
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

static void check_defaults(const NspPathDecision* r) {
    assert(!r->valid && !r->appear_missing && !r->read_only);
    assert(!r->is_redirect && !r->is_ftp);
    assert(r->virtual_kind == NSP_VK_NONE);
    /* 属性覆盖默认全关：模块 memset 零初始化即"不改任何属性" */
    assert(r->attr_override == 0);
    assert(!r->real_path[0]);
}
int main(int argc, char** argv) {
    assert(argc == 2);
    _Static_assert(NSP_MODULE_ABI_VERSION == 4u, "更新 ABI 契约测试");
    _Static_assert(NSP_FRAMEWORK_API_VERSION == 4u, "更新框架 API 版本契约测试");
    _Static_assert(NSP_OV_ALL == 7u, "属性覆盖位图契约");
    NspPathDecision r;
    memset(&r, 0xa5, sizeof r);
    NspQueryCtx q = {.uid = 1000, .pid = 1, .path = "/0/missing"};
    assert(module_dispatch_resolve(&q, &r) == NSP_DISPATCH_NONE);
    check_defaults(&r);
    memset(&r, 0xa5, sizeof r);
    assert(module_dispatch_resolve(NULL, &r) == NSP_DISPATCH_NONE);
    check_defaults(&r);
    NspDecisionGuard guard;
    memset(&guard, 0xa5, sizeof guard);
    nsp_guard_decision_init(&guard);
    check_defaults(&guard.r);
    assert(nsp_guard_decision_ok(&guard));
    guard.back++;
    assert(!nsp_guard_decision_ok(&guard));
    /* 输出校验：越界 virtual_kind / 未知 attr_override 位必须被判非法
       （否则框架会走进未定义分支或误用未初始化字段） */
    char det[64];
    NspPathDecision bad;
    nsp_decision_init(&bad);
    bad.valid = true;
    assert(nsp_guard_validate_decision(&bad, det, sizeof det) == 0);
    bad.virtual_kind = 200;
    assert(nsp_guard_validate_decision(&bad, det, sizeof det) != 0);
    bad.virtual_kind = NSP_VK_TARGET;
    bad.attr_override = 1u << 20;
    assert(nsp_guard_validate_decision(&bad, det, sizeof det) != 0);
    bad.attr_override = NSP_OV_MODE;
    /* mode 不做值域拒绝：框架只取 07777，故 stat 风格写法（带 S_IFMT）也合法 */
    bad.mode = S_IFDIR | 0755;
    assert(nsp_guard_validate_decision(&bad, det, sizeof det) == 0);
    bad.attr_override = NSP_OV_UID;
    bad.uid = -1;
    assert(nsp_guard_validate_decision(&bad, det, sizeof det) != 0);
    fault_fence_init();
    module_guard_init();
    assert(module_system_init(NULL, argv[1], 0) == 0);
    /* V1（信息头布局不同）/V2/V3（决策结构与 ops 表不兼容）都必须被加载器
       拒绝：只剩 sparse 一个模块。V4 删了 pkg/monitor_on/get_pkg，放行旧版本
       会让模块按旧布局写、框架按新布局读，静默错乱 */
    char names[MAX_MODULES][64];
    assert(module_snapshot(names, MAX_MODULES) == 1);
    assert(strcmp(names[0], "sparse") == 0);
    memset(&r, 0xa5, sizeof r);
    assert(module_dispatch_resolve(&q, &r) == NSP_DISPATCH_OK);
    assert(r.valid && r.appear_missing);
    assert(!r.read_only && !r.is_redirect && !r.is_ftp);
    assert(r.virtual_kind == NSP_VK_NONE && r.attr_override == 0);
    assert(!r.real_path[0]);
    q.path = "/";
    memset(&r, 0xa5, sizeof r);
    assert(module_dispatch_resolve(&q, &r) == NSP_DISPATCH_NONE);
    check_defaults(&r);
    puts("模块 V4 契约检查通过：默认值、空查询、根路径、canary、稀疏输出、"
         "输出校验、V1/V2/V3 拒绝");
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
static int resolve(const NspQueryCtx* q, NspPathDecision* out) {
    out->valid = true;
    out->appear_missing = true;
    return 0;
}
static const NspModuleOps ops = {.resolve = resolve};
const NspModuleInfo nsp_module_info = {
    .magic = NSP_MODULE_MAGIC, .abi_version = NSP_MODULE_ABI_VERSION,
    .type = NSP_MODULE_TYPE_RULES, .caps = NSP_CAP_HIDE,
    .name = "sparse", .version = "2", .ops = &ops
};
'''

OLD_MOD = r'''
#include "nsp_module.h"
/* 旧版本模块：NspModuleInfo 布局与新版相同，只有 abi_version 不同。加载器必须
   在 dlopen 之后、init/ops 之前按版本拒绝——V3 改了决策结构、V4 又删了
   pkg/monitor_on 与 ops.get_pkg，放行会让模块按旧布局写而框架按新布局读，
   静默错乱。此处按 {ver} 生成 V2/V3 两个样本。 */
static int forbidden_init(const NspFrameworkApi* api) {{ (void)api; abort(); }}
const NspModuleInfo nsp_module_info = {{
    .magic = NSP_MODULE_MAGIC, .abi_version = {ver}u,
    .type = NSP_MODULE_TYPE_RULES, .caps = NSP_CAP_HIDE,
    .name = "{name}", .version = "{ver}", .init = forbidden_init, .ops = (const void*)1
}};
'''


def main():
    cc = shlex.split(os.environ.get("CC", "cc"))
    with tempfile.TemporaryDirectory(prefix="nsp-abi-test-") as tmp:
        tmp = Path(tmp)
        modules = tmp / "modules"
        old_mods = (("v2old", OLD_MOD.format(ver=2, name="v2old")),
                    ("v3old", OLD_MOD.format(ver=3, name="v3old")))
        for name, text in (("legacy", LEGACY), *old_mods, ("sparse", SPARSE)):
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
                   "src/core/nsp_comm.c", "src/core/sha256.c", "src/core/sha256_hw.c",
                   # 框架侧配置持有者及其读取依赖（loader → fw_config → config_read_view）
                   # fw_pkg.c 是 fw_config 自建索引/ MONITOR 合并的 uid→包名输入
                   "src/daemon/fw_config.c", "src/daemon/fw_pkg.c",
                   "src/config/config_parser.c",
                   "src/config/path_vars.c", "src/core/path_trie.c", "src/core/uid_map.c",
                   "src/core/sys_pkg.c", "src/core/fast_search.c", "src/core/fast_pid.c"]
        binary = tmp / "contract"
        subprocess.run(cc + ["-std=c23", "-O2", "-D_GNU_SOURCE", "-DTARGET_GNU=1",
                             "-ftrivial-auto-var-init=pattern", "-I" + str(ROOT / "include"),
                             str(source)] + [str(ROOT / s) for s in sources] +
                       ["-pthread", "-ldl", "-Wl,--export-dynamic", "-o", str(binary)],
                       check=True)
        subprocess.run([str(binary), str(modules)], check=True, timeout=20)


if __name__ == "__main__":
    main()
