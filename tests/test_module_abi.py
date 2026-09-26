#!/usr/bin/env python3
"""模块 ABI 契约回归（V4 收窄版）：结构体布局/常量契约、旧版本（V1/V2/V3）拒载、
后端模块加载与 min 实现容忍。"""
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
#include <stddef.h>

int main(int argc, char** argv) {
    assert(argc == 2);
    _Static_assert(NSP_MODULE_ABI_VERSION == 4u, "更新 ABI 契约测试");
    _Static_assert(NSP_FRAMEWORK_API_VERSION == 4u, "更新框架 API 版本契约测试");
    /* V4 收窄后的布局契约（LP64）：NspModuleInfo = 2×u32 + 5×指针；
       NspModuleOps = 14 个后端方法指针。字段增删必须同时改这两处与版本号 */
    _Static_assert(sizeof(NspModuleInfo) == 48, "NspModuleInfo 布局变化");
    _Static_assert(sizeof(NspModuleOps) == 112, "NspModuleOps 布局变化");
    _Static_assert(offsetof(NspModuleOps, backend_match) == 0, "后端方法顺序契约");
    _Static_assert(offsetof(NspModuleOps, backend_getattr) == sizeof(void*), "后端方法顺序契约");
    /* 跨 ABI 的数据类型只剩 NspDirEntry（后端 readdir 回传条目） */
    _Static_assert(sizeof(NspDirEntry) == 257, "NspDirEntry 布局变化");

    fault_fence_init();
    module_guard_init();
    assert(module_system_init(NULL, argv[1]) == 0);
    /* V1（信息头布局不同）/V2/V3（决策结构与 ops 表不兼容）都必须被加载器
       拒绝——V4 把规则能力整体移出 ABI（ops 只剩 backend_*、info 去掉
       type/caps），放行旧版本会让模块按旧布局写、框架按新布局读，静默错乱 */
    char names[MAX_MODULES][64];
    assert(module_snapshot(names, MAX_MODULES) == 1);
    assert(strcmp(names[0], "bkmatch") == 0);
    /* 后端模块在册：backend_active 为真（框架热路径据此决定是否查后端） */
    assert(module_backend_active() == true);
    /* 只实现 backend_match 的最小模块不得被误判为异常（BADFN 容忍） */
    assert(module_any_loaded() == true);
    module_system_shutdown();
    puts("模块 V4 契约检查通过：结构布局、旧版本(V1/V2/V3)拒载、最小后端模块加载");
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

BACKEND = r'''
#include "nsp_module.h"
/* V4 唯一的模块形态：后端存储提供者。声明 backend_match 即被框架认作后端；
   这里刻意只实现 match（返回 0 不认领任何路径），用于验证"加载成功但不接管"。 */
static int bm_match(const char* path) { (void)path; return 0; }
static const NspModuleOps ops = {.backend_match = bm_match};
const NspModuleInfo nsp_module_info = {
    .magic = NSP_MODULE_MAGIC, .abi_version = NSP_MODULE_ABI_VERSION,
    .name = "bkmatch", .version = "4", .ops = &ops
};
'''

OLD_MOD = r'''
#include "nsp_module.h"
/* 旧版本模块：NspModuleInfo 布局与新版相同，只有 abi_version 不同。加载器必须
   在 dlopen 之后、init/ops 之前按版本拒绝——V3 换了决策结构、V4 又把规则能力
   整体移出 ABI（ops 只剩 backend_*、NspModuleInfo 去掉 type/caps），放行会让
   模块按旧布局写而框架按新布局读，静默错乱。此处按 {ver} 生成 V2/V3 两个样本。 */
static int forbidden_init(const NspFrameworkApi* api) {{ (void)api; abort(); }}
const NspModuleInfo nsp_module_info = {{
    .magic = NSP_MODULE_MAGIC, .abi_version = {ver}u,
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
        for name, text in (("legacy", LEGACY), *old_mods, ("bkmatch", BACKEND)):
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
                   # loader → fw_config →（内建引擎）fw_rules 的链路须一并链接
                   "src/daemon/fw_config.c", "src/daemon/fw_pkg.c", "src/daemon/fw_rules.c",
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
