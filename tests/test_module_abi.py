#!/usr/bin/env python3
"""模块 ABI 契约回归（V5 分页版）：结构体布局/常量契约、旧版本（V1/V2/V3/V4）拒载、
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
    _Static_assert(NSP_MODULE_ABI_VERSION == 5u, "更新 ABI 契约测试");
    _Static_assert(NSP_FRAMEWORK_API_VERSION == 4u, "更新框架 API 版本契约测试");
    /* V5 截断收敛后的布局契约（LP64）：NspModuleInfo = 2×u32 + 5×指针；
       NspModuleOps = 14 个后端方法指针（backend_readdir 加 offset 参数不改变
       指针数量与结构大小）。字段增删必须同时改这两处与版本号 */
    _Static_assert(sizeof(NspModuleInfo) == 48, "NspModuleInfo 布局变化");
    _Static_assert(sizeof(NspModuleOps) == 112, "NspModuleOps 布局变化");
    _Static_assert(offsetof(NspModuleOps, backend_match) == 0, "后端方法顺序契约");
    _Static_assert(offsetof(NspModuleOps, backend_getattr) == sizeof(void*), "后端方法顺序契约");
    /* 跨 ABI 的数据类型只剩 NspDirEntry（后端 readdir 回传条目） */
    _Static_assert(sizeof(NspDirEntry) == 257, "NspDirEntry 布局变化");

    fault_fence_init();
    module_guard_init();
    assert(module_system_init(NULL, argv[1]) == 0);
    /* V1（信息头布局不同）/V2/V3（决策结构与 ops 表不兼容）/V4（readdir 无
       offset 分页，大目录静默丢尾）都必须被加载器拒绝——V5 前任一版本放行，
       都会让模块按旧布局/旧签名读写而框架按新契约调用，静默错乱 */
    char names[MAX_MODULES][64];
    assert(module_snapshot(names, MAX_MODULES) == 1);
    assert(strcmp(names[0], "bkmatch") == 0);
    /* 后端模块在册：backend_active 为真（框架热路径据此决定是否查后端） */
    assert(module_backend_active() == true);
    /* 只实现 backend_match 的最小模块不得被误判为异常（BADFN 容忍） */
    assert(module_any_loaded() == true);
    module_system_shutdown();
    puts("模块 V5 契约检查通过：结构布局、旧版本(V1/V2/V3/V4)拒载、最小后端模块加载");
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
/* V5 唯一的模块形态：后端存储提供者。声明 backend_match 即被框架认作后端；
   这里刻意只实现 match（返回 0 不认领任何路径），用于验证"加载成功但不接管"。 */
static int bm_match(const char* path) { (void)path; return 0; }
static const NspModuleOps ops = {.backend_match = bm_match};
const NspModuleInfo nsp_module_info = {
    .magic = NSP_MODULE_MAGIC, .abi_version = NSP_MODULE_ABI_VERSION,
    .name = "bkmatch", .version = "5", .ops = &ops
};
'''

OLD_MOD = r'''
#include "nsp_module.h"
/* 旧版本模块：NspModuleInfo 布局与新版相同，只有 abi_version 不同。加载器必须
   在 dlopen 之后、init/ops 之前按版本拒绝——V3 换了决策结构、V4 把规则能力
   整体移出 ABI（ops 只剩 backend_*、NspModuleInfo 去掉 type/caps）、V5 给
   backend_readdir 加 offset 分页（旧模块大目录静默丢尾），放行会让模块按旧
   契约读写而框架按新契约调用，静默错乱。此处按 {ver} 生成 V2/V3/V4 三个样本。 */
static int forbidden_init(const NspFrameworkApi* api) {{ (void)api; abort(); }}
const NspModuleInfo nsp_module_info = {{
    .magic = NSP_MODULE_MAGIC, .abi_version = {ver}u,
    .name = "{name}", .version = "{ver}", .init = forbidden_init, .ops = (const void*)1
}};
'''


GROWTH = r'''
#include "module_loader.h"
#include "module_guard.h"
#include "fault_fence.h"
#include "common.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
/* 注册表增长回归：20 个后端模块（> 初容 16）须全部加载，高水位后槽位
   （如 19）分派正常——旧实现第 17 个起静默拒载。 */
int main(int argc, char** argv) {
    assert(argc == 2);
    fault_fence_init();
    module_guard_init();
    assert(module_system_init(NULL, argv[1]) == 0);
    char names[64][64];
    int n = module_snapshot(names, 64);
    assert(n == 20);
    assert(module_backend_active() == true);
    const NspModuleOps* ops = NULL;
    assert(module_backend_lookup("/g19/x", &ops) == 0 && ops != NULL);
    assert(ops->backend_match("/g19/x") == 1);
    module_backend_put(ops);
    assert(module_backend_lookup("/g7/y", &ops) == 0 && ops != NULL);
    module_backend_put(ops);
    module_system_shutdown();
    puts("注册表增长检查通过：20 模块全加载 + 高水位槽位分派正常");
    return 0;
}
'''

GROW_MOD = r'''
#include "nsp_module.h"
#include <string.h>
/* 增长回归用最小后端：认领 /g{idx} 前缀（idx 烘焙进名字与匹配串）。 */
static int gm_match(const char* path) {{
    static const char want[] = "/g{idx}";
    size_t n = sizeof want - 1;
    return strncmp(path, want, n) == 0 && (path[n] == '/' || path[n] == '\0') ? 1 : 0;
}}
static const NspModuleOps ops = {{.backend_match = gm_match}};
const NspModuleInfo nsp_module_info = {{
    .magic = NSP_MODULE_MAGIC, .abi_version = NSP_MODULE_ABI_VERSION,
    .name = "grow{idx:02d}", .version = "5", .ops = &ops
}};
'''


def main():
    cc = shlex.split(os.environ.get("CC", "cc"))
    with tempfile.TemporaryDirectory(prefix="nsp-abi-test-") as tmp:
        tmp = Path(tmp)
        modules = tmp / "modules"
        old_mods = (("v2old", OLD_MOD.format(ver=2, name="v2old")),
                    ("v3old", OLD_MOD.format(ver=3, name="v3old")),
                    ("v4old", OLD_MOD.format(ver=4, name="v4old")))
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
                   "src/core/nsp_comm.c",
                   # 框架侧配置持有者及其读取依赖（loader → fw_config → config_read_view）
                   # fw_pkg.c 是 fw_config 自建索引/ MONITOR 合并的 uid→包名输入
                   # loader → fw_config →（内建引擎）fw_rules 的链路须一并链接
                   "src/daemon/fw_config.c", "src/daemon/fw_pkg.c", "src/daemon/fw_rules.c",
                   # fw_config 的监听线程用 cfg_watch 对账 App-rules* 子目录 watch
                   "src/daemon/cfg_watch.c",
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
        # ── 增长回归：20 个模块（> 初容 16），同一 harness 二进制复用 ──
        gmods = tmp / "gmodules"
        for idx in range(20):
            name = f"grow{idx:02d}"
            folder = gmods / name
            folder.mkdir(parents=True)
            src = tmp / f"{name}.c"
            src.write_text(GROW_MOD.format(idx=idx))
            subprocess.run(cc + ["-std=c23", "-shared", "-fPIC", "-DNSP_MODULE_BUILD",
                                 "-I" + str(ROOT / "include"), str(src), "-o",
                                 str(folder / f"{name}.so")], check=True)
        gsrc = tmp / "growth.c"
        gsrc.write_text(GROWTH)
        gbinary = tmp / "growth"
        subprocess.run(cc + ["-std=c23", "-O2", "-D_GNU_SOURCE", "-DTARGET_GNU=1",
                             "-ftrivial-auto-var-init=pattern", "-I" + str(ROOT / "include"),
                             str(gsrc)] + [str(ROOT / s) for s in sources] +
                       ["-pthread", "-ldl", "-Wl,--export-dynamic", "-o", str(gbinary)],
                       check=True)
        subprocess.run([str(gbinary), str(gmods)], check=True, timeout=60)


if __name__ == "__main__":
    main()
