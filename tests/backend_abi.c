/* backend_abi.c — ABI 校验 / 旧 ABI 残留回归用的测试模块。
 *
 * 声明的 ABI 由 -DNSP_TEST_ABI=<值> 指定（缺省 = 当前 ABI，即合法模块）：
 *   - 合法：放进模块目录应正常加载（用于验证 ban 不挡真更新：同名文件换了
 *     内容即哈希变化，必须放行）；
 *   - -DNSP_TEST_ABI=1（旧 ABI）：模拟设备上残留的旧 basic_rules.so——框架
 *     内建规则引擎后模块目录里的旧 .so 不随包更新消失，加载器每 5s 扫描一次
 *     就重试一次。修复前每次重试留一条 ERROR 并**泄漏一个内存副本 fd**
 *     （实测 1 个/5s，累积到 nofile 上限后 socket/open 全面 EMFILE），修复后
 *     加载前拒绝 + 按文件哈希落 ban + 只报一次。
 *
 * 不认领任何路径（backend_match 恒 0）：本模块只用于观测加载/拒绝路径本身。
 *
 * 编译：gcc -shared -fPIC -O1 -DNSP_MODULE_BUILD -Iinclude [-DNSP_TEST_ABI=1] \
 *          backend_abi.c -o backend_abi.so
 */
#define _GNU_SOURCE
#include "nsp_module.h"

#ifndef NSP_TEST_ABI
#define NSP_TEST_ABI NSP_MODULE_ABI_VERSION
#endif

static int ba_match(const char* path) {
    (void)path;
    return 0;
}

static const NspModuleOps ba_ops = {
    .backend_match = ba_match,
};

const NspModuleInfo nsp_module_info = {
    .magic = NSP_MODULE_MAGIC,
    .abi_version = NSP_TEST_ABI,
    .name = "backend_abi",
    .version = "1.0",
    .init = NULL,
    .exit = NULL,
    .ops = &ba_ops,
};
