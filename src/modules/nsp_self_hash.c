/* 模块自哈希导出（模块加载兼容性 API）：
   模块运行时经 dladdr 获得自身文件路径，计算该文件的 SHA-256 摘要并上报。
   框架（loader.c）在 dlopen 新模块后调用此符号校验：
   - 框架计算的"文件哈希"与模块上报的"自哈希"不一致（文件在加载窗口内
     被写入/替换/篡改）→ 拒绝加载，保留内存中的旧模块；
   - 扫描热重载时框架另以"当前磁盘哈希 == 已加载模块存储哈希"判定内容
     未变化并跳过热重载。
   该 API 为可选（兼容性）：旧模块未导出此符号时，框架跳过自哈希校验。 */
#include <dlfcn.h>
#include <stddef.h>
#include "../core/sha256.h"

/* 模块上报的自哈希（hex 字符串，64+1 字节）。成功返回字符串，
   失败（dladdr 不可用/文件读取失败）返回 NULL。每次调用重新计算，
   保证反映调用时刻的文件内容（加载窗口内的写入可被检出）。 */
const char* nsp_module_self_hash(void) {
    Dl_info info;
    static char hex[65];
    if (dladdr((void*)&nsp_module_self_hash, &info) == 0 || !info.dli_fname) return NULL;
    if (sha256_file_hex(info.dli_fname, hex) != 0) return NULL;
    return hex;
}
