#ifndef NSP_SHA256_HW_H
#define NSP_SHA256_HW_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 硬件加速 SHA-256：ARMv8 密码学扩展（sha256h）或 x86 SHA-NI。
   sha256_hw_available()：运行时能力检测（getauxval HWCAP_SHA2 /
   __builtin_cpu_supports("sha")）+ 已知向量自校验——硬件路径结果与
   标准摘要不一致时返回 0（永久回退纯软件实现，杜绝硬件 bug 造成错误哈希）。
   sha256_hw_blocks()：处理 nblocks 个 64 字节块，就地更新 8×32 位状态
   （与纯软件 Sha256Ctx.state 布局一致）。 */
int sha256_hw_available(void);
void sha256_hw_blocks(uint32_t state[8], const uint8_t* blocks, size_t nblocks);

#ifdef __cplusplus
}
#endif

#endif /* NSP_SHA256_HW_H */
