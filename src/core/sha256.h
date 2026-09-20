#ifndef NSP_SHA256_H
#define NSP_SHA256_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 极简 SHA-256（FIPS 180-4），供模块加载哈希校验使用 */
typedef struct {
    uint32_t state[8];
    uint64_t len; /* 已处理字节数 */
    uint8_t buf[64];
    size_t buflen;
} Sha256Ctx;

void sha256_init(Sha256Ctx* c);
void sha256_update(Sha256Ctx* c, const void* data, size_t len);
void sha256_final(Sha256Ctx* c, uint8_t out[32]);
void sha256_buf(const void* data, size_t len, uint8_t out[32]);

/* 计算文件的 SHA-256 十六进制摘要（open/read/close，fd 用后即关，
   不长期持有磁盘模块文件句柄）。成功返回 0，失败返回 -1。 */
int sha256_file_hex(const char* path, char out_hex[65]);

#ifdef __cplusplus
}
#endif

#endif /* NSP_SHA256_H */
