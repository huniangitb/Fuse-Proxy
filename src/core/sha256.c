/* 极简 SHA-256（FIPS 180-4）实现：供模块加载哈希校验使用。
   公共域风格实现，无外部依赖。块处理支持硬件加速（ARMv8 SHA2 /
   x86 SHA-NI，见 sha256_hw.c）——能力可用且自校验通过时自动启用。 */
#include "sha256.h"
#include "sha256_hw.h"
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static inline uint32_t rotr32(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

void sha256_init(Sha256Ctx* c) {
    c->state[0] = 0x6a09e667; c->state[1] = 0xbb67ae85;
    c->state[2] = 0x3c6ef372; c->state[3] = 0xa54ff53a;
    c->state[4] = 0x510e527f; c->state[5] = 0x9b05688c;
    c->state[6] = 0x1f83d9ab; c->state[7] = 0x5be0cd19;
    c->len = 0;
    c->buflen = 0;
}

static void sha256_block(Sha256Ctx* c, const uint8_t* p) {
    uint32_t w[64];
    int i;
    for (i = 0; i < 16; i++)
        w[i] = ((uint32_t)p[i * 4] << 24) | ((uint32_t)p[i * 4 + 1] << 16) |
               ((uint32_t)p[i * 4 + 2] << 8) | (uint32_t)p[i * 4 + 3];
    for (i = 16; i < 64; i++) {
        uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = c->state[0], b = c->state[1], cc = c->state[2], d = c->state[3];
    uint32_t e = c->state[4], f = c->state[5], g = c->state[6], h = c->state[7];
    for (i = 0; i < 64; i++) {
        uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t t1 = h + S1 + ch + K[i] + w[i];
        uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & cc) ^ (b & cc);
        uint32_t t2 = S0 + maj;
        h = g; g = f; f = e; e = d + t1; d = cc; cc = b; b = a; a = t1 + t2;
    }
    c->state[0] += a; c->state[1] += b; c->state[2] += cc; c->state[3] += d;
    c->state[4] += e; c->state[5] += f; c->state[6] += g; c->state[7] += h;
}

void sha256_update(Sha256Ctx* c, const void* data, size_t len) {
    const uint8_t* p = (const uint8_t*)data;
    c->len += len;
    if (c->buflen) {
        size_t need = 64 - c->buflen;
        if (len < need) {
            memcpy(c->buf + c->buflen, p, len);
            c->buflen += len;
            return;
        }
        memcpy(c->buf + c->buflen, p, need);
        sha256_block(c, c->buf);
        p += need;
        len -= need;
        c->buflen = 0;
    }
    /* 硬件加速：能力可用且自校验通过时，整批块走 sha256h/SHA-NI */
    if (sha256_hw_available()) {
        size_t nb = len / 64;
        if (nb) {
            sha256_hw_blocks(c->state, p, nb);
            p += nb * 64;
            len -= nb * 64;
        }
    }
    while (len >= 64) {
        sha256_block(c, p);
        p += 64;
        len -= 64;
    }
    if (len) {
        memcpy(c->buf, p, len);
        c->buflen = len;
    }
}

void sha256_final(Sha256Ctx* c, uint8_t out[32]) {
    uint64_t bits = c->len * 8;
    uint8_t pad = 0x80;
    uint8_t z = 0;
    uint8_t lenb[8];
    int i;
    sha256_update(c, &pad, 1);
    while (c->buflen != 56)
        sha256_update(c, &z, 1);
    for (i = 0; i < 8; i++)
        lenb[i] = (uint8_t)(bits >> (56 - i * 8));
    sha256_update(c, lenb, 8);
    for (i = 0; i < 8; i++) {
        out[i * 4]     = (uint8_t)(c->state[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(c->state[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(c->state[i] >> 8);
        out[i * 4 + 3] = (uint8_t)c->state[i];
    }
}

void sha256_buf(const void* data, size_t len, uint8_t out[32]) {
    Sha256Ctx c;
    sha256_init(&c);
    sha256_update(&c, data, len);
    sha256_final(&c, out);
}

int sha256_file_hex(const char* path, char out_hex[65]) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    Sha256Ctx c;
    uint8_t buf[8192];
    uint8_t d[32];
    ssize_t n;
    int i;
    if (fd < 0) return -1;
    sha256_init(&c);
    while ((n = read(fd, buf, sizeof buf)) > 0)
        sha256_update(&c, buf, (size_t)n);
    close(fd);   /* fd 用后即关：不长期持有磁盘模块文件句柄 */
    if (n < 0) return -1;
    sha256_final(&c, d);
    for (i = 0; i < 32; i++) {
        static const char* hex = "0123456789abcdef";
        out_hex[i * 2]     = hex[d[i] >> 4];
        out_hex[i * 2 + 1] = hex[d[i] & 15];
    }
    out_hex[64] = '\0';
    return 0;
}
