#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "fast_search.h"
#include <string.h>
#if defined(__aarch64__)
#include <arm_neon.h>
const char* fast_strstr(const char* haystack, const char* needle) {
    if (!haystack || !needle) return nullptr;
    size_t needle_len = strlen(needle);
    if (needle_len == 0) return haystack;
    size_t haystack_len = strlen(haystack);
    if (haystack_len < needle_len) return nullptr;
    /* 短/超长 needle 走标准算法：省掉边界检测开销 */
    if (needle_len < 2 || needle_len > 128) {
        return strstr(haystack, needle);
    }
    const uint8_t* h = (const uint8_t*)haystack;
    size_t max_search_len = haystack_len - needle_len + 1;
    uint8_t c0 = needle[0];
    uint8_t c1 = needle[needle_len - 1];
    uint8x16_t v_c0 = vdupq_n_u8(c0);
    uint8x16_t v_c1 = vdupq_n_u8(c1);
    size_t i = 0;
    // 每次并行处理 16 字节（ARM64 Advanced SIMD / NEON 硬件加速）
    for (; i + 15 < max_search_len; i += 16) {
        uint8x16_t v_data0 = vld1q_u8(h + i);
        uint8x16_t v_data1 = vld1q_u8(h + i + needle_len - 1);
        uint8x16_t v_match0 = vceqq_u8(v_data0, v_c0);
        uint8x16_t v_match1 = vceqq_u8(v_data1, v_c1);
        uint8x16_t v_match = vandq_u8(v_match0, v_match1);
        /* vmaxvq_u8 汇总匹配掩码：有任意匹配才进逐槽 strcmp 精确比对 */
        if (vmaxvq_u8(v_match) > 0) {
            for (size_t j = 0; j < 16; ++j) {
                if (h[i + j] == c0 && h[i + j + needle_len - 1] == c1) {
                    if (memcmp(h + i + j, needle, needle_len) == 0) {
                        return (const char*)(h + i + j);
                    }
                }
            }
        }
    }
    for (; i < max_search_len; ++i) {
        if (h[i] == c0 && h[i + needle_len - 1] == c1) {
            if (memcmp(h + i, needle, needle_len) == 0) {
                return (const char*)(h + i);
            }
        }
    }
    return nullptr;
}
#else
const char* fast_strstr(const char* haystack, const char* needle) {
    return strstr(haystack, needle);
}
#endif