#define _GNU_SOURCE
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

    // 如果 Needle 太短或太长，降级使用标准算法，避免边界检测开销
    if (needle_len < 2 || needle_len > 128) {
        return strstr(haystack, needle);
    }

    const uint8_t* h = (const uint8_t*)haystack;
    size_t max_search_len = haystack_len - needle_len + 1;
    
    uint8_t c0 = needle[0];
    uint8_t c1 = needle[needle_len - 1];
    
    // 向量化加载特征对比字符
    uint8x16_t v_c0 = vdupq_n_u8(c0);
    uint8x16_t v_c1 = vdupq_n_u8(c1);
    
    size_t i = 0;
    // 每次并行处理 16 字节（ARM64 Advanced SIMD / NEON 硬件加速）
    for (; i + 15 < max_search_len; i += 16) {
        // 加载当前偏移处的 16 字节
        uint8x16_t v_data0 = vld1q_u8(h + i);
        // 并行加载对应偏置（needle_len - 1）处的 16 字节
        uint8x16_t v_data1 = vld1q_u8(h + i + needle_len - 1);
        
        // 并行对比特征
        uint8x16_t v_match0 = vceqq_u8(v_data0, v_c0);
        uint8x16_t v_match1 = vceqq_u8(v_data1, v_c1);
        
        // 双特征交集筛选
        uint8x16_t v_match = vandq_u8(v_match0, v_match1);
        
        // 提取并验证，利用 vmaxvq_u8 汇总匹配掩码，有任意匹配则大于 0
        if (vmaxvq_u8(v_match) > 0) {
            // 对具有匹配潜力的槽位做局部的 strcmp 精确匹配
            for (size_t j = 0; j < 16; ++j) {
                if (h[i + j] == c0 && h[i + j + needle_len - 1] == c1) {
                    if (memcmp(h + i + j, needle, needle_len) == 0) {
                        return (const char*)(h + i + j);
                    }
                }
            }
        }
    }
    
    // 处理末尾少于 16 字节的对齐残余部分
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
// 非 ARM64 平台，无缝兼容降级至标准库
const char* fast_strstr(const char* haystack, const char* needle) {
    return strstr(haystack, needle);
}
#endif