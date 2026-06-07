#ifndef FAST_SEARCH_H
#define FAST_SEARCH_H

#include <stddef.h>

/**
 * 针对 ARM64 Advanced SIMD (NEON) 优化的极速子串检索算法
 * 在大规模文本检索（如 mountinfo 匹配）时比标准 strstr 快数倍
 */
const char* fast_strstr(const char* haystack, const char* needle);

#endif