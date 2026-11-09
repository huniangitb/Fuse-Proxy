/* SPDX-License-Identifier: GPL-3.0-or-later */
/* 版权所有 (C) 2026 huniangitb <3361107168@qq.com> */
/*
 * post_wait.h — post-specialize 等待预算的解析（模块与测试共用）
 *
 * injector 在 pre-specialize 的 DEFER 应答里带一个数字：
 *   "DEFER <ms>"  带预算的 injector（模块 proto >= 4）
 *   "DEFER"       旧 injector，没有预算 → 按 0 处理
 * 0 表示不等待，此时模块一次 /proc/self/mountinfo 都不读。
 *
 * 预算为什么由 injector 给而不是模块写死：读一份 mountinfo 的成本与挂载表条目数
 * 成正比（小表设备零点几毫秒，大表设备几十毫秒），同一个固定值在两类设备上就是
 * 「白等到预算烧完」与「读一次就浪费几十毫秒」的差别。下发一个数字就能同时覆盖
 * 阻塞（>0）与非阻塞（0）两种行为，模块侧不需要两套实现、也不需要两份构建。
 *
 * 单独成文件是为了能被宿主测试直接编译（模块本体依赖 android/log.h，只能在
 * Android 交叉环境下编译）。
 */
#ifndef NSP_ZYGISK_POST_WAIT_H
#define NSP_ZYGISK_POST_WAIT_H

#include <stdlib.h>

/* 模块侧允许的最大预算，与 include/config_parser.h 的
   NSP_ZYGISK_POST_WAIT_MAX_MS 同值（模块不 include 项目头，故各写一份）。
   超限按上限截断：多写一个 0 不该把应用冻在 specialize 上几十秒。 */
#define NSP_POST_WAIT_MAX_MS 1000

/* "DEFER <ms>" → 预算毫秒；其余（裸 "DEFER"、OK、ERR、乱码）→ 0。
   负值与超上限都归一化，绝不返回负数（调用方用它做循环上界）。 */
static inline int nsp_post_wait_budget(const char* reply) {
    if (reply == NULL) return 0;
    /* 只认 DEFER 前缀：其余应答一律视为"不等待" */
    if (reply[0] != 'D' || reply[1] != 'E' || reply[2] != 'F' || reply[3] != 'E' ||
        reply[4] != 'R') {
        return 0;
    }
    const char* p = reply + 5;
    while (*p == ' ' || *p == '\t') ++p;
    if (*p == '\0') return 0;
    char* end = NULL;
    long v = strtol(p, &end, 10);
    if (end == p) return 0;
    if (v <= 0) return 0;
    if (v > NSP_POST_WAIT_MAX_MS) return NSP_POST_WAIT_MAX_MS;
    return (int)v;
}

#endif /* NSP_ZYGISK_POST_WAIT_H */
