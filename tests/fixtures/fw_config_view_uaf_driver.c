/*
 * test_fw_config_view.py 专用 C 驱动（fixture）。
 *
 * 锁定 A14：下发视图在「并发热重载」下必须保持有效。驱动复刻模块真实访问模式
 * ——acquire 一次视图，**先把 recs/count/generation 缓存到局部变量**，再触发一次
 * 真实重载（改写规则文件 → inotify → reload_once），最后访问缓存下来的 recs。
 *
 * 旧实现：fw_config_view_for 解锁后交出 &s->cfg（借用），reload_once 在同一临界区
 * 原地 free 掉 s->filtered 并改写 s->cfg —— 模块缓存下来的 recs 即已释放数组
 * （ASan 报 heap-use-after-free），且模块看到的 generation/recs 被并发改写
 * （快照契约被破坏）。
 *
 * 新实现：acquire 返回「不可变 + 引用计数」的快照，release 之前内容与 generation
 * 恒定，重载只换订阅表指针、旧快照延迟释放。
 *
 * 用法：fw_config_view_uaf_driver <rules.conf>
 * 输出：诊断行 + "PASS/FAIL ..." + "RESULT OK|FAIL"；退出码 0=通过 1=失败。
 */
#define _GNU_SOURCE
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fw_config.h"

static _Atomic int g_hook_fired = 0;
static void on_reload(void) { atomic_store(&g_hook_fired, 1); }

/* 模块的 config_update 监听器（本驱动不消费，仅用于创建订阅项） */
static void on_config(const NspModuleConfig* cfg) { (void)cfg; }

/* 逐字节读遍记录里的字符串（触及 recs 指向的内存；字符串可能为 NULL） */
static uint64_t checksum(const NspCfgRec* recs, int count) {
    uint64_t h = 1469598103934665603ULL;
    for (int i = 0; i < count; i++) {
        const char* fields[3] = {recs[i].file, recs[i].type, recs[i].text};
        for (int f = 0; f < 3; f++) {
            const unsigned char* p = (const unsigned char*)fields[f];
            if (!p) {
                h = (h ^ 0xffu) * 1099511628211ULL;
                continue;
            }
            for (; *p; p++) h = (h ^ *p) * 1099511628211ULL;
        }
    }
    return h;
}

static void write_rules(const char* path, int round) {
    FILE* f = fopen(path, "w");
    if (!f) return;
    /* 每轮内容都不同：重载后过滤视图的记录集合/文本必变 */
    fprintf(f, "[GLOBAL]\nMONITOR ON\nHIDE /nsp_round_%d_a\nHIDE /nsp_round_%d_b\n", round, round);
    fclose(f);
}

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <rules.conf>\n", argv[0]);
        return 2;
    }
    const char* rules = argv[1];
    if (fw_config_init(rules) != 0) {
        fprintf(stderr, "fw_config_init 失败\n");
        return 2;
    }
    /* 注册监听器（创建订阅项）并订阅 HIDE 规则；挂重载钩子（临界区之后触发，
       此刻旧实现已 free 掉旧数组） */
    fw_config_set_listener("testmod", on_config);
    {
        const char* types[] = {"HIDE"};
        fw_config_set_subscription("testmod", types, 1);
    }
    fw_config_set_reload_hook(on_reload);

    const NspModuleConfig* v = fw_config_view_acquire("testmod");
    if (!v) {
        printf("FAIL acquire 返回 NULL（订阅表未建视图）\nRESULT FAIL\n");
        return 1;
    }
    /* 模块真实访问模式：先缓存指针与代际 */
    const NspCfgRec* recs = v->recs;
    int count = v->count;
    uint64_t gen = v->generation;
    uint64_t sum0 = checksum(recs, count);
    printf("acquired: count=%d gen=%llu sum=%llu\n", count, (unsigned long long)gen,
           (unsigned long long)sum0);

    /* 触发真实重载：改写规则文件 → inotify → reload_once。首轮可能因监听线程
       尚未挂好 watch 而丢事件，故重试若干轮（每轮内容不同）。 */
    bool fired = false;
    for (int round = 1; round <= 8 && !fired; round++) {
        write_rules(rules, round);
        for (int i = 0; i < 40; i++) { /* 每轮最多等 2s */
            if (atomic_load(&g_hook_fired)) {
                fired = true;
                break;
            }
            usleep(50000);
        }
    }
    if (!fired) {
        printf("FAIL 重载未触发（inotify 未生效？）\nRESULT FAIL\n");
        fw_config_view_release(v);
        fw_config_shutdown();
        return 1;
    }

    /* 阶段 1：访问缓存下来的 recs（旧实现 = 已释放数组 → ASan heap-use-after-free） */
    uint64_t sum1 = checksum(recs, count);

    /* 阶段 2：快照不可变契约（确定性判据，无需 ASan）——重载不得改写本视图 */
    bool same_gen = (v->generation == gen);
    bool same_ptr = (v->recs == recs);
    bool same_cnt = (v->count == count);
    bool same_sum = (sum1 == sum0);
    printf("after reload: gen=%llu(同=%d) recs_ptr_same=%d count=%d(同=%d) sum_same=%d\n",
           (unsigned long long)v->generation, (int)same_gen, (int)same_ptr, v->count,
           (int)same_cnt, (int)same_sum);

    fw_config_view_release(v);
    fw_config_shutdown();

    bool ok = same_gen && same_ptr && same_cnt && same_sum;
    printf("%s\n", ok ? "PASS 视图在 release 前保持不变（不可变快照 + 引用计数）"
                      : "FAIL 视图被并发重载改写/释放（快照契约被破坏）");
    printf("%s\n", ok ? "RESULT OK" : "RESULT FAIL");
    return ok ? 0 : 1;
}
