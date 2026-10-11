/*
 * test_module_cfg_push.py 专用 C 驱动（fixture）。
 *
 * 锁定「配置读取归属」这条 ABI 约定：模块**不读文件、不跑 inotify**——包括它
 * 自己的配置 `<modules_dir>/<模块名>/<模块名>.conf`。框架读入后以
 * `NSP_CFG_REC_MODULE_FILE` / `NSP_CFG_REC_MODULE_LINE` 记录下发，且**按 owner
 * 过滤**（只发给同名模块）。
 *
 * 旧实现（模块自读配置）：`config_read_view` 只读主文件 + App-rules，视图里
 * 没有任何 MODULE_* 记录 → 断言 1/2/3 全部失败（模块拿不到自己的配置）。
 *
 * 用法：module_cfg_push_driver <rules.conf> <modules_dir>
 * 输出：诊断行 + "PASS/FAIL ..." + "RESULT OK|FAIL"；退出码 0=通过 1=失败。
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config_parser.h"
#include "fw_config.h"

static int g_fail = 0;

static void check(bool ok, const char* what) {
    printf("  %s %s\n", ok ? "PASS" : "FAIL", what);
    if (!ok) g_fail++;
}

static void on_config(const NspModuleConfig* cfg) { (void)cfg; }

/* 在主视图里找某模块的标记；返回该标记之后连续 MODULE_LINE 的条数（-1 = 无标记） */
static int module_lines_after(const NspCfgRec* recs, int count, const char* mod,
                              const char** file_out, int* line_out) {
    for (int i = 0; i < count; i++) {
        if (recs[i].kind != NSP_CFG_REC_MODULE_FILE || !recs[i].text) continue;
        if (strcmp(recs[i].text, mod) != 0) continue;
        if (file_out) *file_out = recs[i].file;
        if (line_out) *line_out = recs[i].line_no;
        int n = 0;
        for (int j = i + 1; j < count; j++) {
            if (recs[j].kind == NSP_CFG_REC_MODULE_FILE) break;
            if (recs[j].kind == NSP_CFG_REC_MODULE_LINE) n++;
        }
        return n;
    }
    return -1;
}

/* 该模块的视图里是否出现指定文本行 */
static bool view_has_line(const NspModuleConfig* v, const char* text) {
    for (int i = 0; i < v->count; i++)
        if (v->recs[i].kind == NSP_CFG_REC_MODULE_LINE && v->recs[i].text &&
            strcmp(v->recs[i].text, text) == 0)
            return true;
    return false;
}

int main(int argc, char** argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <rules.conf> <modules_dir>\n", argv[0]);
        return 2;
    }
    const char* rules = argv[1];
    const char* modules = argv[2];

    /* 模块目录必须在首次读取之前设置（框架据此派生 <名>/<名>.conf 位置） */
    config_set_modules_dir(modules);
    if (fw_config_init(rules) != 0) {
        fprintf(stderr, "fw_config_init 失败\n");
        return 2;
    }

    NspCfgRec* recs = NULL;
    int count = 0;
    config_read_view(rules, &recs, &count);
    if (!recs || count <= 0) {
        printf("FAIL config_read_view 未产出记录\nRESULT FAIL\n");
        fw_config_shutdown();
        return 1;
    }

    char want_a[4096], want_b[4096], want_c[4096];
    snprintf(want_a, sizeof want_a, "%s/modA/modA.conf", modules);
    snprintf(want_b, sizeof want_b, "%s/modB/modB.conf", modules);
    snprintf(want_c, sizeof want_c, "%s/modC/modC.conf", modules);

    /* ---- 1. 有配置文件的模块：标记 + 逐行下发（含注释行与含 '#' 的值） ---- */
    const char* file_a = NULL;
    int line_a = 0;
    int na = module_lines_after(recs, count, "modA", &file_a, &line_a);
    check(na > 0, "modA 有 MODULE_FILE 标记且带 MODULE_LINE 行");
    check(file_a && strcmp(file_a, want_a) == 0, "modA 标记里的 file 是确切配置路径");
    bool saw_comment = false, saw_hash_value = false;
    for (int i = 0; i < count; i++) {
        if (recs[i].kind != NSP_CFG_REC_MODULE_LINE || !recs[i].text) continue;
        if (strcmp(recs[i].text, "# 注释行") == 0) saw_comment = true;
        if (strcmp(recs[i].text, "pass = p#ssw0rd") == 0) saw_hash_value = true;
    }
    /* 框架只去 \r\n 与首尾空白：注释与含 '#' 的值必须原样到达模块，
       否则模块的配置语法（`#` 只在行首/空白后起注释）就被框架改写了 */
    check(saw_comment, "注释行原样下发（框架不替模块剥注释）");
    check(saw_hash_value, "含 '#' 的值原样下发（不被框架截断）");

    /* ---- 2. 无配置文件的模块：标记仍下发（含期望路径），零行 ---- */
    const char* file_c = NULL;
    int nc = module_lines_after(recs, count, "modC", &file_c, NULL);
    check(nc == 0, "modC 无配置文件：标记仍下发且零行（模块据此报出确切路径）");
    check(file_c && strcmp(file_c, want_c) == 0, "modC 标记里的 file 是期望路径");

    /* ---- 3. owner 隔离：A 的视图看不到 B 的行，反之亦然 ----
       且订阅一个不存在的规则类型（NONEXISTENT）不得影响模块拿回自己的配置
       —— subscribe_rules 只过滤 RULE 记录。 */
    fw_config_set_listener("modA", on_config);
    fw_config_set_listener("modB", on_config);
    {
        const char* types[] = {"NONEXISTENT"};
        fw_config_set_subscription("modA", types, 1);
        fw_config_set_subscription("modB", types, 1);
    }
    const NspModuleConfig* va = fw_config_view_acquire("modA");
    const NspModuleConfig* vb = fw_config_view_acquire("modB");
    check(va && vb, "两个模块的视图都能取到");
    if (va && vb) {
        check(view_has_line(va, "host = a.example.com"), "modA 视图含自己的配置行");
        check(!view_has_line(va, "host = b.example.com"), "modA 视图**不含** modB 的配置行");
        check(view_has_line(vb, "host = b.example.com"), "modB 视图含自己的配置行");
        check(!view_has_line(vb, "host = a.example.com"), "modB 视图**不含** modA 的配置行");
        /* 订阅了不存在的类型 → 视图里不应有任何 RULE 记录（隔离正对照） */
        bool any_rule = false;
        for (int i = 0; i < va->count; i++)
            if (va->recs[i].kind == NSP_CFG_REC_RULE) any_rule = true;
        check(!any_rule, "订阅不存在的类型：视图无 RULE 记录（订阅只管 RULE）");
    }
    fw_config_view_release(va);
    fw_config_view_release(vb);

    /* ---- 4. 模块配置不得污染框架自身索引（MODULE_LINE 不是规则） ----
       主文件里恰好 1 条 HIDE；模块配置里也写了 1 条 HIDE，若被当规则解析
       hide_count 就会变成 2。 */
    check(g_global_cfg.hide_count == 1,
          "框架 AppConfig 只含主文件的规则（模块配置行不被当规则解析）");

    (void)line_a;
    config_free_view(recs, count);
    fw_config_shutdown();
    printf("%s\n", g_fail == 0 ? "RESULT OK" : "RESULT FAIL");
    return g_fail == 0 ? 0 : 1;
}
