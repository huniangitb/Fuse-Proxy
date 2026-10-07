/*
 * tests/fixtures/cfg_reload_split_driver.c
 *
 * C11 判别驱动：配置目录的事件必须按 ev->name 分流——uid.map / sys_pkgs.cache 这类
 * **非规则产物**只做轻量刷新，不得触发整份规则重载（重解析 + 重建 Trie + 作废
 * 2048 槽 uid 缓存 + 推送所有模块）；规则文件仍必须触发全量重载。
 *
 * 做法：直编 src/daemon/fw_config.c（-DFW_CONFIG_SRC，同 test_fw_config_view），
 * 并注册自己的 reload 钩子计数——驱动不链接 loader，钩子归驱动所有，故「钩子被
 * 调用次数」就是「全量重载次数」。随后依次改写三类文件，各等一个去抖窗口后打印
 * 累计次数；最后把规则文件重写为**逐字相同**内容，验证「无变化跳过发布」。
 *
 * 判别性：旧实现对任一事件都调 reload_once → 改写 uid.map 后计数 +1（期望 0），
 * 且规则文件重写为相同内容也会 +1（期望 0）。
 *
 * argv[1] = 规则文件路径（其所在目录即被 watch 的配置目录）
 * argv[2] = 配置目录（写 uid.map / sys_pkgs.cache 用；与编译期 CONFIG_DIR 一致）
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fw_config.h"

static int g_reloads;
static void count_hook(void) {
    g_reloads++;
}

static void write_file(const char* dir, const char* name, const char* content) {
    char p[1024];
    snprintf(p, sizeof p, "%s/%s", dir, name);
    FILE* f = fopen(p, "w");
    if (!f) {
        fprintf(stderr, "写 %s 失败\n", p);
        return;
    }
    fputs(content, f);
    fclose(f);
}

/* 去抖 1s + 事件读取与处理：留足余量 */
static void settle(void) {
    usleep(2500 * 1000);
}

int main(int argc, char** argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <rules.conf> <config_dir>\n", argv[0]);
        return 2;
    }
    const char* rules = argv[1];
    const char* dir = argv[2];
    if (fw_config_init(rules) != 0) {
        fprintf(stderr, "fw_config_init failed\n");
        return 2;
    }
    fw_config_set_reload_hook(count_hook);
    settle(); /* 让 init 期间的异步事件落定；钩子此后才开始计数 */
    int base = g_reloads;

    /* 1) uid.map 变更（injector 每启动一个应用都会写）→ 不得触发全量重载 */
    write_file(dir, "uid.map", "10123 com.demo.app\n");
    settle();
    int after_uidmap = g_reloads;

    /* 2) 规则文件变更 → 必须触发全量重载（正对照，防止"钩子根本没被调用"的伪通过） */
    write_file(dir, "injector.conf", "[GLOBAL]\nMONITOR ON\nHIDE /sdcard/x\n");
    settle();
    int after_rules = g_reloads;

    /* 3) sys_pkgs.cache 变更 → 不得触发全量重载 */
    write_file(dir, "sys_pkgs.cache", "com.android.systemui\n");
    settle();
    int after_syspkg = g_reloads;

    /* 4) 规则文件重写为**逐字相同**内容 → 不得再触发全量重载（C11：重解析后与
       旧视图比对无变化则跳过发布）。旧实现无条件发布，本组必失败。 */
    write_file(dir, "injector.conf", "[GLOBAL]\nMONITOR ON\nHIDE /sdcard/x\n");
    settle();
    int after_same = g_reloads;

    printf("base=%d after_uidmap=%d after_rules=%d after_syspkg=%d after_same=%d\n", base,
           after_uidmap, after_rules, after_syspkg, after_same);
    fflush(stdout);
    fw_config_shutdown();
    return 0;
}
