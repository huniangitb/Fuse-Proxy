/*
 * test_backing_gate.py 专用 C 驱动（fixture）。
 *
 * 由 Python 脚本连同实际源码（fw_rules.c / fw_pkg.c / config_parser.c 及其
 * 依赖，不经 Meson）临时编译成测试二进制，argv[1] 为主配置路径；无查询参数
 * 时打印 fw_data_mediation_required() 的 0/1 判定（全局门，兼容旧用例）；
 * 有查询参数时逐行打印 fw_backing_mediation_required_for(query) 的 0/1
 * 判定（按路径细粒度门）。
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>

#include "config_parser.h"
#include "fw_rules.h"
#include "injector.h"
#include "nsp_util.h"

/* injector 全局符号：config_publisher 引用（测试不链接 injector.c，此处占位，
   沿用 test_config_snapshot 做法） */
struct GlobalFuseInfo g_global_fuse;
struct GlobalFuseInfo g_media_fuse;
volatile sig_atomic_t g_should_exit = 0;
volatile sig_atomic_t g_reload_config = 0;
volatile sig_atomic_t g_passive_mode = 0;
volatile sig_atomic_t g_fuse_ready = 0;
int g_epoll_fd = -1;
int g_global_root_fd = -1;
InjectMethod g_inject_method = INJECT_METHOD_V1;

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <main_conf> [query...]\n", argv[0]);
        return 2;
    }
    config_set_allow_app_rules_mkdir(false);
    load_config_rules(argv[1]);
    if (argc == 2) {
        printf("%d\n", fw_data_mediation_required() ? 1 : 0);
        return 0;
    }
    for (int i = 2; i < argc; i++)
        printf("%d\n", fw_backing_mediation_required_for(argv[i]) ? 1 : 0);
    return 0;
}
