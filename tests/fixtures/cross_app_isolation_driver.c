/*
 * test_rules.py 跨应用隔离段专用 C 驱动（fixture）。
 *
 * 由 Python 脚本连同实际源码（fw_rules.c / fw_pkg.c / config_parser.c 及其
 * 依赖，不经 Meson）临时编译成测试二进制——真实 INCLUDE 副本把 CONFIG_DIR
 * 指向临时目录，故 uid.map 即测试自己的夹具。
 *
 * 用法：cross_app_isolation <main_conf> <uid> <path>...
 * 输出（每行一条，便于 Python 逐项比对）：
 *   global=<0|1>                                  —— fw_data_mediation_required()
 *   <path> resolve=<0|1> probe=<0|1> other=<0|1> valid=<0|1> backing=<0|1>
 *     resolve = fw_rules_resolve().appear_missing（打开/getattr 侧裁决）
 *     probe   = fw_rules_probe().appear_missing  （readdir 列举侧裁决）
 *     other   = fw_rules_probe().is_other_app_pkg
 *     backing = fw_backing_mediation_required_for(path)（backing 直通门）
 *
 * 调用方身份（uid→包名）走框架真实链路：fw_pkg 先查 <CONFIG_DIR>/uid.map，
 * 未命中再回退 /proc/<pid>/cmdline；pid 用本进程，故 uid.map 是唯一夹具。
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "config_parser.h"
#include "fw_pkg.h"
#include "fw_rules.h"
#include "injector.h"
#include "nsp_util.h"

/* injector 全局符号：config_publisher 引用（测试不链接 injector.c，此处占位，
   沿用 test_backing_gate / test_config_snapshot 做法） */
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
    if (argc < 4) {
        fprintf(stderr, "usage: %s <main_conf> <uid> <path...>\n", argv[0]);
        return 2;
    }
    config_set_allow_app_rules_mkdir(false);
    load_config_rules(argv[1]);
    /* 生产链路上 fw_config 发布时会 fw_pkg_reload()（装载 CONFIG_DIR/uid.map）；
       本驱动不经 fw_config，须显式装一次，否则 uid→包名 恒走 /proc 回退 */
    fw_pkg_reload();
    uid_t uid = (uid_t)strtoul(argv[2], NULL, 10);
    printf("global=%d\n", fw_data_mediation_required() ? 1 : 0);
    for (int i = 3; i < argc; i++) {
        NspQueryCtx q = {.uid = uid, .pid = getpid(), .gid = 0, .path = argv[i]};
        NspPathDecision d;
        memset(&d, 0, sizeof d);
        fw_rules_resolve(&q, &d);
        NspProbeResult p;
        memset(&p, 0, sizeof p);
        fw_rules_probe(&q, &p);
        printf("%s resolve=%d probe=%d other=%d valid=%d backing=%d\n", argv[i],
               d.appear_missing ? 1 : 0, p.appear_missing ? 1 : 0, p.is_other_app_pkg ? 1 : 0,
               d.valid ? 1 : 0, fw_backing_mediation_required_for(argv[i]) ? 1 : 0);
    }
    return 0;
}
