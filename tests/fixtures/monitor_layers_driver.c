/*
 * test_monitor_layers.py 专用 C 驱动（fixture）。
 *
 * 由 Python 脚本连同「实际源码」（fw_config.c / fw_pkg.c / config_parser.c 及
 * 其依赖）临时编译成测试二进制，不经 Meson。CONFIG_DIR 在编译期被脚本指向临时
 * fixture 根目录，使 uid.map 与规则文件都在普通用户可写的临时目录内，且能构造
 * 真实设备才有的 uid（>=10000）——FUSE 端到端测试的请求者是本机 uid（<10000），
 * 永远走不到 [USER_APPS:*] 分支，故这一层只能在此处用合成 uid 锁定。
 *
 * 用法：monitor_layers_driver <rules.conf> <uid>|<uid>@self> [...]
 *   `<uid>`        tid=0（只查 uid.map，不走 /proc）
 *   `<uid>@self`   以本进程 pid 作 tid，覆盖 uid.map 未收录时的 /proc 回退分支
 * 输出：每行 "uid=<u> pkg=<pkg> monitor=<0|1>"，交给 Python 侧断言
 *       （pkg 列用于失败时定位是「包名没解析出来」还是「合并算错」）。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fw_config.h"
#include "fw_pkg.h"

int main(int argc, char** argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <rules.conf> <uid>|@self> [<uid> ...]\n", argv[0]);
        return 2;
    }
    if (fw_config_init(argv[1]) != 0) {
        fprintf(stderr, "fw_config_init 失败\n");
        return 2;
    }
    for (int i = 2; i < argc; i++) {
        char* arg = argv[i];
        size_t alen = strlen(arg);
        pid_t tid = 0;
        if (alen > 5 && strcmp(arg + alen - 5, "@self") == 0) {
            arg[alen - 5] = '\0';
            tid = getpid();
        }
        unsigned long u = strtoul(arg, NULL, 10);
        char pkg[128] = {0};
        fw_pkg_resolve((uid_t)u, tid, pkg, sizeof pkg);
        printf("uid=%lu pkg=%s monitor=%d\n", u, pkg, fw_config_monitor_for((uid_t)u, tid) ? 1 : 0);
    }
    fflush(stdout);
    fw_config_shutdown();
    return 0;
}
