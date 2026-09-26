/*
 * test_monitor_layers.py 专用 C 驱动（fixture）。
 *
 * 由 Python 脚本连同「实际源码」（fw_config.c / fw_pkg.c / config_parser.c 及
 * 其依赖）临时编译成测试二进制，不经 Meson。CONFIG_DIR 在编译期被脚本指向临时
 * fixture 根目录，使 uid.map 与规则文件都在普通用户可写的临时目录内，且能构造
 * 真实设备才有的 uid（>=10000）——FUSE 端到端测试的请求者是本机 uid（<10000），
 * 永远走不到 [USER_APPS:*] 分支，故这一层只能在此处用合成 uid 锁定。
 *
 * 用法：monitor_layers_driver <rules.conf> (<uid>|<uid>@self>|resolve:<uid>:<path>) [...]
 *   `<uid>`        tid=0（只查 uid.map，不走 /proc）
 *   `<uid>@self`   以本进程 pid 作 tid，覆盖 uid.map 未收录时的 /proc 回退分支
 * 输出：每行 "uid=<u> pkg=<pkg> monitor=<0|1>"，交给 Python 侧断言
 *       （pkg 列用于失败时定位是「包名没解析出来」还是「合并算错」）。
 *       `resolve <path>` 参数额外打印该 uid 下该原始路径的规则解析结果：
 *       "resolve=<0|1> real=<最终真实路径> ro=<0|1>"——用于锁定沙盒/ALLOW 契约
 *       （沙盒把共享目录也重定向进本应用沙盒；ALLOW 则落回真实路径）。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fw_config.h"
#include "fw_pkg.h"
#include "fw_rules.h"

int main(int argc, char** argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <rules.conf> <uid>|@self> [<uid> ...]\n", argv[0]);
        return 2;
    }
    if (fw_config_init(argv[1]) != 0) {
        fprintf(stderr, "fw_config_init 失败\n");
        return 2;
    }
    fw_rules_init(argv[1], false); /* 沙盒/ALLOW 解析断言需要引擎（配置索引由 fw_config 建好） */
    for (int i = 2; i < argc; i++) {
        char* arg = argv[i];
        if (strncmp(arg, "resolve:", 8) == 0) {
            /* resolve:<uid>:<path>：打印规则解析结果（沙盒/ALLOW 契约用） */
            char* uid_s = arg + 8;
            char* path = strchr(uid_s, ':');
            if (!path) continue;
            *path++ = '\0';
            uid_t ruid = (uid_t)strtoul(uid_s, NULL, 10);
            NspQueryCtx q = {.uid = ruid, .pid = 0, .gid = 0, .path = path};
            NspPathDecision d;
            fw_rules_resolve(&q, &d);
            printf("resolve uid=%u path=%s valid=%d real=%s ro=%d\n", (unsigned)ruid, path,
                   (int)d.valid, d.real_path, (int)d.read_only);
            continue;
        }
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
