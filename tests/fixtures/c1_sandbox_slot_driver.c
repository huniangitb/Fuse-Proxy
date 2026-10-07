/*
 * tests/fixtures/c1_sandbox_slot_driver.c
 *
 * C1 判别驱动：沙盒落点的目录创建**不得**发生在 config_read_begin 持槽期间。
 *
 * 做法：与 backing_gate_driver 同套（临时 CONFIG_DIR 副本 + 实际源码编译链接，
 * 不经 Meson）。另经 -Wl,--wrap=config_read_begin/--wrap=config_read_end 维护
 * 「当前是否在配置读槽内」，-Wl,--wrap=mkdir_recursive_p 记录每次目录创建及其
 * 发生的槽状态。
 *
 * 判别性：旧实现把 `access()+mkdir_recursive_p(沙盒落点)` 直接写在
 * br_check_redir_rule 里——而它是在 config_read_begin 持槽期间被调用的，故
 * mkdir_in_slot ≥ 1（慢存储上会放大发布线程等读者归零的全局停顿，C1）。
 * 新实现只在槽内记录待建目录、出槽后由 br_ensure_sandbox_dir 补建，
 * 故 mkdir_in_slot == 0 且 mkdir_total ≥ 1。
 *
 * argv[1] = 主配置路径；uid.map 由 Python 侧预置在同目录（fw_pkg_reload 装载）。
 * 输出：valid/is_redirect/mkdir_total/mkdir_in_slot/mkdir_last 各一行。
 */
#define _GNU_SOURCE
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "config_parser.h"
#include "fw_config.h"
#include "fw_pkg.h"
#include "fw_rules.h"
#include "injector.h"
#include "nsp_util.h"

/* injector 全局符号：config_publisher 引用（测试不链接 injector.c，此处占位，
   沿用 backing_gate_driver 做法） */
struct GlobalFuseInfo g_global_fuse;
struct GlobalFuseInfo g_media_fuse;
volatile sig_atomic_t g_should_exit = 0;
volatile sig_atomic_t g_reload_config = 0;
volatile sig_atomic_t g_passive_mode = 0;
volatile sig_atomic_t g_fuse_ready = 0;
int g_epoll_fd = -1;
int g_global_root_fd = -1;
InjectMethod g_inject_method = INJECT_METHOD_V1;

/* ══════════════ 槽状态与 mkdir 观察 ══════════════ */

static int g_slot_depth;    /* config_read_begin/end 之间 > 0 */
static int g_mkdir_total;   /* mkdir_recursive_p 总调用数 */
static int g_mkdir_in_slot; /* 其中发生在持槽期间的次数 */
static char g_mkdir_last[1024];

int __real_mkdir_recursive_p(const char* path, mode_t mode);
int __wrap_mkdir_recursive_p(const char* path, mode_t mode) {
    g_mkdir_total++;
    if (g_slot_depth > 0) g_mkdir_in_slot++;
    if (path) snprintf(g_mkdir_last, sizeof g_mkdir_last, "%s", path);
    return __real_mkdir_recursive_p(path, mode);
}

uint64_t __real_config_read_begin(void);
uint64_t __wrap_config_read_begin(void) {
    g_slot_depth++;
    return __real_config_read_begin();
}

bool __real_config_read_end(uint64_t gen);
bool __wrap_config_read_end(uint64_t gen) {
    bool r = __real_config_read_end(gen);
    g_slot_depth--;
    return r;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <main_conf>\n", argv[0]);
        return 2;
    }
    config_set_allow_app_rules_mkdir(false);
    if (fw_config_init(argv[1]) != 0) {
        fprintf(stderr, "fw_config_init 失败\n");
        return 2;
    }
    fw_rules_init(argv[1], false); /* 沙盒解析断言需要引擎（配置索引由 fw_config 建好） */
    fw_pkg_reload();               /* 装载 CONFIG_DIR/uid.map，使 uid→包名解析命中 */

    char pathbuf[256];
    snprintf(pathbuf, sizeof pathbuf, "/0/Download/a.txt");
    NspQueryCtx q;
    memset(&q, 0, sizeof q);
    q.uid = 10123;
    q.pid = 0; /* 只用 uid.map，不走 /proc 回退 */
    q.path = pathbuf;

    NspPathDecision d;
    fw_rules_resolve(&q, &d);

    printf("valid=%d is_redirect=%d\n", (int)d.valid, (int)d.is_redirect);
    printf("mkdir_total=%d mkdir_in_slot=%d\n", g_mkdir_total, g_mkdir_in_slot);
    printf("mkdir_last=%s\n", g_mkdir_last);
    return 0;
}
