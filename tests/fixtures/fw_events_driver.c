#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
/*
 * fw_events_driver.c — fw_events（FUSE 事件通道生产侧）的判别性驱动
 *
 * 做法与 fw_acl_driver.c 一致：**直编真实源码**（#include "fw_events.c"），
 * 只把"本模块不负责的那几层"换成桩：
 *   - common_*（路径合成唯一出口）→ 按同语义实现，落点指向临时目录；
 *   - fw_rules_resolve（规则决策单点）→ 按路径前缀给声明式决策；
 *   - fw_acl_check（访问控制单点）→ 按 uid 给拒绝码；
 *   - fw_pkg_resolve → 固定包名；
 *   - log_internal → 落 stderr。
 * 除这些之外跑的都是生产实现：环、合并、TTL 缓存、JSON 渲染、订阅登记、
 * QUERY 判定与响应格式。
 *
 * 判别点（每条都必须在旧实现/错误实现上失败）：
 *   1. 事件字段构造（含 rename 的 src_*、write_denied 的 errno 且无 rpath）
 *   2. 200ms 内同 vpath 合并为最后一条
 *   3. 环形队列满丢最旧并累计 dropped（心跳如实上报增量）
 *   4. 无订阅者 / 关闭时早退（不入队）
 *   5. QUERY 六类响应 + reason 枚举 + 绝对 spath 反解 user 10
 *   6. exists 的 TTL 与「写事件失效」
 *   7. busy=1 与 ok=0 不得混淆
 *   8. 白名单自动含 MediaProvider 进程 uid：由**真实** packages.list 解析得到
 *      （删掉夹具里的行就不在，且只少这一项）；ENOSPC/EDQUOT 的写拒绝要发布
 */
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "config_parser.h"
#include "fw_acl.h"
#include "fw_rules.h"
#include "nsp_log.h"

#include "fw_events.c" /* 被检实现（真实源码） */

/* fw_pkg.c 也直编真实源码：白名单的 MediaProvider 项必须由**真实**的
   packages.list 解析得来（夹具里另写一份解析就等于只测自己）。只有
   fw_pkg_resolve（事件 pkg 字段用的展示名）仍走下面的固定桩，故先按宏改名。 */
#define fw_pkg_resolve fw_pkg_resolve_unused_prod
#include "fw_pkg.c"
#undef fw_pkg_resolve

/* ================== 测试设施 ================== */

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond, ...)                                    \
    do {                                                    \
        if (cond) {                                         \
            g_pass++;                                       \
        } else {                                            \
            g_fail++;                                       \
            fprintf(stderr, "❌ %s:%d ", __FILE__, __LINE__); \
            fprintf(stderr, __VA_ARGS__);                   \
            fputc('\n', stderr);                            \
        }                                                   \
    } while (0)

/* 生产里 g_global_cfg 由 config_parser.c 定义；驱动不链接它，自己提供实例 */
AppConfig g_global_cfg;

static char g_fake_base[128]; /* 假存储根（= 生产 STORAGE_BASE 位置） */
static char g_pkglist[PATH_MAX]; /* packages.list 夹具（白名单自动解析用） */

void log_internal(LogLevel level, const char* format, ...) {
    (void)level;
    va_list ap;
    va_start(ap, format);
    vfprintf(stderr, format, ap);
    va_end(ap);
}

/* ---- 桩：common_* 路径合成出口 ---- */

/* 与 common.c 的 common_parse_user_layer 同语义（唯一实现不在此重复的理由：
   测试驱动用 -I include 编不到 src/core/common.c 的全局状态，故按契约重写
   最小版本；语义断言由 test_fw_events.py 的静态契约另守） */
int common_fuse_user_path(int user_id, const char* sub_path, char* out, size_t sz) {
    if (!out || sz == 0) return -1;
    if (!sub_path) sub_path = "/";
    int n = (user_id < 0) ? snprintf(out, sz, "%s", sub_path)
                          : snprintf(out, sz, "/%d%s", user_id, sub_path);
    if (n < 0 || (size_t)n >= sz) {
        out[0] = '\0';
        return -1;
    }
    return 0;
}

int common_parse_user_layer(const char* path, int* user_id, const char** sub_path) {
    if (user_id) *user_id = -1;
    if (sub_path) *sub_path = path;
    if (!path || path[0] != '/' || path[1] < '0' || path[1] > '9') return 0;
    const char* d = path + 1;
    long v = 0;
    while (*d >= '0' && *d <= '9') {
        int digit = *d - '0';
        if (v > (INT_MAX - digit) / 10) return -1;
        v = v * 10 + digit;
        d++;
    }
    if (*d != '\0' && *d != '/') return 0;
    if (user_id) *user_id = (int)v;
    if (sub_path) *sub_path = (*d == '/') ? d : "/";
    return 1;
}

void common_view_path(int user_id, const char* sub_path, char* out, size_t sz) {
    if (!out || sz == 0) return;
    if (!sub_path) sub_path = "/";
    if (user_id < 0) {
        snprintf(out, sz, "%s", sub_path);
        return;
    }
    snprintf(out, sz, "/storage/emulated/%d%s", user_id, sub_path);
}

void common_default_real_path(int user_id, const char* sub_path, char* out, size_t sz) {
    if (!out || sz == 0) return;
    snprintf(out, sz, "%s/%d%s", g_fake_base, user_id < 0 ? 0 : user_id, sub_path ? sub_path : "/");
}

void common_storage_base(char* out, size_t sz) {
    snprintf(out, sz, "%s", g_fake_base);
}

/* ---- 桩：决策与身份 ---- */

/* fw_pkg.c 的另外两个数据源（uid.map 与 /proc）本套件不关心：白名单只走
   packages.list 分支，桩成"查不到"即可（真实现见 src/core/uid_map.c / fast_pid.c）。 */
int uid_map_load(UidMapEntry* entries, int max_entries) {
    (void)entries;
    (void)max_entries;
    return 0;
}

const char* uid_map_lookup(const UidMapEntry* entries, int count, uid_t uid) {
    (void)entries;
    (void)count;
    (void)uid;
    return NULL;
}

bool proc_get_cmdline(int pid, char* buf, size_t size) {
    (void)pid;
    if (buf && size > 0) buf[0] = '\0';
    return false;
}

bool fw_pkg_resolve(uid_t uid, pid_t tid, char* out, size_t size) {
    (void)uid;
    (void)tid;
    snprintf(out, size, "com.test.app");
    return true;
}

int fw_acl_check(uid_t uid, pid_t pid, const char* path, NspAclOp op, bool is_dir, int access_mask) {
    (void)pid;
    (void)op;
    (void)is_dir;
    (void)access_mask;
    if (uid == 10500 && path && strstr(path, "/Isolated/")) return -EACCES; /* 存在但不许 */
    if (uid == 10501 && path && strstr(path, "/Private/")) return -ENOENT; /* 假装不存在 */
    if (uid == 10502 && path && strstr(path, "/Android/data/com.other.app/")) return -ENOENT; /* 跨应用隔离（ACL 同口径 ENOENT） */
    return 0;
}

/* 规则决策桩：按 sub_path 前缀给声明式结果（模拟 fw_rules_resolve 的输出形态，
   本模块只读字段、不参与判定）。 */
void fw_rules_resolve(const NspQueryCtx* q, NspPathDecision* out) {
    memset(out, 0, sizeof *out);
    if (!q || !q->path) return;
    int user = -1;
    const char* sub = NULL;
    if (common_parse_user_layer(q->path, &user, &sub) != 1) return;
    out->valid = true;
    snprintf(out->real_path, sizeof out->real_path, "%s/%d%s", g_fake_base, user, sub);
    if (strncmp(sub, "/Backend/", 9) == 0) {
        out->is_ftp = true; /* 后端路径：无真实落盘 rpath 语义 → QUERY 回 ok=0 */
        return;
    }
    if (strncmp(sub, "/Android/data/com.other.app/", 27) == 0) {
        out->is_other_app_pkg = true; /* 隔离成因标注 */
        out->rule_kind = NSP_RULE_ISOLATION;
        return;
    }
    if (strncmp(sub, "/Hidden/", 8) == 0) {
        out->appear_missing = true;
        out->rule_kind = NSP_RULE_HIDE;
        out->rule_scope = BR_SCOPE_GLOBAL;
        return;
    }
    if (strncmp(sub, "/Allow/", 7) == 0) {
        /* 显式放行：落点就是默认存储路径（is_redirect=1 但 rpath 不变），
           归因必须是 allow —— 这是"有裁决"与"无规则"的唯一区分点 */
        out->is_redirect = true;
        out->rule_kind = NSP_RULE_ALLOW;
        out->rule_scope = BR_SCOPE_APP;
        return;
    }
    if (strncmp(sub, "/RO/", 4) == 0) {
        out->read_only = true;
        out->rule_kind = NSP_RULE_RO;
        out->rule_scope = BR_SCOPE_CAT;
        return;
    }
    if (user == 0 && strncmp(sub, "/DCIM/redir.jpg", 15) == 0) {
        out->is_redirect = true;
        out->rule_kind = NSP_RULE_REDIRECT;
        out->rule_scope = BR_SCOPE_APP;
        snprintf(out->real_path, sizeof out->real_path, "%s/0/Movies/redir.jpg", g_fake_base);
        return;
    }
    if (user == 10 && strncmp(sub, "/DCIM/redir.jpg", 15) == 0) {
        out->is_redirect = true;
        snprintf(out->real_path, sizeof out->real_path, "%s/10/Movies/redir.jpg", g_fake_base);
        return;
    }
    if (strncmp(sub, "/Sandbox/", 9) == 0) {
        out->is_redirect = true;
        out->is_sandbox = true;
        out->rule_kind = NSP_RULE_SANDBOX;
        snprintf(out->real_path, sizeof out->real_path,
                 "%s/%d/Android/data/com.test.app/sandbox/x.jpg", g_fake_base, user);
        return;
    }
    if (strncmp(sub, "/Unknown/", 9) == 0) {
        out->valid = false; /* 无规则/不认识 → QUERY 必须回 ok=0 */
        return;
    }
}

/* ================== 小工具 ================== */

static void rm_rf(const char* path) {
    char cmd[PATH_MAX + 16];
    snprintf(cmd, sizeof cmd, "rm -rf '%s'", path);
    if (system(cmd) != 0) { /* 清理失败不影响断言 */
    }
}

static void touch(const char* path) {
    FILE* f = fopen(path, "wb");
    if (f) {
        fputs("x", f);
        fclose(f);
    }
}

static void mkdir_p(const char* path) {
    char tmp[PATH_MAX];
    snprintf(tmp, sizeof tmp, "%s", path);
    for (char* p = tmp + 1; *p; p++) {
        if (*p != '/') continue;
        *p = '\0';
        mkdir(tmp, 0775);
        *p = '/';
    }
    mkdir(tmp, 0775);
}

static int g_rx = -1;

static long drv_recv(char* buf, size_t cap) {
    if (g_rx < 0) return -1;
    ssize_t n = recv(g_rx, buf, cap - 1, MSG_DONTWAIT);
    if (n <= 0) return -1;
    buf[n] = '\0';
    return (long)n;
}

static bool has(const char* hay, const char* needle) {
    return hay && needle && strstr(hay, needle) != NULL;
}

/* ================== 用例 ================== */

static char g_rx_name[108];

static void drv_subscribe(void) {
    char req[256];
    snprintf(req, sizeof req,
             "{\"cmd\":\"SUBSCRIBE\",\"reply\":\"%s\",\"filter\":{\"types\":[\"write_done\","
             "\"write_denied\"]}}",
             g_rx_name);
    fw_handle_subscribe(req, NULL, 0, 1000);
}

/* 让通道进入"已启动 + 有一个订阅者"的状态：真实 socket，真发真收。 */
static void channel_up(void) {
    g_global_cfg.fuse_events = true;
    atomic_store(&g_events_on, true);
    if (!g_ring) g_ring = calloc(FW_EVENTS_RING_CAP, sizeof *g_ring);
    if (g_evsock < 0) g_evsock = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (g_rx < 0) {
        g_rx = socket(AF_UNIX, SOCK_DGRAM, 0);
        snprintf(g_rx_name, sizeof g_rx_name, "nsp_fs_events.drv.%d", (int)getpid());
        struct sockaddr_un a;
        socklen_t n = nsp_uds_abstract_addr(&a, g_rx_name);
        if (bind(g_rx, (struct sockaddr*)&a, n) != 0) {
            fprintf(stderr, "订阅端 bind 失败: %s\n", strerror(errno));
            exit(1);
        }
    }
    /* 早退用例会主动摘掉订阅，这里补回来（夹具自愈，不影响被测行为） */
    if (g_sub_count == 0) drv_subscribe();
}

static void test_early_exit(void) {
    channel_up();
    /* 无订阅者：把订阅表整槽摘掉（只清计数会留下 used 槽，夹具自相矛盾） */
    g_subs[0].used = false;
    g_sub_count = 0;
    fw_update_hot();
    atomic_store(&g_fw_events_hot, false);
    while (fw_ring_pop(&(FwEventRec){0}, 1) > 0) {
    }
    fw_events_note_write_done(10337, 0, "/0/Pictures/a.jpg", FW_EV_OP_CREATE, NULL);
    CHECK(g_ring_count == 0, "无订阅者时不应入队（count=%d）", g_ring_count);

    /* 关闭：连 exists 失效都不做，直接返回 */
    atomic_store(&g_events_on, false);
    fw_events_note_write_done(10337, 0, "/0/Pictures/a.jpg", FW_EV_OP_CREATE, NULL);
    CHECK(g_ring_count == 0, "关闭时不应入队（count=%d）", g_ring_count);
    atomic_store(&g_events_on, true);
}

static void test_event_fields(void) {
    channel_up();
    char buf[2048];
    while (drv_recv(buf, sizeof buf) >= 0) {
    }
    fw_events_set_test_now_ms(100000);
    atomic_store(&g_fw_events_hot, true);

    /* create：vpath/spath/rpath 三个路径域的自洽 */
    fw_events_note_write_done(10337, 0, "/0/Pictures/a.jpg", FW_EV_OP_CREATE, NULL);
    fw_drain_ring();
    CHECK(drv_recv(buf, sizeof buf) < 0, "200ms 合并窗口内不得立即发出");
    fw_events_set_test_now_ms(100200);
    fw_coalesce_flush_due();
    CHECK(drv_recv(buf, sizeof buf) > 0, "窗口到期应发出");
    CHECK(has(buf, "\"v\":1"), "缺 v: %s", buf);
    CHECK(has(buf, "\"type\":\"write_done\""), "type 错: %s", buf);
    CHECK(has(buf, "\"vol\":\"external_primary\""), "vol 错: %s", buf);
    CHECK(has(buf, "\"uid\":10337"), "uid 错: %s", buf);
    CHECK(has(buf, "\"pkg\":\"com.test.app\""), "pkg 错: %s", buf);
    CHECK(has(buf, "\"op\":\"create\""), "op 错: %s", buf);
    CHECK(has(buf, "\"vpath\":\"/Pictures/a.jpg\""), "vpath 错(须相对用户根): %s", buf);
    CHECK(has(buf, "\"spath\":\"/storage/emulated/0/Pictures/a.jpg\""), "spath 错: %s", buf);
    CHECK(has(buf, "\"rpath\":\""), "rpath 缺失: %s", buf);
    CHECK(!has(buf, "\"src_vpath\""), "非 rename 不得带 src_vpath: %s", buf);
    CHECK(strlen(buf) < FW_EVENTS_FRAME_MAX, "单帧必须 ≤1KB（实际 %zu）", strlen(buf));

    /* rename：src/dst 各自成条（src 只在字段里） */
    fw_events_set_test_now_ms(200000);
    fw_events_note_write_done(10337, 0, "/0/B/x.txt", FW_EV_OP_RENAME, "/0/A/x.txt");
    fw_drain_ring();
    fw_events_set_test_now_ms(200300);
    fw_coalesce_flush_due();
    CHECK(drv_recv(buf, sizeof buf) > 0, "rename 应发出");
    CHECK(has(buf, "\"op\":\"rename\""), "op 错: %s", buf);
    CHECK(has(buf, "\"vpath\":\"/B/x.txt\""), "rename vpath 取目标: %s", buf);
    CHECK(has(buf, "\"src_vpath\":\"/A/x.txt\""), "rename 缺 src_vpath: %s", buf);
    CHECK(has(buf, "\"src_spath\":\"/storage/emulated/0/A/x.txt\""), "src_spath 错: %s", buf);
    CHECK(has(buf, "\"rpath\":\""), "rename 缺 rpath: %s", buf);

    /* write_denied：带 errno、带 spath、**不带** rpath（文件根本没落盘） */
    fw_events_set_test_now_ms(300000);
    fw_events_note_write_denied(10337, 0, "/0/RO/x.jpg", NSP_ACL_OP_CREATE, -EROFS);
    fw_drain_ring();
    fw_events_set_test_now_ms(300300);
    fw_coalesce_flush_due();
    CHECK(drv_recv(buf, sizeof buf) > 0, "write_denied 应发出");
    CHECK(has(buf, "\"type\":\"write_denied\""), "type 错: %s", buf);
    CHECK(has(buf, "\"errno\":\"EROFS\""), "errno 错: %s", buf);
    CHECK(has(buf, "\"spath\":\"/storage/emulated/0/RO/x.jpg\""), "denied 必须带 spath: %s", buf);
    CHECK(!has(buf, "\"rpath\""), "denied 不得带 rpath: %s", buf);
    CHECK(has(buf, "\"op\":\"create\""), "denied op 错: %s", buf);

    /* 容量不足同样是"写没落盘"的可解释原因（磁盘满 / 配额），必须发布 */
    fw_events_set_test_now_ms(310000);
    fw_events_note_write_denied(10337, 0, "/0/DCIM/full.jpg", NSP_ACL_OP_CREATE, -ENOSPC);
    fw_drain_ring();
    fw_events_set_test_now_ms(310300);
    fw_coalesce_flush_due();
    CHECK(drv_recv(buf, sizeof buf) > 0, "ENOSPC 的写拒绝应发出（磁盘满）");
    CHECK(has(buf, "\"errno\":\"ENOSPC\""), "errno 应为 ENOSPC: %s", buf);
    CHECK(has(buf, "\"spath\":\"/storage/emulated/0/DCIM/full.jpg\""), "denied 缺 spath: %s", buf);

    fw_events_set_test_now_ms(320000);
    fw_events_note_write_denied(10337, 0, "/0/DCIM/quota.jpg", NSP_ACL_OP_CREATE, -EDQUOT);
    fw_drain_ring();
    fw_events_set_test_now_ms(320300);
    fw_coalesce_flush_due();
    CHECK(drv_recv(buf, sizeof buf) > 0, "EDQUOT 的写拒绝应发出（配额）");
    CHECK(has(buf, "\"errno\":\"EDQUOT\""), "errno 应为 EDQUOT: %s", buf);

    /* EIO 一类瞬态/内部错误仍是噪声，不发布（否则对端误判路径状态） */
    fw_events_set_test_now_ms(330000);
    fw_events_note_write_denied(10337, 0, "/0/DCIM/io.jpg", NSP_ACL_OP_CREATE, -EIO);
    fw_drain_ring();
    fw_events_set_test_now_ms(330300);
    fw_coalesce_flush_due();
    CHECK(drv_recv(buf, sizeof buf) < 0, "EIO 不发布（噪声）");

    /* 非变更操作被拒（如 access）不产生事件 */
    fw_events_note_write_denied(10337, 0, "/0/x", NSP_ACL_OP_ACCESS, -EACCES);
    fw_drain_ring();
    fw_events_set_test_now_ms(400300);
    fw_coalesce_flush_due();
    CHECK(drv_recv(buf, sizeof buf) < 0, "ACCESS 被拒不发布事件");

    /* 帧长上限：装不下就返回 0（整帧丢），绝不发出半截 JSON 骗订阅者 */
    FwEvent big;
    memset(&big, 0, sizeof big);
    big.kind = FW_EV_WRITE_DONE;
    snprintf(big.vpath, sizeof big.vpath, "%s", "/Pictures/a.jpg");
    memset(big.spath, 'a', sizeof big.spath - 1);
    char small[256];
    CHECK(fw_format_event(&big, small, sizeof small) == 0, "装不下时必须返回 0（不得截断成半截 JSON）");
}

static void test_coalesce(void) {
    channel_up();
    char buf[2048];
    while (drv_recv(buf, sizeof buf) >= 0) {
    }
    atomic_store(&g_fw_events_hot, true);
    fw_events_set_test_now_ms(500000);
    memset(g_coalesce, 0, sizeof g_coalesce);

    fw_events_note_write_done(10337, 0, "/0/Pictures/c.jpg", FW_EV_OP_CLOSE_WRITE, NULL);
    fw_events_note_write_done(10337, 0, "/0/Pictures/c.jpg", FW_EV_OP_CLOSE_WRITE, NULL);
    fw_events_note_write_done(10337, 0, "/0/Pictures/c.jpg", FW_EV_OP_CLOSE_WRITE, NULL);
    fw_drain_ring();
    int used = 0;
    for (int i = 0; i < FW_EVENTS_COALESCE_SLOTS; i++) used += g_coalesce[i].used ? 1 : 0;
    CHECK(used == 1, "同 vpath 三条应合并成一槽（实际 %d）", used);

    /* 不同路径各自成条 */
    fw_events_note_write_done(10337, 0, "/0/Pictures/d.jpg", FW_EV_OP_CLOSE_WRITE, NULL);
    fw_drain_ring();
    used = 0;
    for (int i = 0; i < FW_EVENTS_COALESCE_SLOTS; i++) used += g_coalesce[i].used ? 1 : 0;
    CHECK(used == 2, "不同 vpath 不应合并（实际 %d）", used);

    fw_events_set_test_now_ms(500199);
    fw_coalesce_flush_due();
    CHECK(drv_recv(buf, sizeof buf) < 0, "199ms 时不得发出");
    fw_events_set_test_now_ms(500200);
    fw_coalesce_flush_due();
    long n1 = drv_recv(buf, sizeof buf);
    CHECK(n1 > 0, "200ms 到期应发出");
    long n2 = drv_recv(buf, sizeof buf);
    CHECK(n2 > 0, "第二条不同路径也应发出");
    CHECK(drv_recv(buf, sizeof buf) < 0, "合并后不得有第三条（同 vpath 只发最后一条）");
}

static void test_ring_drop(void) {
    channel_up();
    char buf[2048];
    while (drv_recv(buf, sizeof buf) >= 0) {
    }
    atomic_store(&g_fw_events_hot, true);
    while (fw_ring_pop(&(FwEventRec){0}, 1) > 0) {
    }
    uint32_t drop_before = g_ring_dropped;

    FwEventRec rec;
    for (uint32_t i = 0; i < FW_EVENTS_RING_CAP + 5; i++) {
        memset(&rec, 0, sizeof rec);
        rec.kind = FW_EV_WRITE_DONE;
        rec.op = FW_EV_OP_CLOSE_WRITE;
        rec.seq = i + 1;
        snprintf(rec.fuse_path, sizeof rec.fuse_path, "/0/Pictures/s%u.jpg", i);
        fw_ring_push(&rec);
    }
    CHECK(g_ring_count == FW_EVENTS_RING_CAP, "环应满（实际 %d）", g_ring_count);
    CHECK(g_ring_dropped - drop_before == 5, "丢弃计数应为 5（实际 %u）",
          g_ring_dropped - drop_before);

    /* 丢的是最旧的：队首应是第 6 条 */
    FwEventRec out[1];
    CHECK(fw_ring_pop(out, 1) == 1 && out[0].seq == 6, "满时丢最旧（队首 seq=%llu）",
          (unsigned long long)out[0].seq);

    /* 心跳如实上报**自上次心跳以来**的丢弃数 */
    g_next_ping_ms = 0;
    fw_maybe_ping();
    CHECK(drv_recv(buf, sizeof buf) > 0, "心跳应发出");
    CHECK(has(buf, "\"type\":\"ping\""), "心跳 type 错: %s", buf);
    CHECK(has(buf, "\"dropped\":5"), "心跳 dropped 错: %s", buf);
    g_next_ping_ms = 0;
    fw_maybe_ping();
    CHECK(drv_recv(buf, sizeof buf) > 0 && has(buf, "\"dropped\":0"),
          "两次心跳之间无丢弃时应报 0");

    while (fw_ring_pop(&(FwEventRec){0}, 1) > 0) {
    }
    memset(g_coalesce, 0, sizeof g_coalesce);
}

static long query(const char* req, char* out, size_t cap, bool congested) {
    size_t n = fw_query_handle(req, out, cap, congested);
    if (n == 0) {
        out[0] = '\0';
        return 0;
    }
    return (long)n;
}

static void test_query_six(void) {
    channel_up();
    char resp[2048];
    char req[512];

    /* ① ok=1 / exists=1 / denied=0 / reason=none */
    snprintf(req, sizeof req,
             "{\"cmd\":\"QUERY\",\"v\":1,\"spath\":\"/storage/emulated/0/Pictures/a.jpg\","
             "\"uid\":10337,\"seq\":11}");
    CHECK(query(req, resp, sizeof resp, false) > 0, "QUERY 应有响应");
    CHECK(has(resp, "\"ok\":1"), "① ok 错: %s", resp);
    CHECK(has(resp, "\"exists\":1,"), "① exists 错: %s", resp);
    CHECK(has(resp, "\"denied\":0,"), "① denied 错: %s", resp);
    CHECK(has(resp, "\"reason\":\"none\""), "① reason 错: %s", resp);
    CHECK(has(resp, "\"seq\":11,"), "① seq 未回显: %s", resp);
    CHECK(has(resp, "\"rpath\":\""), "① 缺 rpath: %s", resp);
    /* 归因：无规则命中时必须明确是 none，不是空串也不是缺字段 */
    CHECK(has(resp, "\"scope\":\"none\",\"rule\":\"none\""), "① 归因应为 none: %s", resp);

    /* ② ok=1 / exists=1 / denied=1（RO）——RO 优先于 redirect */
    snprintf(req, sizeof req,
             "{\"cmd\":\"QUERY\",\"v\":1,\"spath\":\"/storage/emulated/0/RO/x.jpg\",\"uid\":10337,"
             "\"seq\":12}");
    query(req, resp, sizeof resp, false);
    CHECK(has(resp, "\"ok\":1") && has(resp, "\"denied\":1,"), "② ok/denied 错: %s", resp);
    CHECK(has(resp, "\"reason\":\"ro\""), "② reason 应为 ro: %s", resp);
    CHECK(has(resp, "\"exists\":1,"), "② exists 错: %s", resp);
    CHECK(has(resp, "\"scope\":\"cat\",\"rule\":\"ro\""), "② 归因应为 cat/ro: %s", resp);

    /* ③ ok=1 / exists=0（路径不存在） */
    snprintf(req, sizeof req,
             "{\"cmd\":\"QUERY\",\"v\":1,\"spath\":\"/storage/emulated/0/Pictures/none.jpg\","
             "\"uid\":10337,\"seq\":13}");
    query(req, resp, sizeof resp, false);
    CHECK(has(resp, "\"ok\":1") && has(resp, "\"exists\":0,"), "③ 错: %s", resp);
    CHECK(has(resp, "\"denied\":0,"), "③ denied 错: %s", resp);

    /* ④ ok=1 / denied=1 / exists=0（HIDE：假装不存在且真的不在） */
    snprintf(req, sizeof req,
             "{\"cmd\":\"QUERY\",\"v\":1,\"spath\":\"/storage/emulated/0/Hidden/y.jpg\","
             "\"uid\":10337,\"seq\":14}");
    query(req, resp, sizeof resp, false);
    CHECK(has(resp, "\"ok\":1") && has(resp, "\"denied\":1,"), "④ 错: %s", resp);
    CHECK(has(resp, "\"reason\":\"hide\""), "④ reason 应为 hide: %s", resp);
    CHECK(has(resp, "\"exists\":0,"), "④ exists 错: %s", resp);
    CHECK(has(resp, "\"scope\":\"global\",\"rule\":\"hide\""), "④ 归因应为 global/hide: %s",
          resp);

    /* ⑤ ok=0（无规则/不认识）——**不得**回 denied=1 */
    snprintf(req, sizeof req,
             "{\"cmd\":\"QUERY\",\"v\":1,\"spath\":\"/storage/emulated/0/Unknown/z.jpg\","
             "\"uid\":10337,\"seq\":15}");
    query(req, resp, sizeof resp, false);
    CHECK(has(resp, "\"ok\":0"), "⑤ ok 应 0: %s", resp);
    CHECK(!has(resp, "\"denied\""), "⑤ ok=0 不得带 denied（与拒绝混淆）: %s", resp);

    /* ⑥ busy=1（队列拥塞）——不得复用 ok=0 */
    snprintf(req, sizeof req,
             "{\"cmd\":\"QUERY\",\"v\":1,\"spath\":\"/storage/emulated/0/Pictures/a.jpg\","
             "\"uid\":10337,\"seq\":16}");
    query(req, resp, sizeof resp, true);
    CHECK(has(resp, "\"busy\":1"), "⑥ 应回 busy=1: %s", resp);
    CHECK(!has(resp, "\"ok\""), "⑥ busy 不得带 ok: %s", resp);
    CHECK(has(resp, "\"seq\":16"), "⑥ busy 也应回显 seq: %s", resp);

    /* 畸形请求：ok=0 */
    CHECK(query("{\"cmd\":\"NOPE\"}", resp, sizeof resp, false) > 0 && has(resp, "\"ok\":0"),
          "不认识的 cmd 应 ok=0: %s", resp);
    CHECK(query("{\"cmd\":\"QUERY\",\"spath\":\"/data/media/0/x\",\"uid\":1}", resp, sizeof resp,
                false) > 0 &&
              has(resp, "\"ok\":0"),
          "非视图路径（/data/media）应 ok=0: %s", resp);
    CHECK(query("{\"cmd\":\"QUERY\",\"spath\":\"/storage/emulated/0/../../etc/passwd\","
                "\"uid\":1}",
                resp, sizeof resp, false) > 0 &&
              has(resp, "\"ok\":0"),
          "带 .. 的穿越路径应 ok=0: %s", resp);
}

static void test_query_reasons(void) {
    channel_up();
    char resp[2048];
    char req[512];

    /* REDIRECT：spath 变成落点，vpath 域仍是请求域（这里只校验 spath/rpath） */
    snprintf(req, sizeof req,
             "{\"cmd\":\"QUERY\",\"v\":1,\"spath\":\"/storage/emulated/0/DCIM/redir.jpg\","
             "\"uid\":10337,\"seq\":21}");
    query(req, resp, sizeof resp, false);
    CHECK(has(resp, "\"reason\":\"redirect\""), "reason 应为 redirect: %s", resp);
    CHECK(has(resp, "\"denied\":0,"), "redirect 不是拒绝: %s", resp);
    CHECK(has(resp, "\"spath\":\"/storage/emulated/0/Movies/redir.jpg\""), "spath 应为落点: %s",
          resp);
    CHECK(has(resp, "\"scope\":\"app\",\"rule\":\"redirect\""), "redirect 归因错: %s", resp);

    /* SANDBOX：成因与普通 redirect 区分 */
    snprintf(req, sizeof req,
             "{\"cmd\":\"QUERY\",\"v\":1,\"spath\":\"/storage/emulated/0/Sandbox/x.jpg\","
             "\"uid\":10337,\"seq\":22}");
    query(req, resp, sizeof resp, false);
    CHECK(has(resp, "\"reason\":\"sandbox\""), "reason 应为 sandbox: %s", resp);
    CHECK(has(resp, "\"rule\":\"sandbox\""), "sandbox 归因错: %s", resp);

    /* ALLOW：显式放行。spath 不变，但 rule 必须报 allow —— 对端据此"让位" */
    snprintf(req, sizeof req,
             "{\"cmd\":\"QUERY\",\"v\":1,\"spath\":\"/storage/emulated/0/Allow/a.jpg\","
             "\"uid\":10337,\"seq\":26}");
    query(req, resp, sizeof resp, false);
    CHECK(has(resp, "\"ok\":1"), "ALLOW 应 ok=1: %s", resp);
    CHECK(has(resp, "\"denied\":0,"), "ALLOW 不是拒绝: %s", resp);
    CHECK(has(resp, "\"scope\":\"app\",\"rule\":\"allow\""), "ALLOW 归因错: %s", resp);
    CHECK(has(resp, "\"spath\":\"/storage/emulated/0/Allow/a.jpg\""), "ALLOW 落点应为自身: %s",
          resp);

    /* ACL 拒绝：隔离（EACCES） */
    snprintf(req, sizeof req,
             "{\"cmd\":\"QUERY\",\"v\":1,\"spath\":\"/storage/emulated/0/Isolated/x.jpg\","
             "\"uid\":10500,\"seq\":23}");
    query(req, resp, sizeof resp, false);
    CHECK(has(resp, "\"denied\":1,"), "ACL 拒绝应 denied=1: %s", resp);
    CHECK(has(resp, "\"reason\":\"isolation\""), "reason 应为 isolation: %s", resp);
    /* 访问控制先于规则拒绝：归因不许借用某个规则作用域 */
    CHECK(has(resp, "\"scope\":\"none\",\"rule\":\"isolation\""), "ACL 归因错: %s", resp);

    /* ACL 拒绝：假装不存在（ENOENT）→ hide */
    snprintf(req, sizeof req,
             "{\"cmd\":\"QUERY\",\"v\":1,\"spath\":\"/storage/emulated/0/Private/x.jpg\","
             "\"uid\":10501,\"seq\":24}");
    query(req, resp, sizeof resp, false);
    CHECK(has(resp, "\"reason\":\"hide\""), "ACL ENOENT 应 reason=hide: %s", resp);

    /* 跨应用隔离：ACL 也回 ENOENT，但 reason 必须是 isolation（引擎 is_other_app_pkg） */
    snprintf(req, sizeof req,
             "{\"cmd\":\"QUERY\",\"v\":1,\"spath\":\"/storage/emulated/0/Android/data/com.other.app/x\","
             "\"uid\":10502,\"seq\":25}");
    query(req, resp, sizeof resp, false);
    CHECK(has(resp, "\"denied\":1,"), "隔离应 denied=1: %s", resp);
    CHECK(has(resp, "\"reason\":\"isolation\""), "隔离的 reason 应为 isolation: %s", resp);

    /* 后端（FTP）路径：无 rpath 语义 → ok=0 */
    snprintf(req, sizeof req,
             "{\"cmd\":\"QUERY\",\"v\":1,\"spath\":\"/storage/emulated/0/Backend/x.jpg\","
             "\"uid\":10337,\"seq\":25}");
    query(req, resp, sizeof resp, false);
    CHECK(has(resp, "\"ok\":0"), "后端路径应 ok=0: %s", resp);
}

static void test_user10_and_ttl(void) {
    channel_up();
    char resp[2048];
    char req[512];

    /* 绝对 spath 反解 user 10：user 必须一路带到 rpath 与 spath 合成里 */
    snprintf(req, sizeof req,
             "{\"cmd\":\"QUERY\",\"v\":1,\"spath\":\"/storage/emulated/10/DCIM/redir.jpg\","
             "\"uid\":10337,\"seq\":31}");
    query(req, resp, sizeof resp, false);
    CHECK(has(resp, "\"rpath\":\""), "缺 rpath: %s", resp);
    CHECK(has(resp, "/10/Movies/redir.jpg"), "rpath 丢了 user 10: %s", resp);
    CHECK(has(resp, "\"spath\":\"/storage/emulated/10/Movies/redir.jpg\""),
          "spath 应保留 user 10: %s", resp);

    /* TTL：缓存期内不重复 lstat，过期后必须重新看 */
    fw_events_set_test_now_ms(900000);
    snprintf(req, sizeof req,
             "{\"cmd\":\"QUERY\",\"v\":1,\"spath\":\"/storage/emulated/0/Pictures/fresh.jpg\","
             "\"uid\":10337,\"seq\":32}");
    query(req, resp, sizeof resp, false);
    CHECK(has(resp, "\"exists\":0,"), "新路径应 exists=0: %s", resp);
    touch("/tmp/fw_ev_drv_placeholder"); /* 只是让下面 create 之前不留空语句 */
    char real[PATH_MAX];
    snprintf(real, sizeof real, "%s/0/Pictures/fresh.jpg", g_fake_base);
    touch(real);
    query(req, resp, sizeof resp, false);
    CHECK(has(resp, "\"exists\":0,"), "TTL 内应命中缓存（仍是 0）: %s", resp);
    fw_events_set_test_now_ms(900201);
    query(req, resp, sizeof resp, false);
    CHECK(has(resp, "\"exists\":1,"), "TTL 过期后必须重新 lstat（应为 1）: %s", resp);

    /* 写事件失效：缓存 says 1，删掉文件后同一时刻查询仍看到 1；写事件一到立刻翻 0 */
    unlink(real);
    query(req, resp, sizeof resp, false);
    CHECK(has(resp, "\"exists\":1,"), "失效前应仍命中缓存: %s", resp);
    atomic_store(&g_fw_events_hot, true);
    fw_events_note_write_done(10337, 0, "/0/Pictures/fresh.jpg", FW_EV_OP_CLOSE_WRITE, NULL);
    query(req, resp, sizeof resp, false);
    CHECK(has(resp, "\"exists\":0,"), "写事件必须使 exists 缓存失效: %s", resp);

    while (fw_ring_pop(&(FwEventRec){0}, 1) > 0) {
    }
    memset(g_coalesce, 0, sizeof g_coalesce);
}

/* media_refresh：daemon **主动**要求对端补一次媒体扫描（落点被改写的写操作）。
   四条：① 显式请求的字段齐全且不带 op；② 非媒体扩展名整条不发；③ 落点被改写的
   write_done 额外补一条 media_refresh；④ 未改写的 write_done 不补（否则每次写都
   变成两次扫描）。 */
static void test_media_refresh(void) {
    channel_up();
    char buf[2048];
    while (drv_recv(buf, sizeof buf) >= 0) {
    }
    g_subs[0].mask = FW_EV_MASK_DONE | FW_EV_MASK_DENIED | FW_EV_MASK_REFRESH | FW_EV_MASK_PING;
    atomic_store(&g_fw_events_hot, true);

    /* ① 显式请求 */
    memset(g_coalesce, 0, sizeof g_coalesce);
    fw_events_set_test_now_ms(900000);
    fw_events_note_media_refresh(10337, 0, "/0/Pictures/a.jpg", FW_REFRESH_REDIRECT_WRITE);
    fw_drain_ring();
    fw_events_set_test_now_ms(900300);
    fw_coalesce_flush_due();
    CHECK(drv_recv(buf, sizeof buf) > 0, "媒体刷新请求应发出");
    CHECK(has(buf, "\"type\":\"media_refresh\""), "type 错: %s", buf);
    CHECK(has(buf, "\"reason\":\"redirect_write\""), "reason 错: %s", buf);
    CHECK(has(buf, "\"media\":\"image\""), "media 应 image: %s", buf);
    CHECK(has(buf, "\"vpath\":\"/Pictures/a.jpg\""), "vpath 错: %s", buf);
    CHECK(has(buf, "\"spath\":\"/storage/emulated/0/Pictures/a.jpg\""), "spath 错: %s", buf);
    CHECK(has(buf, "\"rpath\":\"/tmp/"), "rpath 缺失: %s", buf);
    CHECK(!has(buf, "\"op\":"), "刷新不是变更操作，不应带 op: %s", buf);
    CHECK(strlen(buf) < FW_EVENTS_FRAME_MAX, "单帧必须 ≤1KB（实际 %zu）", strlen(buf));

    /* ② 非媒体扩展名：整条不发 */
    fw_events_set_test_now_ms(910000);
    fw_events_note_media_refresh(10337, 0, "/0/B/x.txt", FW_REFRESH_FTP_UPLOAD);
    fw_drain_ring();
    fw_events_set_test_now_ms(910300);
    fw_coalesce_flush_due();
    CHECK(drv_recv(buf, sizeof buf) < 0, "非媒体落点不得发出刷新事件");

    /* ③ REDIRECT 落点：write_done + media_refresh 两条 */
    memset(g_coalesce, 0, sizeof g_coalesce);
    fw_events_set_test_now_ms(920000);
    fw_events_note_write_done(10337, 0, "/0/DCIM/redir.jpg", FW_EV_OP_CLOSE_WRITE, NULL);
    fw_drain_ring();
    fw_events_set_test_now_ms(920300);
    fw_coalesce_flush_due();
    char f1[2048];
    char f2[2048];
    long n1 = drv_recv(f1, sizeof f1);
    long n2 = drv_recv(f2, sizeof f2);
    CHECK(n1 > 0 && n2 > 0, "改写落点应发两条（实际 %ld/%ld）", n1, n2);
    if (n1 > 0 && n2 > 0) {
        const char* done = has(f1, "\"write_done\"") ? f1 : f2;
        const char* ref = (done == f1) ? f2 : f1;
        CHECK(has(done, "\"type\":\"write_done\""), "缺少 write_done: %s%s", f1, f2);
        CHECK(has(ref, "\"type\":\"media_refresh\""), "缺少 media_refresh: %s%s", f1, f2);
        CHECK(has(ref, "\"reason\":\"redirect_write\""), "刷新 reason 错: %s", ref);
        CHECK(has(ref, "\"media\":\"image\""), "刷新 media 错: %s", ref);
        CHECK(has(ref, "\"spath\":\"/storage/emulated/0/DCIM/redir.jpg\""), "刷新 spath 错: %s",
              ref);
        CHECK(has(ref, "\"rpath\":\"/tmp/"), "刷新缺 rpath: %s", ref);
    }

    /* ④ 未改写落点：只有 write_done */
    memset(g_coalesce, 0, sizeof g_coalesce);
    fw_events_set_test_now_ms(930000);
    fw_events_note_write_done(10337, 0, "/0/Pictures/b.jpg", FW_EV_OP_CLOSE_WRITE, NULL);
    fw_drain_ring();
    fw_events_set_test_now_ms(930300);
    fw_coalesce_flush_due();
    CHECK(drv_recv(buf, sizeof buf) > 0, "直通写应发 write_done");
    CHECK(has(buf, "\"type\":\"write_done\""), "直通写 type 错: %s", buf);
    CHECK(drv_recv(buf, sizeof buf) < 0, "未改写落点不得补刷新事件");

    /* 夹具自愈：恢复默认订阅掩码，后面的 filter 用例自己会再改 */
    drv_subscribe();
}

static void test_sub_filters(void) {
    channel_up();
    char buf[2048];
    while (drv_recv(buf, sizeof buf) >= 0) {
    }
    /* 只收 write_done 的订阅者不应收到 write_denied */
    g_subs[0].mask = FW_EV_MASK_DONE | FW_EV_MASK_PING;
    atomic_store(&g_fw_events_hot, true);
    fw_events_set_test_now_ms(700000);
    memset(g_coalesce, 0, sizeof g_coalesce);
    fw_events_note_write_denied(10337, 0, "/0/RO/x.jpg", NSP_ACL_OP_MKDIR, -EROFS);
    fw_drain_ring();
    fw_events_set_test_now_ms(700300);
    fw_coalesce_flush_due();
    CHECK(drv_recv(buf, sizeof buf) < 0, "filter 未含 write_denied 时不得收到该事件");
    g_subs[0].mask = FW_EV_MASK_DONE | FW_EV_MASK_DENIED | FW_EV_MASK_PING;
    fw_events_set_test_now_ms(800000);
    fw_events_note_write_denied(10337, 0, "/0/RO/x.jpg", NSP_ACL_OP_MKDIR, -EROFS);
    fw_drain_ring();
    fw_events_set_test_now_ms(800300);
    fw_coalesce_flush_due();
    CHECK(drv_recv(buf, sizeof buf) > 0, "filter 含 write_denied 时应收到");
    CHECK(has(buf, "\"op\":\"mkdir\""), "mkdir 被拒的 op 错: %s", buf);
}

/* packages.list 夹具：写完即 fw_pkg_reload()——生产上"配置重载"是唯一的
   重解析时机，这里用它把 (包名, 代际) 缓存打掉，否则第二次读到的是旧结果。 */
static void pkglist_set(const char* body) {
    FILE* f = fopen(g_pkglist, "w");
    if (!f) {
        fprintf(stderr, "packages.list 夹具写入失败: %s\n", g_pkglist);
        exit(1);
    }
    fputs(body, f);
    fclose(f);
    fw_pkg_reload();
}

/* 最后一个订阅者消失后，合并槽必须被清掉、poll 超时必须回到上限。
   槽只有 flush 才清：遗留槽的 deadline 永远是过去时，超时恒 0，事件线程
   poll(…,0) 空转（现场形态：daemon 单线程 CPU 90%、请求全堵，杀掉该进程
   积压瞬间释放）。 */
static void test_no_sub_coalesce_drain(void) {
    channel_up();
    char buf[2048];
    while (drv_recv(buf, sizeof buf) > 0) {
    }
    while (fw_ring_pop(&(FwEventRec){0}, 1) > 0) {
    }
    memset(g_coalesce, 0, sizeof g_coalesce);
    atomic_store(&g_fw_events_hot, true);
    fw_events_set_test_now_ms(950000);
    /* 两个不同 vpath → 两个合并槽（同 vpath 会被合并成一条） */
    fw_events_note_write_done(10337, 0, "/0/Pictures/a.jpg", FW_EV_OP_CREATE, NULL);
    fw_events_note_write_done(10337, 0, "/0/Pictures/b.jpg", FW_EV_OP_CREATE, NULL);
    fw_drain_ring();
    CHECK(fw_coalesce_timeout() > 0, "窗口未到期时超时不应为 0（会无谓唤醒）");
    /* 等价于 sendto 连续失败后的摘除结果：订阅表清空、计数归零 */
    g_subs[0].used = false;
    g_sub_count = 0;
    fw_update_hot();
    fw_events_set_test_now_ms(950300); /* 已过 200ms 合并窗口 */
    fw_events_maintain();              /* 生产线程每轮都会调它 */
    int timeout = fw_coalesce_timeout();
    CHECK(timeout == FW_EVENTS_POLL_MAX_MS,
          "无订阅者时 poll 超时必须回到上限，实际 %d（0 会让事件线程空转烧核）", timeout);
    bool leftover = false;
    for (int i = 0; i < FW_EVENTS_COALESCE_SLOTS; i++) {
        if (g_coalesce[i].used) leftover = true;
    }
    CHECK(!leftover, "无订阅者时遗留的合并槽必须被 flush 清掉");

    /* 订阅者回来之后仍然能正常收事件（clean 之后不留自锁状态） */
    channel_up();
    while (drv_recv(buf, sizeof buf) > 0) {
    }
    fw_events_set_test_now_ms(960000);
    fw_events_note_write_done(10337, 0, "/0/Pictures/c.jpg", FW_EV_OP_CREATE, NULL);
    fw_drain_ring();
    fw_events_set_test_now_ms(960300);
    fw_events_maintain();
    CHECK(drv_recv(buf, sizeof buf) > 0, "订阅者重新登记后必须恢复推送");
}

static void test_whitelist(void) {
    channel_up();
    g_global_cfg.fuse_events_uid_count = 0;

    /* 夹具一：两个 MediaProvider 包名都在。10277 是设备实测值
       （OPD2404/Android16，com.android.providers.media.module）；
       另一个包名给不同 uid，确保两个包名**各自**被解析、不是只认第一个。 */
    pkglist_set(
        "com.android.providers.media.module 10277 0 "
        "/data/user/0/com.android.providers.media.module platform:privapp:targetSdkVersion=36\n"
        "com.android.providers.media 10112 0 /data/user/0/com.android.providers.media "
        "platform:privapp:targetSdkVersion=36\n"
        "com.test.other 10337 0 /data/user/0/com.test.other default:targetSdkVersion=36\n");
    /* 生产路径：白名单由 fw_build_allow_list 从默认三项 + 解析项 + 配置构造 */
    fw_build_allow_list();
    CHECK(fw_uid_allowed(0) && fw_uid_allowed(1000) && fw_uid_allowed(1023),
          "root/system/media_rw 必须在白名单");
    CHECK(fw_uid_allowed(10277),
          "com.android.providers.media.module 的 uid 必须自动进白名单");
    CHECK(fw_uid_allowed(10112), "com.android.providers.media 的 uid 必须自动进白名单");
    CHECK(!fw_uid_allowed(10337), "普通应用默认不在白名单");

    /* [GLOBAL] FUSE_EVENTS_UIDS 追加后生效 */
    g_global_cfg.fuse_events_uids[0] = 10337;
    g_global_cfg.fuse_events_uid_count = 1;
    fw_build_allow_list();
    CHECK(fw_uid_allowed(10337), "配置追加的 uid 应进白名单");
    CHECK(fw_uid_allowed(1000), "追加不得挤掉默认项");
    CHECK(fw_uid_allowed(10277), "追加不得挤掉自动解析项");
    g_global_cfg.fuse_events_uid_count = 0;

    /* 夹具二：删掉那两行 → 白名单里就没有它们（解析失败只少这一项，不报错） */
    pkglist_set("com.test.other 10337 0 /data/user/0/com.test.other default\n");
    fw_build_allow_list();
    CHECK(!fw_uid_allowed(10277) && !fw_uid_allowed(10112),
          "packages.list 无该行时不得把 MediaProvider 的 uid 放进白名单");
    CHECK(fw_uid_allowed(0) && fw_uid_allowed(1000) && fw_uid_allowed(1023),
          "解析不到时只剩默认三项（通道照常起）");

    /* 夹具三：两个包名同一 uid（旧 ROM / 别名）→ 去重后只占一项 */
    pkglist_set(
        "com.google.android.providers.media.module 10277 0 /data/user/0/a default\n"
        "com.android.providers.media 10277 0 /data/user/0/b default\n");
    fw_build_allow_list();
    CHECK(fw_uid_allowed(10277) && g_allow_count == 4,
          "两个包名同一 uid 应去重（白名单 %d 项，期望 4 = 3 默认 + 1 解析）", g_allow_count);

    fw_pkg_set_packagelist_path(NULL); /* 还原默认路径（生产代码从不设钩子） */
}

/* 路径长度契约：整串发布或整条不发，绝不发布截断后的"另一个路径"。
   FUSE 视角路径合法长度可到 PATH_MAX，事件缓存只有 FW_EVENTS_PATH_MAX：
   截断后 /0/Pictures/<244B>.jpg 的后缀会变成别的名字，派生出的 spath 指向不存在
   或别人的文件，扫描侧据此扫描等于漏原文件 + 查错文件。 */
static void fill_path(char* out, size_t total, char ch) {
    static const char head[] = "/0/Pictures/";
    size_t h = sizeof head - 1;
    memcpy(out, head, h);
    memset(out + h, ch, total - h);
    out[total] = '\0';
}

static void test_oversize_path(void) {
    channel_up();
    char buf[2048];
    while (drv_recv(buf, sizeof buf) >= 0) {
    }
    while (fw_ring_pop(&(FwEventRec){0}, 1) > 0) {
    }
    memset(g_coalesce, 0, sizeof g_coalesce);
    atomic_store(&g_fw_events_hot, true);
    atomic_store(&g_ev_oversize_dropped, 0);

    /* ① 255 字节（缓存 256 含 NUL）刚好装得下 → 照常发布且一字不差 */
    char fits[400];
    fill_path(fits, 255, 'a');
    fw_events_set_test_now_ms(1000000);
    fw_events_note_write_done(10337, 0, fits, FW_EV_OP_CLOSE_WRITE, NULL);
    CHECK(g_ring_count == 1, "255 字节路径应入队（实际 count=%d）", g_ring_count);
    fw_drain_ring();
    fw_events_set_test_now_ms(1000300);
    fw_coalesce_flush_due();
    CHECK(drv_recv(buf, sizeof buf) > 0, "255 字节路径应发出");
    CHECK(has(buf, fits + 2), "255 字节路径必须整串发布（不得截断）");
    CHECK(atomic_load(&g_ev_oversize_dropped) == 0, "装得下的路径不得计丢弃");

    /* ② 256 字节（缓存装不下）→ 整条不发，计入 dropped */
    char too_long[400];
    fill_path(too_long, 256, 'b');
    fw_events_note_write_done(10337, 0, too_long, FW_EV_OP_CLOSE_WRITE, NULL);
    CHECK(g_ring_count == 0, "超长路径不得入队（实际 count=%d）", g_ring_count);
    CHECK(atomic_load(&g_ev_oversize_dropped) == 1, "超长路径应计入丢弃（实际 %u）",
          atomic_load(&g_ev_oversize_dropped));
    fw_drain_ring();
    fw_coalesce_flush_due();
    CHECK(drv_recv(buf, sizeof buf) < 0, "超长路径不得发布任何帧");

    /* ③ write_denied 同一口径（否则拒绝事件会带着截断路径） */
    fw_events_note_write_denied(10337, 0, too_long, NSP_ACL_OP_CREATE, -EROFS);
    CHECK(g_ring_count == 0, "超长路径的写拒绝也不得入队");
    CHECK(atomic_load(&g_ev_oversize_dropped) == 2, "写拒绝同样计入丢弃（实际 %u）",
          atomic_load(&g_ev_oversize_dropped));

    /* ④ rename 的源超长：目的端事件仍然有效，源字段整对不发（不能清错行） */
    fw_events_set_test_now_ms(1010000);
    fw_events_note_write_done(10337, 0, "/0/Pictures/dst.jpg", FW_EV_OP_RENAME, too_long);
    CHECK(g_ring_count == 0, "rename 源超长时整条不发（实际 count=%d）", g_ring_count);
    CHECK(atomic_load(&g_ev_oversize_dropped) == 3, "rename 源超长计入丢弃（实际 %u）",
          atomic_load(&g_ev_oversize_dropped));

    /* ⑤ 路径装得下但 JSON 转义后超帧：一样整条不发（引号/反斜杠是合法文件名字符） */
    char esc[400];
    size_t h = sizeof "/0/Pictures/" - 1;
    memcpy(esc, "/0/Pictures/", h);
    memset(esc + h, '\\', 255 - h);
    esc[255] = '\0';
    fw_events_set_test_now_ms(1020000);
    fw_events_note_write_done(10337, 0, esc, FW_EV_OP_CLOSE_WRITE, NULL);
    CHECK(g_ring_count == 1, "转义型路径本身装得下（实际 count=%d）", g_ring_count);
    fw_drain_ring();
    fw_events_set_test_now_ms(1020300);
    fw_coalesce_flush_due();
    CHECK(drv_recv(buf, sizeof buf) < 0, "转义后超帧不得发出半截 JSON");
    CHECK(atomic_load(&g_ev_oversize_dropped) == 4, "超帧计入丢弃（实际 %u）",
          atomic_load(&g_ev_oversize_dropped));

    /* ⑥ 丢弃数如实进入心跳，订阅者能知道自己漏了事件 */
    g_next_ping_ms = 0;
    fw_maybe_ping();
    CHECK(drv_recv(buf, sizeof buf) > 0, "心跳应发出");
    CHECK(has(buf, "\"type\":\"ping\""), "心跳 type 错: %s", buf);
    CHECK(has(buf, "\"dropped\":4"), "心跳应上报 4 条丢弃（实际: %s）", buf);

    memset(g_coalesce, 0, sizeof g_coalesce);
    while (fw_ring_pop(&(FwEventRec){0}, 1) > 0) {
    }
}

int main(void) {
    snprintf(g_fake_base, sizeof g_fake_base, "/tmp/fw_ev_drv_%d", (int)getpid());
    rm_rf(g_fake_base);
    /* 白名单要解析 packages.list：把读取路径钩到夹具（生产恒为 /data/system/
       packages.list，GNU 宿主没有这个文件）。路径串必须活得比钩子久 */
    snprintf(g_pkglist, sizeof g_pkglist, "%s/packages.list", g_fake_base);
    fw_pkg_set_packagelist_path(g_pkglist);
    char p[256];
    snprintf(p, sizeof p, "%s/0/Pictures", g_fake_base);
    mkdir_p(p);
    snprintf(p, sizeof p, "%s/0/Pictures/a.jpg", g_fake_base);
    touch(p);
    snprintf(p, sizeof p, "%s/0/RO", g_fake_base);
    mkdir_p(p);
    snprintf(p, sizeof p, "%s/0/RO/x.jpg", g_fake_base);
    touch(p);
    snprintf(p, sizeof p, "%s/10/Pictures", g_fake_base);
    mkdir_p(p);
    snprintf(p, sizeof p, "%s/10/Pictures/a.jpg", g_fake_base);
    touch(p);
    snprintf(p, sizeof p, "%s/0/Private", g_fake_base);
    mkdir_p(p);
    snprintf(p, sizeof p, "%s/0/Private/x.jpg", g_fake_base);
    touch(p);
    snprintf(p, sizeof p, "%s/0/Movies", g_fake_base);
    mkdir_p(p);
    snprintf(p, sizeof p, "%s/0/Allow", g_fake_base);
    mkdir_p(p);
    snprintf(p, sizeof p, "%s/0/Allow/a.jpg", g_fake_base);
    touch(p);

    test_early_exit();
    test_event_fields();
    test_coalesce();
    test_ring_drop();
    test_query_six();
    test_query_reasons();
    test_user10_and_ttl();
    test_media_refresh();
    test_sub_filters();
    test_no_sub_coalesce_drain();
    test_oversize_path();
    test_whitelist();

    rm_rf(g_fake_base);
    fprintf(stderr, "fw_events driver: %d 通过, %d 失败\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
