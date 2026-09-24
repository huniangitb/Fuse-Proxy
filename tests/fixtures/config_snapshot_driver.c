/*
 * test_config_snapshot.py 专用 C 驱动（fixture）。
 *
 * 由 Python 脚本连同「实际源码」（src/config/config_parser.c、
 * src/injector/config_publisher.c 及其依赖）临时编译成测试二进制，不经 Meson
 * （不新增 C 测试目标）。CONFIG_DIR 在编译期被脚本指向临时 fixture 根目录，
 * 使 App-rules* 扫描与 app_rules 内容回显可在普通用户下验证。
 *
 * 验证内容：
 *   1. load_config_rules 后的 AppConfig 快照：默认值、global、pkg、pkg:uid、
 *      类别段、ALLOW 与 REDIRECT 的区分、路径前缀归一、变量赋值。
 *   2. config_publisher 的 STATIC JSON：global/apps 段复用同一快照（已解析视图），
 *      app_rules 段保留磁盘原始文件内容。
 *   3. STATIC 请求不得触发配置重载（g_app_cfgs 指针不变）。
 *   4. 规则数组容量增长回归：每类 40 条（跨 8→16→32→64 多次扩容），校验计数与
 *      每一条规则（含末尾）都在——覆盖 grow_rule_array 未回写 *cap 的越界写回归。
 *
 * 输出：每项一行 "PASS <名称>" / "FAIL <名称>"，末尾汇总；有失败时退出码 1。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <signal.h>
#include <limits.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <unistd.h>
#include <json-c/json.h>

#include "config_parser.h"
#include "config_publisher.h"
#include "common.h"
#include "injector.h"
#include "nsp_util.h"

/* injector 全局符号：config_publisher 引用（测试不链接 injector.c，此处占位） */
struct GlobalFuseInfo g_global_fuse;
struct GlobalFuseInfo g_media_fuse;
volatile sig_atomic_t g_should_exit = 0;
volatile sig_atomic_t g_reload_config = 0;
volatile sig_atomic_t g_passive_mode = 0;
volatile sig_atomic_t g_fuse_ready = 0;
int g_epoll_fd = -1;
int g_global_root_fd = -1;
bool g_global_replace_mode = false;

static int g_pass = 0;
static int g_fail = 0;

static void ck(bool ok, const char* name) {
    if (ok) {
        g_pass++;
        printf("PASS %s\n", name);
    } else {
        g_fail++;
        printf("FAIL %s\n", name);
    }
}

static bool streq(const char* a, const char* b) {
    return a && b && strcmp(a, b) == 0;
}

static AppConfig* find_app(const char* pkg, int uid) {
    for (int i = 0; i < g_app_cfg_count; i++) {
        if (g_app_cfgs[i] && g_app_cfgs[i]->user_id == uid &&
            strcmp(g_app_cfgs[i]->pkg_name, pkg) == 0)
            return g_app_cfgs[i];
    }
    return NULL;
}

static bool has_str(char* const* arr, int count, const char* want) {
    for (int i = 0; i < count; i++) {
        if (streq(arr[i], want)) return true;
    }
    return false;
}

static const RedirectRule* find_redir(const AppConfig* cfg, bool is_allow, const char* vp) {
    for (int i = 0; i < cfg->redir_count; i++) {
        if (cfg->redir_rules[i].is_allow == is_allow &&
            strcmp(cfg->redir_rules[i].virtual_prefix, vp) == 0)
            return &cfg->redir_rules[i];
    }
    return NULL;
}

static void check_snapshot(void) {
    /* ---- 默认值（fixture 未写 MONITOR/SANDBOX/SKIP_SYSTEM_APPS） ---- */
    ck(g_global_cfg.global_inject == true, "snapshot.global_inject ON");
    ck(g_global_cfg.skip_system_apps == true, "snapshot.skip_system_apps 默认 ON");
    ck(g_global_cfg.monitor == false && g_global_cfg.monitor_explicit == false,
       "snapshot.monitor 默认 OFF 且非显式");
    ck(g_global_cfg.sandbox == false && g_global_cfg.sandbox_explicit == false,
       "snapshot.sandbox 默认 OFF 且非显式");
    ck(streq(g_global_cfg.fuse_extra_args, "--strip-o-direct"), "snapshot.FUSE_EXTRA_ARGS 原样");

    /* ---- [GLOBAL] 规则（含归一与 ALLOW/REDIRECT 区分） ---- */
    ck(g_global_cfg.hide_count == 2 &&
           has_str(g_global_cfg.hide_rules, g_global_cfg.hide_count, "/sdcard/Secret") &&
           has_str(g_global_cfg.hide_rules, g_global_cfg.hide_count, "/EmuHidden"),
       "snapshot.global HIDE 归一(/storage/emulated 剥离)");
    ck(g_global_cfg.ro_count == 2 &&
           has_str(g_global_cfg.ro_rules, g_global_cfg.ro_count, "/sdcard/ReadOnly") &&
           has_str(g_global_cfg.ro_rules, g_global_cfg.ro_count, "/sdcard/*/cache/"),
       "snapshot.global RO 通配保留尾斜杠");
    const RedirectRule* r1 = find_redir(&g_global_cfg, false, "/files");
    ck(r1 && streq(r1->real_target, "?/Download"), "snapshot.global REDIRECT 相对目标 ? 前缀");
    const RedirectRule* r2 = find_redir(&g_global_cfg, false, "/emudir");
    ck(r2 && streq(r2->real_target, "?/Download"),
       "snapshot.global REDIRECT /storage/emulated 剥离");
    const RedirectRule* r3 = find_redir(&g_global_cfg, false, "/vardir");
    ck(r3 && streq(r3->real_target, "$DATA_BASE/files"), "snapshot.global REDIRECT 变量目标原样");
    const RedirectRule* a1 = find_redir(&g_global_cfg, true, "/system/fonts");
    ck(a1 && streq(a1->real_target, "?/system/fonts"), "snapshot.global ALLOW 归入 is_allow");
    ck(find_redir(&g_global_cfg, false, "/system/fonts") == NULL,
       "snapshot.global ALLOW 不计入 REDIRECT");
    ck(g_global_cfg.var_count == 1 && streq(g_global_cfg.var_names[0], "DATA_BASE") &&
           streq(g_global_cfg.var_values[0], "/sdcard/AppData"),
       "snapshot.global 变量赋值");

    /* ---- [pkg] / [pkg:uid] ----
       [pkg] 省略 :uid 时主文件解析以 user_id=-1 表示"跨用户 fallback"
       （find_app_cfg_locked 第二段精确匹配 -1），并非 user 0。 */
    AppConfig* app0 = find_app("com.example.app", -1);
    ck(app0 && app0->inject_enable, "snapshot.[pkg] 默认使能 ON 且 user_id=-1");
    ck(app0 && app0->monitor == true && app0->monitor_explicit, "snapshot.[pkg] MONITOR 显式 ON");
    ck(app0 && app0->sandbox == false, "snapshot.[pkg] SANDBOX 默认 OFF");
    ck(app0 && app0->hide_count == 1 && streq(app0->hide_rules[0], "/sdcard/AppSecret"),
       "snapshot.[pkg] HIDE");
    const RedirectRule* ar = app0 ? find_redir(app0, false, "/appdir") : NULL;
    ck(ar && streq(ar->real_target, "/data/media/0/AppDir"),
       "snapshot.[pkg] REDIRECT 系统绝对目标原样");

    AppConfig* app999 = find_app("com.example.app", 999);
    ck(app999 && app999->sandbox == true && app999->sandbox_explicit,
       "snapshot.[pkg:uid] 独立作用域 SANDBOX ON");
    const RedirectRule* al = app999 ? find_redir(app999, true, "/sdcard/Public") : NULL;
    ck(al && streq(al->real_target, "?/sdcard/Public"), "snapshot.[pkg:uid] ALLOW");

    /* ---- 类别段 ---- */
    AppConfig* ua = find_app("USER_APPS", 0);
    ck(ua && ua->hide_count == 1 && streq(ua->hide_rules[0], "/sdcard/CatSecret"),
       "snapshot.[USER_APPS:0]");
    AppConfig* sa = find_app("SYSTEM_APPS", -1);
    ck(sa && sa->ro_count == 1 && streq(sa->ro_rules[0], "/system/vendor"),
       "snapshot.[SYSTEM_APPS] uid 归一为 -1");

    /* ---- App-rules-<uid>/ 分文件 ---- */
    AppConfig* other = find_app("com.other.app", 999);
    ck(other && other->inject_enable, "snapshot.App-rules-999 分文件使能");
    ck(other && other->monitor == true && other->hide_count == 1 &&
           streq(other->hide_rules[0], "/sdcard/OtherHidden"),
       "snapshot.App-rules-999 规则内容");
}

/* ---- STATIC JSON 取回 ---- */
static char g_static_buf[256 * 1024];

static char* fetch_static(void) {
    int srv = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    int cli = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (srv < 0 || cli < 0) {
        if (srv >= 0) close(srv);
        if (cli >= 0) close(cli);
        return NULL;
    }
    struct timeval tv = {.tv_sec = 2, .tv_usec = 0};
    setsockopt(cli, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    struct sockaddr_un sa, ca;
    socklen_t sal = nsp_uds_abstract_addr(&sa, "nsp_test_cfg_snapshot_srv");
    socklen_t cal = nsp_uds_abstract_addr(&ca, "nsp_test_cfg_snapshot_cli");
    if (bind(srv, (struct sockaddr*)&sa, sal) < 0 || bind(cli, (struct sockaddr*)&ca, cal) < 0 ||
        sendto(cli, "STATIC", 6, 0, (struct sockaddr*)&sa, sal) < 0) {
        close(srv);
        close(cli);
        return NULL;
    }
    config_publisher_handle_readable(srv);
    ssize_t n = recv(cli, g_static_buf, sizeof(g_static_buf) - 1, 0);
    close(srv);
    close(cli);
    if (n <= 0) return NULL;
    g_static_buf[n] = '\0';
    return g_static_buf;
}

static json_object* obj_get(json_object* o, const char* key) {
    json_object* v = NULL;
    if (!o || !json_object_object_get_ex(o, key, &v)) return NULL;
    return v;
}

static bool arr_has_str(json_object* arr, const char* want) {
    if (!arr) return false;
    for (size_t i = 0; i < json_object_array_length(arr); i++) {
        json_object* e = json_object_array_get_idx(arr, i);
        if (e && streq(json_object_get_string(e), want)) return true;
    }
    return false;
}

static json_object* find_app_entry(json_object* apps, const char* pkg, int uid) {
    if (!apps) return NULL;
    for (size_t i = 0; i < json_object_array_length(apps); i++) {
        json_object* e = json_object_array_get_idx(apps, i);
        json_object* p = obj_get(e, "pkg");
        json_object* u = obj_get(e, "user_id");
        if (p && u && streq(json_object_get_string(p), pkg) && json_object_get_int(u) == uid)
            return e;
    }
    return NULL;
}

static void check_static_json(void) {
    char* raw = fetch_static();
    ck(raw != NULL, "static.STATIC 请求有响应");
    if (!raw) return;
    json_object* root = json_tokener_parse(raw);
    ck(root != NULL, "static.JSON 可解析");
    if (!root) return;

    ck(streq(json_object_get_string(obj_get(root, "type")), "static"), "static.type=static");
    ck(json_object_get_int64(obj_get(root, "timestamp")) > 0, "static.timestamp 存在");

    json_object* global = obj_get(root, "global");
    ck(global != NULL, "static.global 为对象（快照可用，非 null）");
    json_object* sw = obj_get(global, "switches");
    ck(streq(json_object_get_string(obj_get(sw, "global_inject")), "ON"),
       "static.switches.global_inject=ON");
    ck(streq(json_object_get_string(obj_get(sw, "monitor")), "OFF"),
       "static.switches.monitor=OFF（默认值）");
    ck(streq(json_object_get_string(obj_get(sw, "sandbox")), "OFF"),
       "static.switches.sandbox=OFF（默认值）");

    json_object* hide = obj_get(global, "hide_rules");
    ck(arr_has_str(hide, "/sdcard/Secret") && arr_has_str(hide, "/EmuHidden"),
       "static.global.hide_rules 来自快照（含归一）");
    json_object* ro = obj_get(global, "ro_rules");
    ck(arr_has_str(ro, "/sdcard/ReadOnly") && arr_has_str(ro, "/sdcard/*/cache/"),
       "static.global.ro_rules 来自快照");

    json_object* redir = obj_get(global, "redirect_rules");
    ck(arr_has_str(redir, "/files /Download") && arr_has_str(redir, "/emudir /Download") &&
           arr_has_str(redir, "/vardir $DATA_BASE/files"),
       "static.global.redirect_rules 仅 REDIRECT 且目标剥离 ? 前缀");
    ck(!arr_has_str(redir, "/system/fonts ?/system/fonts"),
       "static.global.redirect_rules 不含 ALLOW");
    json_object* allow = obj_get(global, "allow_rules");
    ck(arr_has_str(allow, "/system/fonts"), "static.global.allow_rules 仅 ALLOW");

    json_object* apps = obj_get(root, "apps");
    json_object* e0 = find_app_entry(apps, "com.example.app", -1);
    ck(e0 && streq(json_object_get_string(obj_get(e0, "inject_enable")), "ON"),
       "static.apps com.example.app 无 :uid 段 user_id=-1");
    json_object* e999 = find_app_entry(apps, "com.example.app", 999);
    ck(e999 && streq(json_object_get_string(obj_get(e999, "inject_enable")), "ON"),
       "static.apps com.example.app:999 保留 user_id");
    json_object* eother = find_app_entry(apps, "com.other.app", 999);
    ck(eother && streq(json_object_get_string(obj_get(eother, "inject_enable")), "ON"),
       "static.apps 含 App-rules-999 分文件应用");
    json_object* ua = find_app_entry(apps, "USER_APPS", 0);
    json_object* sa = find_app_entry(apps, "SYSTEM_APPS", -1);
    ck(ua && streq(json_object_get_string(obj_get(ua, "scope")), "category"),
       "static.apps USER_APPS 带 scope=category");
    ck(sa && streq(json_object_get_string(obj_get(sa, "scope")), "category"),
       "static.apps SYSTEM_APPS uid=-1 且 scope=category");

    /* ---- app_rules：磁盘原始文件内容 ---- */
    json_object* app_rules = obj_get(root, "app_rules");
    bool found_file = false;
    bool content_ok = false;
    if (app_rules) {
        for (size_t i = 0; i < json_object_array_length(app_rules); i++) {
            json_object* e = json_object_array_get_idx(app_rules, i);
            if (streq(json_object_get_string(obj_get(e, "file")), "com.other.app.conf") &&
                streq(json_object_get_string(obj_get(e, "user_dir")), "App-rules-999")) {
                found_file = true;
                const char* c = json_object_get_string(obj_get(e, "content"));
                content_ok = c && strstr(c, "HIDE /sdcard/OtherHidden") != NULL;
            }
        }
    }
    ck(found_file, "static.app_rules 含 App-rules-999/com.other.app.conf");
    ck(content_ok, "static.app_rules 回显磁盘原始文件内容");

    json_object_put(root);
}

/* ================= 容量增长回归 =================
   规则数组按 8→16→32→64 倍增；此前 grow_rule_array 分配新容量后未回写
   *cap，导致第 9 条起按"容量 8"继续写入（越界）。本用例每类 40 条，跨三次
   扩容，校验计数与每一条规则（含末尾规则）都在。 */
#define CAP_N 40

static bool has_ftp(const AppConfig* cfg, const char* vp) {
    for (int i = 0; i < cfg->ftp_count; i++) {
        if (streq(cfg->ftp_rules[i].virtual_prefix, vp)) return true;
    }
    return false;
}

static void check_capacity(const char* main_conf) {
    char dir[PATH_MAX];
    snprintf(dir, sizeof dir, "%s", main_conf);
    char* slash = strrchr(dir, '/');
    if (slash)
        *slash = '\0';
    else
        snprintf(dir, sizeof dir, ".");
    char conf[PATH_MAX];
    snprintf(conf, sizeof conf, "%s/capacity.conf", dir);

    FILE* f = fopen(conf, "w");
    if (!f) {
        ck(false, "capacity.生成扩容 fixture");
        return;
    }
    fputs("[GLOBAL]\n", f);
    for (int i = 0; i < CAP_N; i++) fprintf(f, "HIDE /cap/hide/%03d\n", i);
    for (int i = 0; i < CAP_N; i++) fprintf(f, "RO /cap/ro/%03d\n", i);
    for (int i = 0; i < CAP_N; i++) fprintf(f, "REDIRECT /cap/redir/%03d /cap/target/%03d\n", i, i);
    for (int i = 0; i < CAP_N; i++) fprintf(f, "ALLOW /cap/allow/%03d\n", i);
    for (int i = 0; i < CAP_N; i++) fprintf(f, "FTP /cap/ftp/%03d capsec%03d\n", i, i);
    fclose(f);

    load_config_rules(conf);

    ck(g_global_cfg.hide_count == CAP_N, "capacity.HIDE 计数=40（跨多次扩容）");
    ck(g_global_cfg.ro_count == CAP_N, "capacity.RO 计数=40");
    ck(g_global_cfg.ftp_count == CAP_N, "capacity.FTP 计数=40");

    int redir_n = 0, allow_n = 0;
    for (int i = 0; i < g_global_cfg.redir_count; i++) {
        if (g_global_cfg.redir_rules[i].is_allow)
            allow_n++;
        else
            redir_n++;
    }
    ck(redir_n == CAP_N && allow_n == CAP_N, "capacity.REDIRECT/ALLOW 计数各=40");

    int miss_hide = 0, miss_ro = 0, miss_redir = 0, miss_allow = 0, miss_ftp = 0;
    char want[MAX_PATH_LEN];
    char tgt[MAX_PATH_LEN];
    for (int i = 0; i < CAP_N; i++) {
        snprintf(want, sizeof want, "/cap/hide/%03d", i);
        if (!has_str(g_global_cfg.hide_rules, g_global_cfg.hide_count, want)) miss_hide++;
        snprintf(want, sizeof want, "/cap/ro/%03d", i);
        if (!has_str(g_global_cfg.ro_rules, g_global_cfg.ro_count, want)) miss_ro++;
        snprintf(want, sizeof want, "/cap/redir/%03d", i);
        snprintf(tgt, sizeof tgt, "?/cap/target/%03d", i);
        const RedirectRule* rr = find_redir(&g_global_cfg, false, want);
        if (!rr || !streq(rr->real_target, tgt)) miss_redir++;
        snprintf(want, sizeof want, "/cap/allow/%03d", i);
        if (!find_redir(&g_global_cfg, true, want)) miss_allow++;
        snprintf(want, sizeof want, "/cap/ftp/%03d", i);
        if (!has_ftp(&g_global_cfg, want)) miss_ftp++;
    }
    ck(miss_hide == 0, "capacity.HIDE 40 条全部保留（含末尾规则）");
    ck(miss_ro == 0, "capacity.RO 40 条全部保留（含末尾规则）");
    ck(miss_redir == 0, "capacity.REDIRECT 40 条全部保留且目标正确");
    ck(miss_allow == 0, "capacity.ALLOW 40 条全部保留（含末尾规则）");
    ck(miss_ftp == 0, "capacity.FTP 40 条全部保留（含末尾规则）");
}

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <main_conf>\n", argv[0]);
        return 2;
    }
    config_init_lock();
    /* 只读加载方语义：不 popen(pm)、不 mkdir App-rules 目录 */
    config_set_scan_users_skip_pm(true);
    config_set_allow_app_rules_mkdir(false);
    load_config_rules(argv[1]);

    check_snapshot();

    /* STATIC 请求不得重载配置：live 数组指针在请求前后必须一致 */
    AppConfig** before_apps = g_app_cfgs;
    int before_count = g_app_cfg_count;
    check_static_json();
    ck(g_app_cfgs == before_apps && g_app_cfg_count == before_count,
       "static.请求不触发配置重载（live 快照未替换）");

    check_capacity(argv[1]);

    printf("SUMMARY pass=%d fail=%d\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
