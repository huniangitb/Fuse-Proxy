/* SPDX-License-Identifier: GPL-3.0-or-later */
/* 版权所有 (C) 2026 huniangitb <3361107168@qq.com> */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <poll.h>
#include <sys/epoll.h>
#include <stddef.h>
#include <ctype.h>
#include <signal.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <time.h>
#include <json-c/json.h>
#include "common.h"
#include "nsp_util.h"
#include "nsp_rule_file.h"
#include "config_parser.h"

static volatile sig_atomic_t g_running = 1;

/* 配置根目录与主配置路径：默认编译期 CONFIG_DIR，可经 --config-dir 覆盖
   （与 rule_server 同名选项一致，测试可指向临时目录，无需写 /var/fuse-proxy）。
   g_main_conf 由 config_paths_init 在参数解析后填充。 */
static char g_config_dir[PATH_MAX] = CONFIG_DIR;
static char g_main_conf[PATH_MAX];

static void config_paths_init(void) {
    snprintf(g_main_conf, sizeof(g_main_conf), "%s/injector.conf", g_config_dir);
}

void sigint_handler(int sig) {
    (void)sig;
    g_running = 0;
}

void usage(const char* prog) {
    printf("用法: %s <command> [--level level] [args]\n", prog);
    printf("\n日志查询命令:\n");
    printf("  search-io|search-sys [--level level] [key] [limit] [offset] [-u] [api]\n");
    printf("    --level level: 日志级别过滤（仅 search-sys 有效）\n");
    printf("           0=DEBUG 1=INFO 2=WARN 3=ERROR (-1=全部，默认-1)\n");
    printf("  clear-io|clear-sys\n");
    printf("\n日志统计命令:\n");
    printf("  log-count [api]            获取当前日志缓冲区总计条数（JSON）\n");
    printf("\n流式日志命令（实时输出，Ctrl+C 停止）:\n");
    printf("  stream-io|stream-sys|stream-logcat|stream-all [--level level] [-u]\n");
    printf("    --level level: 最低日志级别，仅显示 >= 此级别的日志\n");
    printf("           0=DEBUG 1=INFO 2=WARN 3=ERROR (默认0)\n");
    printf("\n注入状态命令:\n");
    printf("  list-injected [api]        列出已注入应用列表\n");
    printf("  list-users [api]           列出当前活跃用户及对应应用数\n");
    printf("\n配置查看命令:\n");
    printf("  get-config [api]           获取当前内存中的解析后配置（JSON）\n");
    printf("  get-config --static [api]  从磁盘读取原始规则文件内容（JSON）\n");
    printf("  stream-config [api]       订阅配置变更推送（Ctrl+C 停止）\n");
    printf("\n本地规则解析与配置命令 (API 友好):\n");
    printf("  parse-rules [api]          直接解析本地磁盘规则文件，输出结构化 JSON\n");
    printf("  get-global-rules [api]     查看本地 [GLOBAL] 段全部规则（开关+路径）\n");
    printf("  get-app-rules <pkg> [--uid uid] [api]\n");
    printf("                             查看指定应用的配置和规则\n");
    printf("  validate-rules [api]       验证本地规则语法正确性\n");
    printf("  reload-config [api]        重新加载配置（向注入器发送 SIGHUP）\n");
    printf("  status [api]               全面系统状态概览（JSON）\n");
    printf("  set-rule <pkg> <type> <value> [--uid uid] [api]\n");
    printf("                             添加/更新规则到文件\n");
    printf(
        "                              type: HIDE|RO|REDIRECT|ALLOW|MONITOR|SANDBOX|GLOBAL_INJECT\n");
    printf("  remove-rule <pkg> <type> <index> [--uid uid] [api]\n");
    printf("                             删除指定索引的规则\n");
    printf("\n选项:\n");
    printf("  -u               始终显示 UID\n");
    printf("  api              以 API 格式输出（供程序调用，结构化 JSON）\n");
    printf("  --uid <uid>      指定用户 ID（默认 0）\n");
    printf("  --config-dir <dir>  覆盖配置根目录（默认 %s）\n", CONFIG_DIR);
    exit(1);
}

/* ========== JSON API 结构化输出 ========== */
static void json_api_finish(bool api_mode, const char* cmd, const char* json_data) {
    (void)cmd;
    if (!api_mode) return;
    printf("%s\n", json_data ? json_data : "{}");
}

static void json_api_error(bool api_mode, const char* cmd, const char* error_msg) {
    if (!api_mode) {
        fprintf(stderr, "错误: %s\n", error_msg ? error_msg : "未知错误");
        return;
    }
    json_object* root = json_object_new_object();
    json_object_object_add(root, "status", json_object_new_string("error"));
    json_object_object_add(root, "command", cmd ? json_object_new_string(cmd) : NULL);
    json_object_object_add(root, "error", error_msg ? json_object_new_string(error_msg) : NULL);
    json_object_object_add(root, "timestamp", json_object_new_int64(time(NULL)));
    printf("%s\n", json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN));
    json_object_put(root);
}

/* ========== 配置文件读写辅助 ========== */
static int read_pid_file(const char* path) {
    FILE* fp = fopen(path, "r");
    if (!fp) return -1;
    int pid = -1;
    if (fscanf(fp, "%d", &pid) != 1) pid = -1;
    fclose(fp);
    return pid;
}

static const char* send_reload_signal(void) {
    int pid = read_pid_file(INJECTOR_PID_PATH);
    if (pid <= 0) return "无法读取注入器 PID 文件";
    if (kill(pid, SIGHUP) != 0) {
        static char err_buf[128];
        snprintf(err_buf, sizeof(err_buf), "发送 SIGHUP 到 PID %d 失败: %s", pid, strerror(errno));
        return err_buf;
    }
    return NULL;
}

/* ========== 解析本地规则 ========== */
static json_object* build_parsed_rules_json(void) {
    json_object* root = json_object_new_object();
    config_lock_read();

    json_object* global = json_object_new_object();
    json_object_object_add(global, "sandbox", json_object_new_boolean(g_global_cfg.sandbox));
    json_object_object_add(global, "global_inject",
                           json_object_new_boolean(g_global_cfg.global_inject));
    json_object_object_add(global, "monitor", json_object_new_boolean(g_global_cfg.monitor));
    json_object_object_add(global, "inject_enable", json_object_new_boolean(true));
    json_object_object_add(global, "hide_count", json_object_new_int(g_global_cfg.hide_count));
    json_object_object_add(global, "ro_count", json_object_new_int(g_global_cfg.ro_count));
    json_object_object_add(global, "redir_count", json_object_new_int(g_global_cfg.redir_count));
    json_object_object_add(root, "global", global);

    json_object* apps = json_object_new_array();
    for (int i = 0; i < g_app_cfg_count; i++) {
        AppConfig* cfg = g_app_cfgs[i];
        json_object* app = json_object_new_object();
        json_object_object_add(app, "pkg", json_object_new_string(cfg->pkg_name));
        json_object_object_add(app, "user_id", json_object_new_int(cfg->user_id));
        json_object_object_add(app, "inject_enable", json_object_new_boolean(cfg->inject_enable));
        json_object_object_add(app, "monitor", json_object_new_boolean(cfg->monitor));
        json_object_object_add(app, "sandbox", json_object_new_boolean(cfg->sandbox));
        json_object_object_add(app, "hide_count", json_object_new_int(cfg->hide_count));
        json_object_object_add(app, "ro_count", json_object_new_int(cfg->ro_count));
        json_object_object_add(app, "redir_count", json_object_new_int(cfg->redir_count));
        json_object_array_add(apps, app);
    }
    json_object_object_add(root, "apps", apps);

    config_unlock_read();
    return root;
}

static void handle_parse_rules(bool api_mode) {
    config_lock_write();
    load_config_rules(g_main_conf);
    config_unlock_write();
    json_object* json = build_parsed_rules_json();
    if (api_mode) {
        json_api_finish(true, "\"parse-rules\"",
                        json_object_to_json_string_ext(json, JSON_C_TO_STRING_PLAIN));
    } else {
        printf("===== 本地规则解析结果 =====\n%s\n",
               json_object_to_json_string_ext(json, JSON_C_TO_STRING_PLAIN));
    }
    json_object_put(json);
}

static void handle_validate_rules(bool api_mode) {
    config_lock_write();
    load_config_rules(g_main_conf);
    int app_count = g_app_cfg_count;
    config_unlock_write();
    if (api_mode) {
        json_object* root = json_object_new_object();
        json_object_object_add(root, "valid", json_object_new_boolean(true));
        json_object_object_add(root, "app_count", json_object_new_int(app_count));
        json_object_object_add(root, "global_hide_rules",
                               json_object_new_int(g_global_cfg.hide_count));
        json_object_object_add(root, "global_ro_rules", json_object_new_int(g_global_cfg.ro_count));
        json_object_object_add(root, "global_redir_rules",
                               json_object_new_int(g_global_cfg.redir_count));
        json_api_finish(true, "\"validate-rules\"",
                        json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN));
        json_object_put(root);
    } else {
        printf("规则验证通过。共解析 %d 个应用配置。\n", app_count);
        printf("全局: %d 条 HIDE, %d 条 RO, %d 条 REDIRECT\n", g_global_cfg.hide_count,
               g_global_cfg.ro_count, g_global_cfg.redir_count);
    }
}

/* 核心修复：分离 ALLOW 规则和 REDIRECT 规则并输出 */
static void handle_get_global_rules(bool api_mode) {
    config_lock_write();
    load_config_rules(g_main_conf);
    config_unlock_write();
    config_lock_read();
    if (api_mode) {
        json_object* root = json_object_new_object();

        /* switches */
        json_object* switches = json_object_new_object();
        json_object_object_add(switches, "global_inject",
                               json_object_new_boolean(g_global_cfg.global_inject));
        json_object_object_add(switches, "monitor", json_object_new_boolean(g_global_cfg.monitor));
        json_object_object_add(switches, "sandbox", json_object_new_boolean(g_global_cfg.sandbox));
        json_object_object_add(root, "switches", switches);

        /* hide_rules */
        json_object* hide_rules = json_object_new_array();
        for (int i = 0; i < g_global_cfg.hide_count; i++)
            json_object_array_add(hide_rules, json_object_new_string(g_global_cfg.hide_rules[i]));
        json_object_object_add(root, "hide_rules", hide_rules);

        /* ro_rules */
        json_object* ro_rules = json_object_new_array();
        for (int i = 0; i < g_global_cfg.ro_count; i++)
            json_object_array_add(ro_rules, json_object_new_string(g_global_cfg.ro_rules[i]));
        json_object_object_add(root, "ro_rules", ro_rules);

        /* 分流: redirect vs allow */
        int real_redir_cnt = 0, allow_cnt = 0;
        for (int i = 0; i < g_global_cfg.redir_count; i++) {
            if (g_global_cfg.redir_rules[i].is_allow)
                allow_cnt++;
            else
                real_redir_cnt++;
        }

        json_object* redirect_rules = json_object_new_array();
        for (int i = 0; i < g_global_cfg.redir_count; i++) {
            if (g_global_cfg.redir_rules[i].is_allow) continue;
            json_object* rule = json_object_new_object();
            json_object_object_add(
                rule, "virtual_prefix",
                json_object_new_string(g_global_cfg.redir_rules[i].virtual_prefix));
            const char* raw = g_global_cfg.redir_rules[i].real_target;
            json_object_object_add(rule, "real_target",
                                   json_object_new_string(raw[0] == '?' ? raw + 1 : raw));
            json_object_array_add(redirect_rules, rule);
        }
        json_object_object_add(root, "redirect_rules", redirect_rules);

        json_object* allow_rules = json_object_new_array();
        for (int i = 0; i < g_global_cfg.redir_count; i++) {
            if (!g_global_cfg.redir_rules[i].is_allow) continue;
            json_object_array_add(
                allow_rules, json_object_new_string(g_global_cfg.redir_rules[i].virtual_prefix));
        }
        json_object_object_add(root, "allow_rules", allow_rules);

        json_object_object_add(root, "fuse_extra_args",
                               json_object_new_string(g_global_cfg.fuse_extra_args));

        json_object* counts = json_object_new_object();
        json_object_object_add(counts, "hide", json_object_new_int(g_global_cfg.hide_count));
        json_object_object_add(counts, "ro", json_object_new_int(g_global_cfg.ro_count));
        json_object_object_add(counts, "redirect", json_object_new_int(real_redir_cnt));
        json_object_object_add(counts, "allow", json_object_new_int(allow_cnt));
        json_object_object_add(root, "counts", counts);

        config_unlock_read();
        json_api_finish(true, "\"get-global-rules\"",
                        json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN));
        json_object_put(root);
    } else {
        printf("===== 全局规则 (GLOBAL) =====\n\n");
        printf("--- Switch 开关 ---\n");
        printf("  GLOBAL_INJECT %s\n", g_global_cfg.global_inject ? "ON" : "OFF");
        printf("  MONITOR       %s\n", g_global_cfg.monitor ? "ON" : "OFF");
        printf("  SANDBOX       %s\n", g_global_cfg.sandbox ? "ON" : "OFF");
        printf("\n--- HIDE 规则 (%d 条) ---\n", g_global_cfg.hide_count);
        for (int i = 0; i < g_global_cfg.hide_count; i++) {
            printf("  [%d] HIDE %s\n", i, g_global_cfg.hide_rules[i]);
        }
        printf("\n--- RO 规则 (%d 条) ---\n", g_global_cfg.ro_count);
        for (int i = 0; i < g_global_cfg.ro_count; i++) {
            printf("  [%d] RO %s\n", i, g_global_cfg.ro_rules[i]);
        }

        int real_redir_cnt = 0;
        int allow_cnt = 0;
        for (int i = 0; i < g_global_cfg.redir_count; i++) {
            if (g_global_cfg.redir_rules[i].is_allow)
                allow_cnt++;
            else
                real_redir_cnt++;
        }

        printf("\n--- REDIRECT 规则 (%d 条) ---\n", real_redir_cnt);
        int idx = 0;
        for (int i = 0; i < g_global_cfg.redir_count; i++) {
            if (g_global_cfg.redir_rules[i].is_allow) continue;
            const char* raw = g_global_cfg.redir_rules[i].real_target;
            printf("  [%d] REDIRECT %s %s\n", idx++, g_global_cfg.redir_rules[i].virtual_prefix,
                   raw[0] == '?' ? raw + 1 : raw);
        }

        printf("\n--- ALLOW 规则 (%d 条) ---\n", allow_cnt);
        idx = 0;
        for (int i = 0; i < g_global_cfg.redir_count; i++) {
            if (!g_global_cfg.redir_rules[i].is_allow) continue;
            printf("  [%d] ALLOW %s\n", idx++, g_global_cfg.redir_rules[i].virtual_prefix);
        }

        if (g_global_cfg.fuse_extra_args[0]) {
            printf("\n--- FUSE_EXTRA_ARGS ---\n");
            printf("  %s\n", g_global_cfg.fuse_extra_args);
        }
        config_unlock_read();
    }
}

/* 核心修复：应用配置查询逻辑同步分离 ALLOW */
static void handle_get_app_rules(bool api_mode, const char* pkg, int user_id) {
    config_lock_write();
    load_config_rules(g_main_conf);
    config_unlock_write();
    config_lock_read();
    AppConfig* cfg = find_app_cfg_locked(pkg, user_id);
    if (!cfg) {
        config_unlock_read();
        char err[256];
        snprintf(err, sizeof(err), "未找到应用 \"%s\" (UID %d) 的配置", pkg, user_id);
        json_api_error(api_mode, "\"get-app-rules\"", err);
        return;
    }
    if (api_mode) {
        json_object* root = json_object_new_object();
        json_object_object_add(root, "pkg", json_object_new_string(cfg->pkg_name));
        json_object_object_add(root, "user_id", json_object_new_int(cfg->user_id));

        json_object* switches = json_object_new_object();
        json_object_object_add(switches, "inject_enable",
                               json_object_new_boolean(cfg->inject_enable));
        json_object_object_add(switches, "monitor", json_object_new_boolean(cfg->monitor));
        json_object_object_add(switches, "sandbox", json_object_new_boolean(cfg->sandbox));
        json_object_object_add(root, "switches", switches);

        json_object* hide_rules = json_object_new_array();
        for (int i = 0; i < cfg->hide_count; i++)
            json_object_array_add(hide_rules, json_object_new_string(cfg->hide_rules[i]));
        json_object_object_add(root, "hide_rules", hide_rules);

        json_object* ro_rules = json_object_new_array();
        for (int i = 0; i < cfg->ro_count; i++)
            json_object_array_add(ro_rules, json_object_new_string(cfg->ro_rules[i]));
        json_object_object_add(root, "ro_rules", ro_rules);

        int real_redir_cnt = 0, allow_cnt = 0;
        for (int i = 0; i < cfg->redir_count; i++) {
            if (cfg->redir_rules[i].is_allow)
                allow_cnt++;
            else
                real_redir_cnt++;
        }

        json_object* redirect_rules = json_object_new_array();
        for (int i = 0; i < cfg->redir_count; i++) {
            if (cfg->redir_rules[i].is_allow) continue;
            json_object* rule = json_object_new_object();
            json_object_object_add(rule, "virtual_prefix",
                                   json_object_new_string(cfg->redir_rules[i].virtual_prefix));
            const char* raw = cfg->redir_rules[i].real_target;
            json_object_object_add(rule, "real_target",
                                   json_object_new_string(raw[0] == '?' ? raw + 1 : raw));
            json_object_array_add(redirect_rules, rule);
        }
        json_object_object_add(root, "redirect_rules", redirect_rules);

        json_object* allow_rules = json_object_new_array();
        for (int i = 0; i < cfg->redir_count; i++) {
            if (!cfg->redir_rules[i].is_allow) continue;
            json_object_array_add(allow_rules,
                                  json_object_new_string(cfg->redir_rules[i].virtual_prefix));
        }
        json_object_object_add(root, "allow_rules", allow_rules);

        json_object* counts = json_object_new_object();
        json_object_object_add(counts, "hide", json_object_new_int(cfg->hide_count));
        json_object_object_add(counts, "ro", json_object_new_int(cfg->ro_count));
        json_object_object_add(counts, "redirect", json_object_new_int(real_redir_cnt));
        json_object_object_add(counts, "allow", json_object_new_int(allow_cnt));
        json_object_object_add(root, "counts", counts);

        config_unlock_read();
        json_api_finish(true, "\"get-app-rules\"",
                        json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN));
        json_object_put(root);
    } else {
        printf("===== 应用规则: %s (UID %d) =====\n\n", cfg->pkg_name, cfg->user_id);
        printf("--- Switch 开关 ---\n");
        printf("  INJECT_ENABLE %s\n", cfg->inject_enable ? "ON" : "OFF");
        printf("  MONITOR       %s\n", cfg->monitor ? "ON" : "OFF");
        printf("  SANDBOX       %s\n", cfg->sandbox ? "ON" : "OFF");
        printf("\n--- HIDE 规则 (%d 条) ---\n", cfg->hide_count);
        for (int i = 0; i < cfg->hide_count; i++) {
            printf("  [%d] HIDE %s\n", i, cfg->hide_rules[i]);
        }
        printf("\n--- RO 规则 (%d 条) ---\n", cfg->ro_count);
        for (int i = 0; i < cfg->ro_count; i++) {
            printf("  [%d] RO %s\n", i, cfg->ro_rules[i]);
        }

        int real_redir_cnt = 0;
        int allow_cnt = 0;
        for (int i = 0; i < cfg->redir_count; i++) {
            if (cfg->redir_rules[i].is_allow)
                allow_cnt++;
            else
                real_redir_cnt++;
        }

        printf("\n--- REDIRECT 规则 (%d 条) ---\n", real_redir_cnt);
        int idx = 0;
        for (int i = 0; i < cfg->redir_count; i++) {
            if (cfg->redir_rules[i].is_allow) continue;
            const char* raw = cfg->redir_rules[i].real_target;
            printf("  [%d] REDIRECT %s %s\n", idx++, cfg->redir_rules[i].virtual_prefix,
                   raw[0] == '?' ? raw + 1 : raw);
        }

        printf("\n--- ALLOW 规则 (%d 条) ---\n", allow_cnt);
        idx = 0;
        for (int i = 0; i < cfg->redir_count; i++) {
            if (!cfg->redir_rules[i].is_allow) continue;
            printf("  [%d] ALLOW %s\n", idx++, cfg->redir_rules[i].virtual_prefix);
        }

        if (cfg->fuse_extra_args[0]) {
            printf("\n--- FUSE_EXTRA_ARGS ---\n");
            printf("  %s\n", cfg->fuse_extra_args);
        }
        config_unlock_read();
    }
}

/* ========== 配置管理命令 ========== */
static void handle_reload_config(bool api_mode) {
    const char* err = send_reload_signal();
    if (err) {
        json_api_error(api_mode, "\"reload-config\"", err);
        return;
    }
    if (api_mode) {
        char data_buf[256];
        int pid = read_pid_file(INJECTOR_PID_PATH);
        snprintf(data_buf, sizeof(data_buf), "{\"pid\":%d,\"signal\":\"SIGHUP\"}", pid);
        json_api_finish(true, "\"reload-config\"", data_buf);
    } else {
        int pid = read_pid_file(INJECTOR_PID_PATH);
        printf("已向注入器 (PID %d) 发送 SIGHUP 信号，触发配置重载\n", pid);
    }
}

/* ========== 系统状态 ========== */
static void handle_status(bool api_mode) {
    int injector_pid = read_pid_file(INJECTOR_PID_PATH);
    bool injector_alive = (injector_pid > 0 && kill(injector_pid, 0) == 0);
    int fuse_pid = 0;
    FILE* fp = fopen("/proc/self/mountinfo", "r");
    if (fp) {
        char line[512];
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, "fuse") && strstr(line, "nsp_global")) {
                char* tok = strtok(line, " ");
                for (int i = 0; tok && i < 4; i++) tok = strtok(NULL, " ");
                if (tok) fuse_pid = atoi(tok);
                break;
            }
        }
        fclose(fp);
    }
    bool fuse_alive = (fuse_pid > 0 && kill(fuse_pid, 0) == 0);
    int main_conf_size = 0;
    struct stat st;
    if (stat(g_main_conf, &st) == 0) main_conf_size = (int)st.st_size;

    int app_rule_files = 0;
    DIR* dir = opendir(g_config_dir);
    if (dir) {
        struct dirent* de;
        while ((de = readdir(dir)) != nullptr) {
            if (de->d_type != DT_DIR) continue;
            if (!nsp_is_app_rules_dirname(de->d_name)) continue;
            char rules_dir[PATH_MAX];
            snprintf(rules_dir, sizeof(rules_dir), "%s/%s", g_config_dir, de->d_name);
            DIR* rdir = opendir(rules_dir);
            if (rdir) {
                struct dirent* rde;
                while ((rde = readdir(rdir)) != nullptr) {
                    if (rde->d_type == DT_REG || rde->d_type == DT_LNK) {
                        char* ext = strrchr(rde->d_name, '.');
                        if (ext && strcmp(ext, ".conf") == 0) app_rule_files++;
                    }
                }
                closedir(rdir);
            }
        }
        closedir(dir);
    }

    config_lock_read();
    int mem_app_count = g_app_cfg_count;
    config_unlock_read();

    if (api_mode) {
        time_t now = time(NULL);
        struct tm tm_info;
        char time_str[64];
        localtime_r(&now, &tm_info);
        strftime(time_str, sizeof(time_str), "%Y-%m-%dT%H:%M:%S", &tm_info);

        json_object* root = json_object_new_object();
        json_object_object_add(root, "timestamp", json_object_new_int64(now));
        json_object_object_add(root, "time", json_object_new_string(time_str));

        json_object* injector = json_object_new_object();
        json_object_object_add(injector, "pid", json_object_new_int(injector_pid));
        json_object_object_add(injector, "alive", json_object_new_boolean(injector_alive));
        json_object_object_add(root, "injector", injector);

        json_object* fuse = json_object_new_object();
        json_object_object_add(fuse, "pid", json_object_new_int(fuse_pid));
        json_object_object_add(fuse, "alive", json_object_new_boolean(fuse_alive));
        json_object_object_add(root, "fuse", fuse);

        json_object* config = json_object_new_object();
        json_object_object_add(config, "main_conf_path", json_object_new_string(g_main_conf));
        json_object_object_add(config, "main_conf_size", json_object_new_int(main_conf_size));
        json_object_object_add(config, "app_rule_files", json_object_new_int(app_rule_files));
        json_object_object_add(config, "parsed_apps_in_memory", json_object_new_int(mem_app_count));
        json_object_object_add(root, "config", config);

        json_object* system = json_object_new_object();
        json_object_object_add(system, "config_dir", json_object_new_string(g_config_dir));
        json_object_object_add(system, "pid_file", json_object_new_string(INJECTOR_PID_PATH));
        json_object_object_add(root, "system", system);

        json_api_finish(true, "\"status\"",
                        json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN));
        json_object_put(root);
    } else {
        printf("===== 系统状态概览 =====\n");
        printf("时间: %lld\n", (long long)time(NULL));
        printf("注入器: PID %d [%s]\n", injector_pid, injector_alive ? "运行中" : "未运行");
        printf("FUSE 守护进程: PID %d [%s]\n", fuse_pid, fuse_alive ? "运行中" : "未运行");
        printf("主配置文件: %s (%d 字节)\n", g_main_conf, main_conf_size);
        printf("应用规则文件数: %d\n", app_rule_files);
        printf("内存中已解析应用: %d\n", mem_app_count);
    }
}

/* ========== set-rule / remove-rule 处理 ========== */
/* 行级读写与段编辑统一走 nsp_rule_file（与 rule_server 共享同一实现；
   语义基准为 rule_server：开关在作用域内唯一、规则行全文件去重、落盘原子写）。 */

static void handle_set_rule(bool api_mode, const char* pkg, const char* type, const char* value,
                            int user_id) {
    if (!pkg || !type || !value) {
        json_api_error(api_mode, "\"set-rule\"", "缺少必要参数: pkg type value");
        return;
    }
    bool is_global = (strcmp(pkg, "GLOBAL") == 0);
    bool is_cat = (!is_global && nsp_rule_file_is_category_pkg(pkg));
    char rule_path[PATH_MAX];
    if (is_global || is_cat) {
        snprintf(rule_path, sizeof(rule_path), "%s", g_main_conf);
    } else {
        nsp_app_rule_path(g_config_dir, user_id, pkg, rule_path, sizeof(rule_path));
    }

    char line[1024];
    if (strcmp(type, "REDIRECT") == 0) {
        char src[512], dst[512];
        const char* sep = strchr(value, '|');
        if (sep) {
            size_t src_len = (size_t)(sep - value);
            if (src_len >= sizeof(src)) src_len = sizeof(src) - 1;
            memcpy(src, value, src_len);
            src[src_len] = '\0';
            strncpy(dst, sep + 1, sizeof(dst) - 1);
            dst[sizeof(dst) - 1] = '\0';
            snprintf(line, sizeof(line), "REDIRECT %s %s\n", src, dst);
        } else {
            snprintf(line, sizeof(line), "REDIRECT %s %s\n", value, value);
        }
    } else if (strcmp(type, "ALLOW") == 0) {
        snprintf(line, sizeof(line), "ALLOW %s\n", value);
    } else if (strcmp(type, "HIDE") == 0) {
        snprintf(line, sizeof(line), "HIDE %s\n", value);
    } else if (strcmp(type, "RO") == 0) {
        snprintf(line, sizeof(line), "RO %s\n", value);
    } else if (strcmp(type, "MONITOR") == 0 || strcmp(type, "SANDBOX") == 0 ||
               strcmp(type, "GLOBAL_INJECT") == 0) {
        snprintf(line, sizeof(line), "%s %s\n", type, value);
    } else {
        char err_buf[128];
        snprintf(err_buf, sizeof(err_buf), "未知规则类型: %s", type);
        json_api_error(api_mode, "\"set-rule\"", err_buf);
        return;
    }

    bool is_switch = (strcmp(type, "MONITOR") == 0 || strcmp(type, "SANDBOX") == 0 ||
                      strcmp(type, "GLOBAL_INJECT") == 0);
    int rc;
    if (is_global || is_cat) {
        /* 段名不含方括号（段头由共享实现按 [段名] 构造）：GLOBAL 用前缀匹配
           以兼容 [GLOBAL:...]；类别段用精确匹配，避免与裸 [USER_APPS] 混淆 */
        char sec_name[64];
        NspRuleSectionMatch sec_match;
        if (is_cat) {
            nsp_rule_file_category_name(pkg, user_id, sec_name, sizeof sec_name);
            sec_match = NSP_RULE_SEC_EXACT;
        } else {
            snprintf(sec_name, sizeof sec_name, "GLOBAL");
            sec_match = NSP_RULE_SEC_PREFIX;
        }
        nsp_mkdir_p(g_config_dir, 0755);
        rc = nsp_rule_file_upsert_in_section(rule_path, sec_name, sec_match, is_switch, type, line,
                                             NULL);
    } else {
        /* 应用段：无段结构文件（规则行去重追加、开关就地替换） */
        char rule_dir[PATH_MAX];
        nsp_app_rule_dir(g_config_dir, user_id, rule_dir, sizeof(rule_dir));
        if (nsp_mkdir_p(rule_dir, 0755) != 0) {
            char err_buf[256];
            snprintf(err_buf, sizeof(err_buf), "无法创建目录 %s: %s", rule_dir, strerror(errno));
            json_api_error(api_mode, "\"set-rule\"", err_buf);
            return;
        }
        rc = nsp_rule_file_upsert_line(rule_path, is_switch, type, line, NULL);
    }
    if (rc != NSP_RULE_FILE_OK) {
        char err_buf[256];
        snprintf(err_buf, sizeof(err_buf), "无法写入规则文件 %s: %s", rule_path, strerror(errno));
        json_api_error(api_mode, "\"set-rule\"", err_buf);
        return;
    }

    if (!api_mode) {
        /* 通知注入器重新加载配置 */
        const char* err = send_reload_signal();
        if (err) {
            fprintf(stderr, "警告: %s（配置已写入，需手动触发重载）\n", err);
        }
    }
    if (api_mode) {
        json_object* root = json_object_new_object();
        json_object_object_add(root, "file", json_object_new_string(rule_path));
        json_object_object_add(root, "line", json_object_new_string(line));
        json_object_object_add(root, "pkg", json_object_new_string(pkg));
        json_object_object_add(root, "type", json_object_new_string(type));
        json_object_object_add(root, "value", json_object_new_string(value));
        json_api_finish(true, "\"set-rule\"",
                        json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN));
        json_object_put(root);
    } else {
        printf("已向 %s 写入规则: %s", rule_path, line);
    }
}

static void handle_remove_rule(bool api_mode, const char* pkg, const char* type, int index,
                               int user_id) {
    if (!pkg || !type) {
        json_api_error(api_mode, "\"remove-rule\"", "缺少必要参数: pkg type index");
        return;
    }
    if (index < 0) {
        json_api_error(api_mode, "\"remove-rule\"", "索引必须 >= 0");
        return;
    }
    char rule_path[PATH_MAX];
    if (strcmp(pkg, "GLOBAL") == 0 || nsp_rule_file_is_category_pkg(pkg)) {
        snprintf(rule_path, sizeof(rule_path), "%s", g_main_conf);
    } else {
        nsp_app_rule_path(g_config_dir, user_id, pkg, rule_path, sizeof(rule_path));
    }
    /* 索引计入已停用行（与 rule_server / LIST 输出一致） */
    int rc = nsp_rule_file_remove_nth(rule_path, type, index, NULL, 0);
    if (rc == NSP_RULE_FILE_ENOTFND) {
        char err_buf[128];
        snprintf(err_buf, sizeof(err_buf), "未找到 %s 类型的第 %d 条规则", type, index);
        json_api_error(api_mode, "\"remove-rule\"", err_buf);
        return;
    }
    if (rc != NSP_RULE_FILE_OK) {
        char err_buf[256];
        snprintf(err_buf, sizeof(err_buf), "无法写入规则文件 %s: %s", rule_path, strerror(errno));
        json_api_error(api_mode, "\"remove-rule\"", err_buf);
        return;
    }

    if (!api_mode) {
        const char* err = send_reload_signal();
        if (err) {
            fprintf(stderr, "警告: %s（配置已写入，需手动触发重载）\n", err);
        }
    }
    if (api_mode) {
        json_object* root = json_object_new_object();
        json_object_object_add(root, "file", json_object_new_string(rule_path));
        json_object_object_add(root, "pkg", json_object_new_string(pkg));
        json_object_object_add(root, "type", json_object_new_string(type));
        json_object_object_add(root, "index", json_object_new_int(index));
        json_api_finish(true, "\"remove-rule\"",
                        json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN));
        json_object_put(root);
    } else {
        printf("已从 %s 删除第 %d 条 %s 规则\n", rule_path, index, type);
    }
}

/* ========== 配置广播接收 ========== */
static int config_broadcast_connect(void) {
    int sock = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (sock < 0) {
        perror("创建 DGRAM socket 失败");
        return -1;
    }
    char local_name[64];
    snprintf(local_name, sizeof(local_name), "nsp_ctl_%d", getpid());
    struct sockaddr_un local;
    socklen_t local_len = nsp_uds_abstract_addr(&local, local_name);
    if (bind(sock, (struct sockaddr*)&local, local_len) < 0) {
        perror("绑定本地 DGRAM 地址失败");
        close(sock);
        return -1;
    }
    return sock;
}

static int config_broadcast_send_cmd(int sock, const char* cmd) {
    struct sockaddr_un pub;
    socklen_t pub_len = nsp_uds_abstract_addr(&pub, CONFIG_BROADCAST_SOCKET);
    return sendto(sock, cmd, strlen(cmd), MSG_NOSIGNAL, (struct sockaddr*)&pub, pub_len);
}

static ssize_t config_broadcast_recv(int sock, char* buf, size_t size, int timeout_ms) {
    struct pollfd pfd = {.fd = sock, .events = POLLIN};
    int ret = poll(&pfd, 1, timeout_ms);
    if (ret < 0) return -1;
    if (ret == 0) return -2;
    ssize_t n = recv(sock, buf, size - 1, MSG_DONTWAIT);
    if (n > 0) buf[n] = '\0';
    return n;
}

#define BROADCAST_RECEIVE_MAX_SIZE (256 * 1024)

static void handle_get_config(bool api_mode, bool static_mode) {
    int sock = config_broadcast_connect();
    if (sock < 0) return;
    const char* cmd = static_mode ? "STATIC" : "GET";
    if (config_broadcast_send_cmd(sock, cmd) < 0) {
        perror("发送命令失败");
        close(sock);
        return;
    }
    char* resp = malloc(BROADCAST_RECEIVE_MAX_SIZE);
    if (!resp) {
        fprintf(stderr, "系统物理内存不足，无法分配接收缓冲区\n");
        close(sock);
        return;
    }
    ssize_t n = config_broadcast_recv(sock, resp, BROADCAST_RECEIVE_MAX_SIZE, 3000);
    close(sock);
    if (n < 0) {
        fprintf(stderr, "未获取到配置信息（%s）\n", (n == -2) ? "超时" : strerror(errno));
        free(resp);
        return;
    }
    if (api_mode) {
        json_api_finish(true, static_mode ? "\"get-config-static\"" : "\"get-config\"", resp);
    } else {
        printf("%s\n", resp);
    }
    free(resp);
}

static void handle_stream_config(bool api_mode) {
    int sock = config_broadcast_connect();
    if (sock < 0) return;
    if (config_broadcast_send_cmd(sock, "SUBSCRIBE") < 0) {
        perror("发送 SUBSCRIBE 命令失败");
        close(sock);
        return;
    }
    char* resp = malloc(BROADCAST_RECEIVE_MAX_SIZE);
    if (!resp) {
        fprintf(stderr, "系统物理内存不足，无法分配接收缓冲区\n");
        close(sock);
        return;
    }
    ssize_t n = config_broadcast_recv(sock, resp, BROADCAST_RECEIVE_MAX_SIZE, 3000);
    if (n > 0) {
        if (api_mode) {
            json_api_finish(true, "\"stream-config\"", resp);
        } else {
            printf("===== 当前配置 (首次推送) =====\n%s\n", resp);
        }
    }
    struct sigaction sa = {.sa_handler = sigint_handler};
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
    while (g_running) {
        n = config_broadcast_recv(sock, resp, BROADCAST_RECEIVE_MAX_SIZE, 60000);
        if (n > 0) {
            if (api_mode) {
                json_api_finish(true, "\"stream-config\"", resp);
            } else {
                printf("===== 配置变更推送 =====\n%s\n", resp);
            }
            fflush(stdout);
        } else if (n == -2) {
            continue;
        } else if (n < 0) {
            if (errno != EINTR) {
                perror("接收配置推送失败");
                break;
            }
        }
    }
    /* 退出前主动取消订阅，避免 injector 端残留死订阅 */
    config_broadcast_send_cmd(sock, "UNSUBSCRIBE");
    free(resp);
    close(sock);
}

void process_and_print(char* line, bool force_uid, [[maybe_unused]] bool api_mode) {
    char* open_b = strchr(line, '[');
    if (open_b && !force_uid) {
        char* open_p = strchr(open_b, '(');
        if (open_p) {
            char* close_p = strchr(open_p, ')');
            bool valid_close = (close_p && close_p > open_p);
            if (valid_close) {
                bool is_uid = true;
                for (char* c = open_p + 1; c < close_p; c++)
                    if (!isdigit((unsigned char)*c)) is_uid = false;
                if (is_uid) memmove(open_p, close_p + 1, strlen(close_p + 1) + 1);
            } else {
                char* close_b = strchr(open_p, ']');
                char* term = close_b ? close_b : (open_p + strlen(open_p));
                if (term > open_p) {
                    bool is_uid = true;
                    for (char* c = open_p + 1; c < term; c++) {
                        if (!isdigit((unsigned char)*c)) {
                            is_uid = false;
                            break;
                        }
                    }
                    if (is_uid) memmove(open_p, term, strlen(term) + 1);
                }
            }
        }
    }
    printf("%s\n", line);
    fflush(stdout);
}

static void handle_list_injected(bool api_mode) {
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un addr;
    socklen_t addr_len = nsp_uds_abstract_addr(&addr, IPC_SOCKET_NAME);
    if (connect(sock, (struct sockaddr*)&addr, addr_len) < 0) {
        perror("连接注入器 IPC 服务失败");
        return;
    }
    write(sock, "LIST_INJECTED", 13);
    shutdown(sock, SHUT_WR);
    struct pollfd pfd = {.fd = sock, .events = POLLIN};
    if (poll(&pfd, 1, 5000) <= 0) {
        if (!api_mode) fprintf(stderr, "未获取到响应\n");
        close(sock);
        return;
    }
    /* 循环读到 EOF + 动态增长：注入应用可达数百，固定 8192 的单次 read 会截断
       末尾 APP 行与 DONE 行，DONE 解析失败即"共计 0 个"误报（injector 侧
       781fc94 已改为动态缓冲，此处是同一问题的接收端）；且 SOCK_STREAM 上
       单次 read 本身不保证读全，内核可分段投递——与本文件其它 IPC 读取同范式 */
    size_t cap = 65536;
    char* resp = malloc(cap);
    if (!resp) {
        close(sock);
        return;
    }
    size_t nread = 0;
    ssize_t n;
    while ((n = read(sock, resp + nread, cap - 1 - nread)) > 0) {
        nread += (size_t)n;
        if (nread >= cap - 1) {
            cap *= 2;
            char* tmp = realloc(resp, cap);
            if (!tmp) {
                free(resp);
                close(sock);
                return;
            }
            resp = tmp;
        }
    }
    close(sock);
    if (nread == 0) {
        if (!api_mode) fprintf(stderr, "未获取到响应\n");
        free(resp);
        return;
    }
    resp[nread] = '\0';
    if (api_mode) {
        char* done_line = NULL;
        int done_total = 0;
        bool has_done = false;
        done_line = strstr(resp, "\nDONE|");
        if (done_line) {
            *done_line = '\0';
            done_line++;
        } else if (strncmp(resp, "DONE|", 5) == 0) {
            done_line = resp;
            resp[0] = '\0';
        }
        if (done_line && sscanf(done_line + 5, "%d", &done_total) == 1) {
            has_done = true;
        }
        json_object* root = json_object_new_object();
        json_object_object_add(root, "raw", json_object_new_string(resp));
        if (has_done) {
            json_object* done = json_object_new_object();
            json_object_object_add(done, "total", json_object_new_int(done_total));
            json_object_object_add(root, "done", done);
        }
        json_api_finish(true, "\"list-injected\"",
                        json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN));
        json_object_put(root);
        free(resp);
        return;
    }
    int total = 0;
    char* line = strtok(resp, "\n");
    printf("\n已注入应用列表:\n");
    printf("%-4s %-40s %-7s %-8s %-5s %-5s %-5s\n", "序号", "包名", "PID", "UID", "重定向", "隐藏",
           "只读");
    printf("%s\n",
           "---- --------------------------------------- ------- -------- ----- ----- -----");
    int idx = 1;
    while (line) {
        if (strncmp(line, "APP|", 4) == 0) {
            char pkg[256];
            int pid, uid, r, h, ro;
            if (sscanf(line, "APP|%255[^|]|%d|%d|%d|%d|%d", pkg, &pid, &uid, &r, &h, &ro) == 6) {
                printf("%-4d %-40s %-7d %-8d %-5d %-5d %-5d\n", idx++, pkg, pid, uid, r, h, ro);
            }
        } else if (strncmp(line, "DONE|", 5) == 0) {
            sscanf(line + 5, "%d", &total);
        }
        line = strtok(nullptr, "\n");
    }
    printf("\n共计 %d 个应用已注入\n", total);
    free(resp);
}

static void handle_list_users(bool api_mode) {
    /* 与其它 handler 一致：先加载配置——load_config_rules 内部调用
       scan_active_users 填充 g_active_users，否则本进程内恒为 0 */
    config_lock_write();
    load_config_rules(g_main_conf);
    config_unlock_write();
    config_lock_read();
    int count = g_active_user_count;
    if (api_mode) {
        json_object* root = json_object_new_object();
        json_object_object_add(root, "count", json_object_new_int(count));
        json_object* users = json_object_new_array();
        for (int i = 0; i < count; i++) {
            int uid = g_active_users[i];
            int app_cnt = 0;
            for (int j = 0; j < g_app_cfg_count; j++) {
                if (g_app_cfgs[j]->user_id == uid) app_cnt++;
            }
            json_object* user = json_object_new_object();
            json_object_object_add(user, "uid", json_object_new_int(uid));
            json_object_object_add(user, "app_count", json_object_new_int(app_cnt));
            json_object_array_add(users, user);
        }
        json_object_object_add(root, "users", users);
        config_unlock_read();
        json_api_finish(true, "\"list-users\"",
                        json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN));
        json_object_put(root);
    } else {
        printf("===== 活跃用户列表 (%d) =====\n", count);
        for (int i = 0; i < count; i++) {
            int uid = g_active_users[i];
            int app_cnt = 0;
            for (int j = 0; j < g_app_cfg_count; j++) {
                if (g_app_cfgs[j]->user_id == uid) app_cnt++;
            }
            printf("  UID %-8d  %d 个应用配置\n", uid, app_cnt);
        }
    }
    config_unlock_read();
}

static void stream_logs(const char* stream_cmd) {
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un addr;
    socklen_t len = nsp_uds_abstract_addr(&addr, LOG_SOCKET_NAME);
    if (connect(sock, (struct sockaddr*)&addr, len) < 0) {
        perror("连接日志服务失败");
        return;
    }
    char cmd[64];
    snprintf(cmd, sizeof(cmd), "%s\n", stream_cmd);
    write(sock, cmd, strlen(cmd));
    char ack[16];
    ssize_t n = read(sock, ack, sizeof(ack) - 1);
    if (n <= 0 || strncmp(ack, "OK", 2) != 0) {
        fprintf(stderr, "服务端拒绝流式请求\n");
        close(sock);
        return;
    }
    struct sigaction sa = {.sa_handler = sigint_handler};
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
    char buf[8192];
    char line_buf[8192];
    size_t line_pos = 0;
    int epfd = epoll_create1(0);
    if (epfd < 0) {
        perror("epoll_create1");
        close(sock);
        return;
    }
    struct epoll_event ep_ev = {.events = EPOLLIN, .data.fd = sock};
    epoll_ctl(epfd, EPOLL_CTL_ADD, sock, &ep_ev);
    while (g_running) {
        struct epoll_event ev;
        int ret = epoll_wait(epfd, &ev, 1, 1000);
        if (!g_running) break;
        if (ret < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (ret == 0) continue;
        ssize_t n = read(sock, buf, sizeof(buf));
        if (n <= 0) break;
        for (ssize_t i = 0; i < n; i++) {
            if (buf[i] == '\n') {
                line_buf[line_pos] = '\0';
                process_and_print(line_buf, false, false);
                line_pos = 0;
            } else if (line_pos < sizeof(line_buf) - 1) {
                line_buf[line_pos++] = buf[i];
            } else {
                line_buf[line_pos] = '\0';
                process_and_print(line_buf, false, false);
                line_pos = 0;
                line_buf[line_pos++] = buf[i];
            }
        }
    }
    close(epfd);
    close(sock);
}

int main(int argc, char* argv[]) {
    if (argc < 2) usage(argv[0]);
    bool api_mode = false;
    bool force_uid = false;
    bool static_mode = false;
    char* level_arg = NULL;
    char* pos_args[10] = {NULL};
    int pos_idx = 0;
    int user_id = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "api") == 0) {
            api_mode = true;
        } else if (strcmp(argv[i], "-u") == 0) {
            force_uid = true;
        } else if (strcmp(argv[i], "--static") == 0) {
            static_mode = true;
        } else if (strcmp(argv[i], "--level") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "错误: --level 需要指定一个级别\n");
                usage(argv[0]);
            }
            /* 支持级别名与数字：debug/info/warn/error（及大写）→ 0/1/2/3，
               避免传名字时 atoi 解析为 0 导致过滤失效（显示全部日志） */
            const char* lv = argv[++i];
            if (strcasecmp(lv, "debug") == 0)
                lv = "0";
            else if (strcasecmp(lv, "info") == 0)
                lv = "1";
            else if (strcasecmp(lv, "warn") == 0 || strcasecmp(lv, "warning") == 0)
                lv = "2";
            else if (strcasecmp(lv, "error") == 0 || strcasecmp(lv, "err") == 0)
                lv = "3";
            level_arg = (char*)lv;
        } else if (strcmp(argv[i], "--uid") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "错误: --uid 需要指定用户 ID\n");
                usage(argv[0]);
            }
            user_id = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--config-dir") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "错误: --config-dir 需要指定目录\n");
                usage(argv[0]);
            }
            strncpy(g_config_dir, argv[++i], sizeof(g_config_dir) - 1);
            g_config_dir[sizeof(g_config_dir) - 1] = '\0';
        } else {
            if (pos_idx < 10) {
                pos_args[pos_idx++] = argv[i];
            } else {
                fprintf(stderr, "错误: 参数过多\n");
                usage(argv[0]);
            }
        }
    }
    if (pos_idx < 1) usage(argv[0]);
    config_paths_init(); /* --config-dir 覆盖后重算主配置路径 */

    /* 只读加载方：跳过 scan_active_users 的 popen("pm list users")——log_ctl
       是短命 CLI，parse-rules/validate-rules/get-global-rules/get-app-rules
       每次调用都会 load_config_rules，管理端轮询 JSON API 时每次都要付一次
       binder 通信 system_server 的开销。用户列表退化为扫 /data/media 与
       App-rules-* 目录，对只读查询足够（App-rules 目录创建权本就不在 log_ctl，
       g_allow_app_rules_mkdir 保持默认 false） */
    config_set_scan_users_skip_pm(true);

    if (strcmp(pos_args[0], "parse-rules") == 0) {
        handle_parse_rules(api_mode);
        return 0;
    }
    if (strcmp(pos_args[0], "get-global-rules") == 0) {
        handle_get_global_rules(api_mode);
        return 0;
    }
    if (strcmp(pos_args[0], "get-app-rules") == 0) {
        if (pos_idx < 2) {
            json_api_error(api_mode, "\"get-app-rules\"",
                           "用法: log_ctl get-app-rules <pkg> [--uid uid] [api]");
            return 1;
        }
        handle_get_app_rules(api_mode, pos_args[1], user_id);
        return 0;
    }
    if (strcmp(pos_args[0], "validate-rules") == 0) {
        handle_validate_rules(api_mode);
        return 0;
    }
    if (strcmp(pos_args[0], "reload-config") == 0) {
        handle_reload_config(api_mode);
        return 0;
    }
    if (strcmp(pos_args[0], "status") == 0) {
        handle_status(api_mode);
        return 0;
    }
    if (strcmp(pos_args[0], "set-rule") == 0) {
        if (pos_idx < 4) {
            json_api_error(api_mode, "\"set-rule\"",
                           "用法: log_ctl set-rule <pkg> <type> <value> [--uid uid] [api]");
            return 1;
        }
        handle_set_rule(api_mode, pos_args[1], pos_args[2], pos_args[3], user_id);
        return 0;
    }
    if (strcmp(pos_args[0], "remove-rule") == 0) {
        if (pos_idx < 4) {
            json_api_error(api_mode, "\"remove-rule\"",
                           "用法: log_ctl remove-rule <pkg> <type> <index> [--uid uid] [api]");
            return 1;
        }
        int index = atoi(pos_args[3]);
        handle_remove_rule(api_mode, pos_args[1], pos_args[2], index, user_id);
        return 0;
    }
    if (strncmp(pos_args[0], "stream", 6) == 0) {
        const char* level = level_arg ? level_arg : "0";
        char stream_cmd[64] = {0};
        if (strcmp(pos_args[0], "stream-io") == 0) {
            snprintf(stream_cmd, sizeof(stream_cmd), "STREAM_IO:%s", level);
        } else if (strcmp(pos_args[0], "stream-sys") == 0) {
            snprintf(stream_cmd, sizeof(stream_cmd),
                     api_mode ? "STREAM_SYS_API:%s" : "STREAM_SYS:%s", level);
        } else if (strcmp(pos_args[0], "stream-logcat") == 0) {
            snprintf(stream_cmd, sizeof(stream_cmd), "STREAM_LOGCAT:%s", level);
        } else if (strcmp(pos_args[0], "stream-all") == 0) {
            snprintf(stream_cmd, sizeof(stream_cmd), "STREAM_ALL:%s", level);
        } else if (strcmp(pos_args[0], "stream-config") == 0) {
            handle_stream_config(api_mode);
            return 0;
        } else {
            usage(argv[0]);
        }
        stream_logs(stream_cmd);
        return 0;
    }
    if (strcmp(pos_args[0], "list-injected") == 0) {
        handle_list_injected(api_mode);
        return 0;
    }
    if (strcmp(pos_args[0], "list-users") == 0) {
        handle_list_users(api_mode);
        return 0;
    }
    if (strcmp(pos_args[0], "get-config") == 0) {
        handle_get_config(api_mode, static_mode);
        return 0;
    }
    if (strcmp(pos_args[0], "log-count") == 0) {
        int sock = socket(AF_UNIX, SOCK_STREAM, 0);
        struct sockaddr_un log_addr;
        socklen_t log_addr_len = nsp_uds_abstract_addr(&log_addr, LOG_SOCKET_NAME);
        if (connect(sock, (struct sockaddr*)&log_addr, log_addr_len) < 0) {
            perror("连接日志服务失败");
            return 1;
        }
        write(sock, "COUNT\n", 6);
        shutdown(sock, SHUT_WR);
        char resp[256];
        ssize_t n = read(sock, resp, sizeof(resp) - 1);
        close(sock);
        if (n > 0) {
            resp[n] = '\0';
            int io_total = 0, sys_total = 0, logcat_total = 0;
            sscanf(resp, "COUNT|%d|%d|%d", &io_total, &sys_total, &logcat_total);
            if (api_mode) {
                char data_buf[256];
                snprintf(data_buf, sizeof(data_buf), "{\"io\":%d,\"sys\":%d,\"logcat\":%d}",
                         io_total, sys_total, logcat_total);
                json_api_finish(true, "\"log-count\"", data_buf);
            } else {
                printf("===== 日志统计 =====\n");
                printf("I/O 日志:     %d 条\n", io_total);
                printf("系统日志:     %d 条\n", sys_total);
                printf("Logcat 日志:  %d 条\n", logcat_total);
            }
        }
        return 0;
    }

    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("创建 socket 失败");
        return 1;
    }
    struct sockaddr_un log_addr;
    socklen_t log_addr_len = nsp_uds_abstract_addr(&log_addr, LOG_SOCKET_NAME);
    if (connect(sock, (struct sockaddr*)&log_addr, log_addr_len) < 0) {
        perror("连接日志服务失败");
        close(sock);
        return 1;
    }
    char cmd[128];
    if (strstr(pos_args[0], "search") != NULL) {
        const char* key = "";
        const char* limit = "100";
        const char* offset = "0";
        if (pos_idx > 1) key = pos_args[1];
        if (pos_idx > 2) limit = pos_args[2];
        if (pos_idx > 3) offset = pos_args[3];
        const char* level = level_arg ? level_arg : "-1";
        snprintf(cmd, sizeof(cmd), "QUERY_%s:%s:%s:%s:%s\n",
                 strstr(pos_args[0], "io") ? "IO" : "SYS", level, key, limit, offset);
    } else if (strstr(pos_args[0], "clear") != NULL) {
        snprintf(cmd, sizeof(cmd), "CLEAR_%s\n", strstr(pos_args[0], "io") ? "IO" : "SYS");
    } else {
        close(sock);
        usage(argv[0]);
        return 1;
    }
    write(sock, cmd, strlen(cmd));
    shutdown(sock, SHUT_WR);
    struct pollfd pfd = {.fd = sock, .events = POLLIN};
    if (poll(&pfd, 1, 5000) <= 0) {
        close(sock);
        return 1;
    }

    size_t cap = 65536;
    char* resp = malloc(cap);
    if (!resp) {
        close(sock);
        return 1;
    }
    size_t total = 0;
    ssize_t n;
    while ((n = read(sock, resp + total, cap - 1 - total)) > 0) {
        total += (size_t)n;
        if (total >= cap - 1) {
            cap *= 2;
            char* tmp = realloc(resp, cap);
            if (!tmp) {
                free(resp);
                close(sock);
                return 1;
            }
            resp = tmp;
        }
    }
    if (total > 0) {
        resp[total] = '\0';
        if (api_mode) {
            char* done_line = NULL;
            int done_total = 0, done_remaining = 0;
            bool has_done = false;
            done_line = strstr(resp, "\nDONE|");
            if (done_line) {
                *done_line = '\0';
                done_line++;
            } else if (strncmp(resp, "DONE|", 5) == 0) {
                done_line = resp;
                resp[0] = '\0';
            }
            if (done_line && sscanf(done_line + 5, "%d|%d", &done_total, &done_remaining) >= 1) {
                has_done = true;
            }

            json_object* root = json_object_new_object();
            json_object_object_add(root, "raw", json_object_new_string(resp));
            if (has_done) {
                json_object* done = json_object_new_object();
                json_object_object_add(done, "total", json_object_new_int(done_total));
                json_object_object_add(done, "remaining", json_object_new_int(done_remaining));
                json_object_object_add(root, "done", done);
            }
            json_api_finish(true,
                            (strncmp(pos_args[0], "search", 6) == 0) ? "\"search\"" : "\"clear\"",
                            json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN));
            json_object_put(root);
        } else {
            char* line = strtok(resp, "\n");
            while (line) {
                if (strncmp(line, "DONE|", 5) == 0) {
                    if (!api_mode) {
                        int tot, remain;
                        if (sscanf(line + 5, "%d|%d", &tot, &remain) == 2)
                            fprintf(stderr, "\n[统计] 总数: %d | 剩余: %d\n", tot, remain);
                    }
                    break;
                } else if (strcmp(line, "OK") != 0) {
                    process_and_print(line, force_uid, api_mode);
                }
                line = strtok(nullptr, "\n");
            }
        }
    }
    free(resp);
    close(sock);
    return 0;
}