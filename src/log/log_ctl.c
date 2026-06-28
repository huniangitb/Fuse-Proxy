#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <sys/epoll.h>
#include <stddef.h>
#include <ctype.h>
#include <signal.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <time.h>
#include "common.h"
#include "config_parser.h"

static volatile sig_atomic_t g_running = 1;

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
    printf("                              type: HIDE|RO|REDIRECT|ALLOW|MONITOR|SANDBOX|GLOBAL_INJECT|FUSE_DIRECT\n");
    printf("  remove-rule <pkg> <type> <index> [--uid uid] [api]\n");
    printf("                             删除指定索引的规则\n");
    printf("\n选项:\n");
    printf("  -u               始终显示 UID\n");
    printf("  api              以 API 格式输出（供程序调用，结构化 JSON）\n");
    printf("  --subscribe      订阅模式，持续接收配置变更\n");
    printf("  --uid <uid>      指定用户 ID（默认 0）\n");
    exit(1);
}

/* ========== JSON API 结构化输出 ========== */
static void json_api_start(bool api_mode) {
    (void)api_mode;
}

static void json_api_finish(bool api_mode, const char *cmd, const char *json_data) {
    if (!api_mode) return;
    printf("{\"status\":\"ok\",\"command\":%s,\"data\":%s,\"timestamp\":%lld}\n",
           cmd ? cmd : "null",
           json_data ? json_data : "null",
           (long long)time(NULL));
}

static void json_api_error(bool api_mode, const char *cmd, const char *error_msg) {
    if (!api_mode) {
        fprintf(stderr, "错误: %s\n", error_msg ? error_msg : "未知错误");
        return;
    }
    printf("{\"status\":\"error\",\"command\":%s,\"error\":",
           cmd ? cmd : "null");
    if (error_msg) {
        putchar('"');
        for (const char *p = error_msg; *p; p++) {
            unsigned char c = (unsigned char)*p;
            switch (c) {
                case '"':  printf("\\\""); break;
                case '\\': printf("\\\\"); break;
                case '\n': printf("\\n"); break;
                case '\r': printf("\\r"); break;
                case '\t': printf("\\t"); break;
                default:
                    if (c < 0x20) printf("\\u%04x", c);
                    else putchar(c);
                    break;
            }
        }
        putchar('"');
    } else {
        printf("null");
    }
    printf(",\"timestamp\":%lld}\n", (long long)time(NULL));
}

static int json_escape_str(const char *src, char *dst, size_t dst_size) {
    if (!src || !dst || dst_size == 0) return 0;
    size_t pos = 0;
    for (const char *p = src; *p && pos < dst_size - 1; p++) {
        unsigned char c = (unsigned char)*p;
        switch (c) {
            case '"':  if (pos + 2 < dst_size) { dst[pos++] = '\\'; dst[pos++] = '"'; } break;
            case '\\': if (pos + 2 < dst_size) { dst[pos++] = '\\'; dst[pos++] = '\\'; } break;
            case '\n': if (pos + 2 < dst_size) { dst[pos++] = '\\'; dst[pos++] = 'n'; } break;
            case '\r': if (pos + 2 < dst_size) { dst[pos++] = '\\'; dst[pos++] = 'r'; } break;
            case '\t': if (pos + 2 < dst_size) { dst[pos++] = '\\'; dst[pos++] = 't'; } break;
            default:
                if (c < 0x20) {
                    int n = snprintf(dst + pos, dst_size - pos, "\\u%04x", c);
                    if (n > 0) pos += (size_t)n;
                } else {
                    dst[pos++] = (char)c;
                }
                break;
        }
    }
    dst[pos] = '\0';
    return (int)pos;
}

/* ========== 配置文件读写辅助 ========== */
static int read_pid_file(const char *path) {
    FILE *fp = fopen(path, "r");
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

static void get_app_rule_path(char *buf, size_t size, const char *pkg, int user_id) {
    if (user_id == 0)
        snprintf(buf, size, "%s/App-rules/%s.conf", CONFIG_DIR, pkg);
    else
        snprintf(buf, size, "%s/App-rules-%d/%s.conf", CONFIG_DIR, user_id, pkg);
}

static void get_app_rule_dir(char *buf, size_t size, int user_id) {
    if (user_id == 0)
        snprintf(buf, size, "%s/App-rules", CONFIG_DIR);
    else
        snprintf(buf, size, "%s/App-rules-%d", CONFIG_DIR, user_id);
}

/* ========== 解析本地规则 ========== */
static void build_parsed_rules_json(char *out, size_t out_size) {
    if (!out || out_size == 0) return;
    size_t pos = 0;
    pos += snprintf(out + pos, out_size - pos, "{");
    config_lock_read();
    pos += snprintf(out + pos, out_size - pos,
        "\"global\":{\"sandbox\":%s,\"global_inject\":%s,\"fuse_direct\":%s,\"monitor\":%s,\"inject_enable\":true,\"hide_count\":%d,\"ro_count\":%d,\"redir_count\":%d},",
        g_global_cfg.sandbox ? "true" : "false",
        g_global_cfg.global_inject ? "true" : "false",
        g_global_cfg.fuse_direct ? "true" : "false",
        g_global_cfg.monitor ? "true" : "false",
        g_global_cfg.hide_count,
        g_global_cfg.ro_count,
        g_global_cfg.redir_count);
    
    pos += snprintf(out + pos, out_size - pos, "\"apps\":[");
    for (int i = 0; i < g_app_cfg_count; i++) {
        AppConfig *cfg = g_app_cfgs[i];
        char esc_pkg[256];
        json_escape_str(cfg->pkg_name, esc_pkg, sizeof(esc_pkg));
        if (i > 0) pos += snprintf(out + pos, out_size - pos, ",");
        pos += snprintf(out + pos, out_size - pos,
            "{\"pkg\":\"%s\",\"user_id\":%d,\"inject_enable\":%s,\"monitor\":%s,\"sandbox\":%s,\"fuse_direct\":%s,\"hide_count\":%d,\"ro_count\":%d,\"redir_count\":%d}",
            esc_pkg,
            cfg->user_id,
            cfg->inject_enable ? "true" : "false",
            cfg->monitor ? "true" : "false",
            cfg->sandbox ? "true" : "false",
            cfg->fuse_direct ? "true" : "false",
            cfg->hide_count,
            cfg->ro_count,
            cfg->redir_count);
    }
    config_unlock_read();
    pos += snprintf(out + pos, out_size - pos, "]}");
}

static void handle_parse_rules(bool api_mode) {
    config_lock_write();
    load_config_rules(INJECTOR_CONFIG_PATH);
    config_unlock_write();
    char json_buf[65536];
    build_parsed_rules_json(json_buf, sizeof(json_buf));
    if (api_mode) {
        json_api_finish(true, "\"parse-rules\"", json_buf);
    } else {
        printf("===== 本地规则解析结果 =====\n%s\n", json_buf);
    }
}

static void handle_validate_rules(bool api_mode) {
    config_lock_write();
    load_config_rules(INJECTOR_CONFIG_PATH);
    int app_count = g_app_cfg_count;
    config_unlock_write();
    if (api_mode) {
        char data_buf[512];
        snprintf(data_buf, sizeof(data_buf),
            "{\"valid\":true,\"app_count\":%d,\"global_hide_rules\":%d,\"global_ro_rules\":%d,\"global_redir_rules\":%d}",
            app_count, g_global_cfg.hide_count, g_global_cfg.ro_count, g_global_cfg.redir_count);
        json_api_finish(true, "\"validate-rules\"", data_buf);
    } else {
        printf("规则验证通过。共解析 %d 个应用配置。\n", app_count);
        printf("全局: %d 条 HIDE, %d 条 RO, %d 条 REDIRECT\n",
               g_global_cfg.hide_count, g_global_cfg.ro_count, g_global_cfg.redir_count);
    }
}

/* 核心修复：分离 ALLOW 规则和 REDIRECT 规则并输出 */
static void handle_get_global_rules(bool api_mode) {
    config_lock_write();
    load_config_rules(INJECTOR_CONFIG_PATH);
    config_unlock_write();
    config_lock_read();
    if (api_mode) {
        char data_buf[65536];
        size_t pos = 0;
        pos += snprintf(data_buf + pos, sizeof(data_buf) - pos,
            "{\"switches\":{\"global_inject\":%s,\"monitor\":%s,\"sandbox\":%s,\"fuse_direct\":%s},",
            g_global_cfg.global_inject ? "true" : "false",
            g_global_cfg.monitor ? "true" : "false",
            g_global_cfg.sandbox ? "true" : "false",
            g_global_cfg.fuse_direct ? "true" : "false");
        
        pos += snprintf(data_buf + pos, sizeof(data_buf) - pos, "\"hide_rules\":[");
        for (int i = 0; i < g_global_cfg.hide_count; i++) {
            char esc[1024];
            json_escape_str(g_global_cfg.hide_rules[i], esc, sizeof(esc));
            if (i > 0) pos += snprintf(data_buf + pos, sizeof(data_buf) - pos, ",");
            pos += snprintf(data_buf + pos, sizeof(data_buf) - pos, "\"%s\"", esc);
        }
        pos += snprintf(data_buf + pos, sizeof(data_buf) - pos, "],");
        
        pos += snprintf(data_buf + pos, sizeof(data_buf) - pos, "\"ro_rules\":[");
        for (int i = 0; i < g_global_cfg.ro_count; i++) {
            char esc[1024];
            json_escape_str(g_global_cfg.ro_rules[i], esc, sizeof(esc));
            if (i > 0) pos += snprintf(data_buf + pos, sizeof(data_buf) - pos, ",");
            pos += snprintf(data_buf + pos, sizeof(data_buf) - pos, "\"%s\"", esc);
        }
        pos += snprintf(data_buf + pos, sizeof(data_buf) - pos, "],");

        /* 进行规则分流研判 */
        int real_redir_cnt = 0;
        int allow_cnt = 0;
        for (int i = 0; i < g_global_cfg.redir_count; i++) {
            if (g_global_cfg.redir_rules[i].real_target[0] == '?') allow_cnt++;
            else real_redir_cnt++;
        }

        /* 纯重定向规则输出 (剔除 '?' 伪重定向) */
        pos += snprintf(data_buf + pos, sizeof(data_buf) - pos, "\"redirect_rules\":[");
        int printed_redir = 0;
        for (int i = 0; i < g_global_cfg.redir_count; i++) {
            if (g_global_cfg.redir_rules[i].real_target[0] == '?') continue;
            char esc_v[1024], esc_r[1024];
            json_escape_str(g_global_cfg.redir_rules[i].virtual_prefix, esc_v, sizeof(esc_v));
            json_escape_str(g_global_cfg.redir_rules[i].real_target, esc_r, sizeof(esc_r));
            if (printed_redir > 0) pos += snprintf(data_buf + pos, sizeof(data_buf) - pos, ",");
            pos += snprintf(data_buf + pos, sizeof(data_buf) - pos,
                "{\"virtual_prefix\":\"%s\",\"real_target\":\"%s\"}", esc_v, esc_r);
            printed_redir++;
        }
        pos += snprintf(data_buf + pos, sizeof(data_buf) - pos, "],");

        /* 纯 ALLOW 规则单独输出 */
        pos += snprintf(data_buf + pos, sizeof(data_buf) - pos, "\"allow_rules\":[");
        int printed_allow = 0;
        for (int i = 0; i < g_global_cfg.redir_count; i++) {
            if (g_global_cfg.redir_rules[i].real_target[0] != '?') continue;
            char esc_v[1024];
            json_escape_str(g_global_cfg.redir_rules[i].virtual_prefix, esc_v, sizeof(esc_v));
            if (printed_allow > 0) pos += snprintf(data_buf + pos, sizeof(data_buf) - pos, ",");
            pos += snprintf(data_buf + pos, sizeof(data_buf) - pos, "\"%s\"", esc_v);
            printed_allow++;
        }
        pos += snprintf(data_buf + pos, sizeof(data_buf) - pos, "],");

        char esc_fuse[512];
        json_escape_str(g_global_cfg.fuse_extra_args, esc_fuse, sizeof(esc_fuse));
        pos += snprintf(data_buf + pos, sizeof(data_buf) - pos,
            "\"fuse_extra_args\":\"%s\",", esc_fuse);
        
        pos += snprintf(data_buf + pos, sizeof(data_buf) - pos,
            "\"counts\":{\"hide\":%d,\"ro\":%d,\"redirect\":%d,\"allow\":%d}}",
            g_global_cfg.hide_count,
            g_global_cfg.ro_count,
            real_redir_cnt,
            allow_cnt);
        config_unlock_read();
        json_api_finish(true, "\"get-global-rules\"", data_buf);
    } else {
        printf("===== 全局规则 (GLOBAL) =====\n\n");
        printf("--- Switch 开关 ---\n");
        printf("  GLOBAL_INJECT %s\n", g_global_cfg.global_inject ? "ON" : "OFF");
        printf("  MONITOR       %s\n", g_global_cfg.monitor ? "ON" : "OFF");
        printf("  SANDBOX       %s\n", g_global_cfg.sandbox ? "ON" : "OFF");
        printf("  FUSE_DIRECT   %s\n", g_global_cfg.fuse_direct ? "ON" : "OFF");
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
            if (g_global_cfg.redir_rules[i].real_target[0] == '?') allow_cnt++;
            else real_redir_cnt++;
        }

        printf("\n--- REDIRECT 规则 (%d 条) ---\n", real_redir_cnt);
        int idx = 0;
        for (int i = 0; i < g_global_cfg.redir_count; i++) {
            if (g_global_cfg.redir_rules[i].real_target[0] == '?') continue;
            printf("  [%d] REDIRECT %s %s\n", idx++,
                   g_global_cfg.redir_rules[i].virtual_prefix,
                   g_global_cfg.redir_rules[i].real_target);
        }

        printf("\n--- ALLOW 规则 (%d 条) ---\n", allow_cnt);
        idx = 0;
        for (int i = 0; i < g_global_cfg.redir_count; i++) {
            if (g_global_cfg.redir_rules[i].real_target[0] != '?') continue;
            printf("  [%d] ALLOW %s\n", idx++,
                   g_global_cfg.redir_rules[i].virtual_prefix);
        }

        if (g_global_cfg.fuse_extra_args[0]) {
            printf("\n--- FUSE_EXTRA_ARGS ---\n");
            printf("  %s\n", g_global_cfg.fuse_extra_args);
        }
        config_unlock_read();
    }
}

/* 核心修复：应用配置查询逻辑同步分离 ALLOW */
static void handle_get_app_rules(bool api_mode, const char *pkg, int user_id) {
    config_lock_write();
    load_config_rules(INJECTOR_CONFIG_PATH);
    config_unlock_write();
    config_lock_read();
    AppConfig *cfg = find_app_cfg_locked(pkg, user_id);
    if (!cfg) {
        config_unlock_read();
        char err[256];
        snprintf(err, sizeof(err), "未找到应用 \"%s\" (UID %d) 的配置", pkg, user_id);
        json_api_error(api_mode, "\"get-app-rules\"", err);
        return;
    }
    if (api_mode) {
        char data_buf[65536];
        size_t pos = 0;
        char esc_pkg[256];
        json_escape_str(cfg->pkg_name, esc_pkg, sizeof(esc_pkg));
        pos += snprintf(data_buf + pos, sizeof(data_buf) - pos,
            "{\"pkg\":\"%s\",\"user_id\":%d,"
            "\"switches\":{\"inject_enable\":%s,\"monitor\":%s,\"sandbox\":%s,\"fuse_direct\":%s},",
            esc_pkg, cfg->user_id,
            cfg->inject_enable ? "true" : "false",
            cfg->monitor ? "true" : "false",
            cfg->sandbox ? "true" : "false",
            cfg->fuse_direct ? "true" : "false");
        
        pos += snprintf(data_buf + pos, sizeof(data_buf) - pos, "\"hide_rules\":[");
        for (int i = 0; i < cfg->hide_count; i++) {
            char esc[1024];
            json_escape_str(cfg->hide_rules[i], esc, sizeof(esc));
            if (i > 0) pos += snprintf(data_buf + pos, sizeof(data_buf) - pos, ",");
            pos += snprintf(data_buf + pos, sizeof(data_buf) - pos, "\"%s\"", esc);
        }
        pos += snprintf(data_buf + pos, sizeof(data_buf) - pos, "],");
        
        pos += snprintf(data_buf + pos, sizeof(data_buf) - pos, "\"ro_rules\":[");
        for (int i = 0; i < cfg->ro_count; i++) {
            char esc[1024];
            json_escape_str(cfg->ro_rules[i], esc, sizeof(esc));
            if (i > 0) pos += snprintf(data_buf + pos, sizeof(data_buf) - pos, ",");
            pos += snprintf(data_buf + pos, sizeof(data_buf) - pos, "\"%s\"", esc);
        }
        pos += snprintf(data_buf + pos, sizeof(data_buf) - pos, "],");

        int real_redir_cnt = 0;
        int allow_cnt = 0;
        for (int i = 0; i < cfg->redir_count; i++) {
            if (cfg->redir_rules[i].real_target[0] == '?') allow_cnt++;
            else real_redir_cnt++;
        }

        pos += snprintf(data_buf + pos, sizeof(data_buf) - pos, "\"redirect_rules\":[");
        int printed_redir = 0;
        for (int i = 0; i < cfg->redir_count; i++) {
            if (cfg->redir_rules[i].real_target[0] == '?') continue;
            char esc_v[1024], esc_r[1024];
            json_escape_str(cfg->redir_rules[i].virtual_prefix, esc_v, sizeof(esc_v));
            json_escape_str(cfg->redir_rules[i].real_target, esc_r, sizeof(esc_r));
            if (printed_redir > 0) pos += snprintf(data_buf + pos, sizeof(data_buf) - pos, ",");
            pos += snprintf(data_buf + pos, sizeof(data_buf) - pos,
                "{\"virtual_prefix\":\"%s\",\"real_target\":\"%s\"}", esc_v, esc_r);
            printed_redir++;
        }
        pos += snprintf(data_buf + pos, sizeof(data_buf) - pos, "],");

        pos += snprintf(data_buf + pos, sizeof(data_buf) - pos, "\"allow_rules\":[");
        int printed_allow = 0;
        for (int i = 0; i < cfg->redir_count; i++) {
            if (cfg->redir_rules[i].real_target[0] != '?') continue;
            char esc_v[1024];
            json_escape_str(cfg->redir_rules[i].virtual_prefix, esc_v, sizeof(esc_v));
            if (printed_allow > 0) pos += snprintf(data_buf + pos, sizeof(data_buf) - pos, ",");
            pos += snprintf(data_buf + pos, sizeof(data_buf) - pos, "\"%s\"", esc_v);
            printed_allow++;
        }
        pos += snprintf(data_buf + pos, sizeof(data_buf) - pos, "],");

        pos += snprintf(data_buf + pos, sizeof(data_buf) - pos,
            "\"counts\":{\"hide\":%d,\"ro\":%d,\"redirect\":%d,\"allow\":%d}}",
            cfg->hide_count,
            cfg->ro_count,
            real_redir_cnt,
            allow_cnt);
        config_unlock_read();
        json_api_finish(true, "\"get-app-rules\"", data_buf);
    } else {
        printf("===== 应用规则: %s (UID %d) =====\n\n", cfg->pkg_name, cfg->user_id);
        printf("--- Switch 开关 ---\n");
        printf("  INJECT_ENABLE %s\n", cfg->inject_enable ? "ON" : "OFF");
        printf("  MONITOR       %s\n", cfg->monitor ? "ON" : "OFF");
        printf("  SANDBOX       %s\n", cfg->sandbox ? "ON" : "OFF");
        printf("  FUSE_DIRECT   %s\n", cfg->fuse_direct ? "ON" : "OFF");
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
            if (cfg->redir_rules[i].real_target[0] == '?') allow_cnt++;
            else real_redir_cnt++;
        }

        printf("\n--- REDIRECT 规则 (%d 条) ---\n", real_redir_cnt);
        int idx = 0;
        for (int i = 0; i < cfg->redir_count; i++) {
            if (cfg->redir_rules[i].real_target[0] == '?') continue;
            printf("  [%d] REDIRECT %s %s\n", idx++,
                   cfg->redir_rules[i].virtual_prefix,
                   cfg->redir_rules[i].real_target);
        }

        printf("\n--- ALLOW 规则 (%d 条) ---\n", allow_cnt);
        idx = 0;
        for (int i = 0; i < cfg->redir_count; i++) {
            if (cfg->redir_rules[i].real_target[0] != '?') continue;
            printf("  [%d] ALLOW %s\n", idx++,
                   cfg->redir_rules[i].virtual_prefix);
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
    const char *err = send_reload_signal();
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
    FILE *fp = fopen("/proc/self/mountinfo", "r");
    if (fp) {
        char line[512];
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, "fuse") && strstr(line, "nsp_global")) {
                char *tok = strtok(line, " ");
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
    if (stat(INJECTOR_CONFIG_PATH, &st) == 0) main_conf_size = (int)st.st_size;
    
    int app_rule_files = 0;
    DIR *dir = opendir(CONFIG_DIR);
    if (dir) {
        struct dirent *de;
        while ((de = readdir(dir)) != nullptr) {
            if (de->d_type != DT_DIR) continue;
            if (strcmp(de->d_name, "App-rules") != 0 &&
                strncmp(de->d_name, "App-rules-", 10) != 0)
                continue;
            char rules_dir[PATH_MAX];
            snprintf(rules_dir, sizeof(rules_dir), "%s/%s", CONFIG_DIR, de->d_name);
            DIR *rdir = opendir(rules_dir);
            if (rdir) {
                struct dirent *rde;
                while ((rde = readdir(rdir)) != nullptr) {
                    if (rde->d_type == DT_REG || rde->d_type == DT_LNK) {
                        char *ext = strrchr(rde->d_name, '.');
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
        char data_buf[4096];
        char time_str[64];
        time_t now = time(NULL);
        struct tm tm_info;
        localtime_r(&now, &tm_info);
        strftime(time_str, sizeof(time_str), "%Y-%m-%dT%H:%M:%S", &tm_info);
        snprintf(data_buf, sizeof(data_buf),
            "{\"timestamp\":%lld,\"time\":\"%s\","
            "\"injector\":{\"pid\":%d,\"alive\":%s},"
            "\"fuse\":{\"pid\":%d,\"alive\":%s},"
            "\"config\":{\"main_conf_path\":\"%s\",\"main_conf_size\":%d,\"app_rule_files\":%d,\"parsed_apps_in_memory\":%d},"
            "\"system\":{\"config_dir\":\"%s\",\"pid_file\":\"%s\"}}",
            (long long)now, time_str,
            injector_pid, injector_alive ? "true" : "false",
            fuse_pid, fuse_alive ? "true" : "false",
            INJECTOR_CONFIG_PATH, main_conf_size,
            app_rule_files, mem_app_count,
            CONFIG_DIR, INJECTOR_PID_PATH);
        json_api_finish(true, "\"status\"", data_buf);
    } else {
        printf("===== 系统状态概览 =====\n");
        printf("时间: %lld\n", (long long)time(NULL));
        printf("注入器: PID %d [%s]\n", injector_pid, injector_alive ? "运行中" : "未运行");
        printf("FUSE 守护进程: PID %d [%s]\n", fuse_pid, fuse_alive ? "运行中" : "未运行");
        printf("主配置文件: %s (%d 字节)\n", INJECTOR_CONFIG_PATH, main_conf_size);
        printf("应用规则文件数: %d\n", app_rule_files);
        printf("内存中已解析应用: %d\n", mem_app_count);
    }
}

/* ========== set-rule / remove-rule 处理 ========== */
static char **read_file_lines(const char *path, int *out_count, int *out_cap) {
    FILE *fp = fopen(path, "r");
    if (!fp) { *out_count = 0; *out_cap = 0; return NULL; }
    char **lines = NULL;
    int count = 0, cap = 0;
    char buf[2048];
    while (fgets(buf, sizeof(buf), fp)) {
        if (count >= cap) {
            cap = cap == 0 ? 64 : cap * 2;
            char **new_lines = realloc(lines, cap * sizeof(char *));
            if (!new_lines) {
                for (int j = 0; j < count; j++) free(lines[j]);
                free(lines);
                fclose(fp);
                *out_count = 0; *out_cap = 0; return NULL;
            }
            lines = new_lines;
        }
        lines[count] = strdup(buf);
        if (!lines[count]) {
            for (int j = 0; j < count; j++) free(lines[j]);
            free(lines);
            fclose(fp);
            *out_count = 0; *out_cap = 0; return NULL;
        }
        count++;
    }
    fclose(fp);
    *out_count = count; *out_cap = cap;
    return lines;
}

static bool write_file_lines(const char *path, char **lines, int count) {
    FILE *fp = fopen(path, "w");
    if (!fp) return false;
    for (int i = 0; i < count; i++) {
        if (fputs(lines[i], fp) < 0) { fclose(fp); return false; }
    }
    fclose(fp);
    return true;
}

static void free_file_lines(char **lines, int count) {
    for (int i = 0; i < count; i++) free(lines[i]);
    free(lines);
}

static int insert_line_at(char ***lines, int *cap, int count, int pos, const char *text) {
    if (pos < 0 || pos > count) return -1;
    if (count >= *cap) {
        *cap = *cap == 0 ? 64 : *cap * 2;
        char **new_lines = realloc(*lines, *cap * sizeof(char *));
        if (!new_lines) return -1;
        *lines = new_lines;
    }
    memmove(&(*lines)[pos + 1], &(*lines)[pos], (count - pos) * sizeof(char *));
    (*lines)[pos] = strdup(text);
    return (*lines)[pos] ? count + 1 : -1;
}

static void remove_line_at(char **lines, int *count, int pos) {
    if (pos < 0 || pos >= *count) return;
    free(lines[pos]);
    memmove(&lines[pos], &lines[pos + 1], (*count - pos - 1) * sizeof(char *));
    (*count)--;
}

static int append_line(char ***lines, int *cap, int count, const char *text) {
    return insert_line_at(lines, cap, count, count, text);
}

static int find_section_header(char **lines, int count, const char *name) {
    size_t nlen = strlen(name);
    for (int i = 0; i < count; i++) {
        char *p = lines[i];
        while (isspace((unsigned char)*p)) p++;
        if (p[0] == '[' && strncmp(p + 1, name, nlen) == 0) {
            char after = p[1 + nlen];
            if (after == ']' || after == ':') return i;
        }
    }
    return -1;
}

static int find_switch_in_section(char **lines, int count, int header_idx, const char *type) {
    size_t tlen = strlen(type);
    for (int i = header_idx + 1; i < count; i++) {
        char *p = lines[i];
        while (isspace((unsigned char)*p)) p++;
        if (p[0] == '[') break;
        if (strncasecmp(p, type, tlen) == 0 &&
            (p[tlen] == ' ' || p[tlen] == '\t' || p[tlen] == '\n')) {
            return i;
        }
    }
    return -1;
}

static void handle_set_rule(bool api_mode, const char *pkg, const char *type,
                            const char *value, int user_id) {
    if (!pkg || !type || !value) {
        json_api_error(api_mode, "\"set-rule\"", "缺少必要参数: pkg type value");
        return;
    }
    char rule_path[PATH_MAX];
    if (strcmp(pkg, "GLOBAL") == 0) {
        snprintf(rule_path, sizeof(rule_path), "%s", INJECTOR_CONFIG_PATH);
    } else {
        get_app_rule_path(rule_path, sizeof(rule_path), pkg, user_id);
        char rule_dir[PATH_MAX];
        get_app_rule_dir(rule_dir, sizeof(rule_dir), user_id);
        mkdir_recursive(rule_dir);
    }
    char line[1024];
    if (strcmp(type, "REDIRECT") == 0) {
        char src[512], dst[512];
        const char *sep = strchr(value, '|');
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
    } else if (strcmp(type, "MONITOR") == 0 ||
               strcmp(type, "SANDBOX") == 0 ||
               strcmp(type, "GLOBAL_INJECT") == 0 ||
               strcmp(type, "FUSE_DIRECT") == 0) {
        snprintf(line, sizeof(line), "%s %s\n", type, value);
    } else {
        char err_buf[128];
        snprintf(err_buf, sizeof(err_buf), "未知规则类型: %s", type);
        json_api_error(api_mode, "\"set-rule\"", err_buf);
        return;
    }
    
    bool is_global_switch = (strcmp(type, "MONITOR") == 0 ||
                             strcmp(type, "SANDBOX") == 0 ||
                             strcmp(type, "GLOBAL_INJECT") == 0 ||
                             strcmp(type, "FUSE_DIRECT") == 0);
    if (strcmp(pkg, "GLOBAL") == 0) {
        int line_count = 0, line_cap = 0;
        char **lines = read_file_lines(rule_path, &line_count, &line_cap);
        if (!lines) {
            FILE *fp = fopen(rule_path, "w");
            if (!fp) {
                char err_buf[256];
                snprintf(err_buf, sizeof(err_buf), "无法创建规则文件 %s: %s", rule_path, strerror(errno));
                json_api_error(api_mode, "\"set-rule\"", err_buf);
                return;
            }
            fprintf(fp, "[GLOBAL]\n");
            fputs(line, fp);
            fclose(fp);
            goto report_success;
        }
        int hdr = find_section_header(lines, line_count, "GLOBAL");
        bool changed = false;
        if (is_global_switch && hdr >= 0) {
            int old = find_switch_in_section(lines, line_count, hdr, type);
            if (old >= 0) {
                if (strcmp(lines[old], line) != 0) {
                    free(lines[old]);
                    lines[old] = strdup(line);
                    if (!lines[old]) {
                        free_file_lines(lines, line_count);
                        json_api_error(api_mode, "\"set-rule\"", "内存不足");
                        return;
                    }
                    changed = true;
                }
            } else {
                int new_count = insert_line_at(&lines, &line_cap, line_count, hdr + 1, line);
                if (new_count < 0) {
                    free_file_lines(lines, line_count);
                    json_api_error(api_mode, "\"set-rule\"", "内存不足");
                    return;
                }
                line_count = new_count;
                changed = true;
            }
        } else if (hdr >= 0) {
            bool dup = false;
            for (int i = hdr + 1; i < line_count; i++) {
                char *p = lines[i];
                while (isspace((unsigned char)*p)) p++;
                if (p[0] == '[') break;
                if (strcmp(p, line) == 0) { dup = true; break; }
            }
            if (!dup) {
                int new_count = insert_line_at(&lines, &line_cap, line_count, hdr + 1, line);
                if (new_count < 0) {
                    free_file_lines(lines, line_count);
                    json_api_error(api_mode, "\"set-rule\"", "内存不足");
                    return;
                }
                line_count = new_count;
                changed = true;
            }
        } else {
            int new_count = append_line(&lines, &line_cap, line_count, "[GLOBAL]\n");
            if (new_count < 0) {
                free_file_lines(lines, line_count);
                json_api_error(api_mode, "\"set-rule\"", "内存不足");
                return;
            }
            line_count = new_count;
            new_count = append_line(&lines, &line_cap, line_count, line);
            if (new_count < 0) {
                free_file_lines(lines, line_count);
                json_api_error(api_mode, "\"set-rule\"", "内存不足");
                return;
            }
            line_count = new_count;
            changed = true;
        }
        if (changed) {
            if (!write_file_lines(rule_path, lines, line_count)) {
                char err_buf[256];
                snprintf(err_buf, sizeof(err_buf), "无法写入规则文件 %s: %s", rule_path, strerror(errno));
                free_file_lines(lines, line_count);
                json_api_error(api_mode, "\"set-rule\"", err_buf);
                return;
            }
        }
        free_file_lines(lines, line_count);
    } else {
        FILE *fp = fopen(rule_path, "a");
        if (!fp) {
            char err_buf[256];
            snprintf(err_buf, sizeof(err_buf), "无法打开规则文件 %s: %s", rule_path, strerror(errno));
            json_api_error(api_mode, "\"set-rule\"", err_buf);
            return;
        }
        if (fputs(line, fp) < 0) {
            char err_buf[256];
            snprintf(err_buf, sizeof(err_buf), "写入规则文件失败: %s", strerror(errno));
            fclose(fp);
            json_api_error(api_mode, "\"set-rule\"", err_buf);
            return;
        }
        fclose(fp);
    }
report_success:
    if (api_mode) {
        char data_buf[1024];
        char esc_file[256], esc_line[256];
        json_escape_str(rule_path, esc_file, sizeof(esc_file));
        json_escape_str(line, esc_line, sizeof(esc_line));
        snprintf(data_buf, sizeof(data_buf),
            "{\"file\":\"%s\",\"line\":\"%s\",\"pkg\":\"%s\",\"type\":\"%s\",\"value\":\"%s\"}",
            esc_file, esc_line, pkg, type, value);
        json_api_finish(true, "\"set-rule\"", data_buf);
    } else {
        printf("已向 %s 写入规则: %s", rule_path, line);
    }
}

static void handle_remove_rule(bool api_mode, const char *pkg, const char *type,
                               int index, int user_id) {
    if (!pkg || !type) {
        json_api_error(api_mode, "\"remove-rule\"", "缺少必要参数: pkg type index");
        return;
    }
    if (index < 0) {
        json_api_error(api_mode, "\"remove-rule\"", "索引必须 >= 0");
        return;
    }
    char rule_path[PATH_MAX];
    if (strcmp(pkg, "GLOBAL") == 0) {
        snprintf(rule_path, sizeof(rule_path), "%s", INJECTOR_CONFIG_PATH);
    } else {
        get_app_rule_path(rule_path, sizeof(rule_path), pkg, user_id);
    }
    int line_count = 0, line_cap = 0;
    char **lines = read_file_lines(rule_path, &line_count, &line_cap);
    if (!lines) {
        char err_buf[256];
        snprintf(err_buf, sizeof(err_buf), "无法打开规则文件 %s: %s", rule_path, strerror(errno));
        json_api_error(api_mode, "\"remove-rule\"", err_buf);
        return;
    }
    int found_idx = -1, skip_idx = 0;
    size_t tlen = strlen(type);
    for (int i = 0; i < line_count; i++) {
        char *p = lines[i];
        while (isspace((unsigned char)*p)) p++;
        if (p[0] == '#') continue;
        bool is_type_rule = (strncasecmp(p, type, tlen) == 0 &&
                            (p[tlen] == ' ' || p[tlen] == '\t'));
        if (is_type_rule) {
            if (skip_idx == index) { found_idx = i; break; }
            skip_idx++;
        }
    }
    if (found_idx < 0) {
        free_file_lines(lines, line_count);
        char err_buf[128];
        snprintf(err_buf, sizeof(err_buf), "未找到 %s 类型的第 %d 条规则", type, index);
        json_api_error(api_mode, "\"remove-rule\"", err_buf);
        return;
    }
    remove_line_at(lines, &line_count, found_idx);
    if (!write_file_lines(rule_path, lines, line_count)) {
        char err_buf[256];
        snprintf(err_buf, sizeof(err_buf), "无法写入规则文件 %s: %s", rule_path, strerror(errno));
        free_file_lines(lines, line_count);
        json_api_error(api_mode, "\"remove-rule\"", err_buf);
        return;
    }
    free_file_lines(lines, line_count);
    if (api_mode) {
        char esc_file[256];
        json_escape_str(rule_path, esc_file, sizeof(esc_file));
        char data_buf[512];
        snprintf(data_buf, sizeof(data_buf),
            "{\"file\":\"%s\",\"pkg\":\"%s\",\"type\":\"%s\",\"index\":%d}",
            esc_file, pkg, type, index);
        json_api_finish(true, "\"remove-rule\"", data_buf);
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
    struct sockaddr_un local = { .sun_family = AF_UNIX };
    local.sun_path[0] = '\0';
    snprintf(local.sun_path + 1, sizeof(local.sun_path) - 2, "nsp_ctl_%d", getpid());
    socklen_t local_len = offsetof(struct sockaddr_un, sun_path) + 1 + strlen(local.sun_path + 1);
    if (bind(sock, (struct sockaddr *)&local, local_len) < 0) {
        perror("绑定本地 DGRAM 地址失败");
        close(sock);
        return -1;
    }
    return sock;
}

static int config_broadcast_send_cmd(int sock, const char *cmd) {
    struct sockaddr_un pub = { .sun_family = AF_UNIX };
    pub.sun_path[0] = '\0';
    strncpy(pub.sun_path + 1, CONFIG_BROADCAST_SOCKET, sizeof(pub.sun_path) - 2);
    socklen_t pub_len = offsetof(struct sockaddr_un, sun_path) + 1 + strlen(CONFIG_BROADCAST_SOCKET);
    return sendto(sock, cmd, strlen(cmd), MSG_NOSIGNAL,
                  (struct sockaddr *)&pub, pub_len);
}

static ssize_t config_broadcast_recv(int sock, char *buf, size_t size, int timeout_ms) {
    struct pollfd pfd = { .fd = sock, .events = POLLIN };
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
    const char *cmd = static_mode ? "STATIC" : "GET";
    if (config_broadcast_send_cmd(sock, cmd) < 0) {
        perror("发送命令失败");
        close(sock);
        return;
    }
    char *resp = malloc(BROADCAST_RECEIVE_MAX_SIZE);
    if (!resp) {
        fprintf(stderr, "系统物理内存不足，无法分配接收缓冲区\n");
        close(sock);
        return;
    }
    ssize_t n = config_broadcast_recv(sock, resp, BROADCAST_RECEIVE_MAX_SIZE, 3000);
    close(sock);
    if (n < 0) {
        fprintf(stderr, "未获取到配置信息（%s）\n",
                (n == -2) ? "超时" : strerror(errno));
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
    char *resp = malloc(BROADCAST_RECEIVE_MAX_SIZE);
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
    struct sigaction sa = { .sa_handler = sigint_handler };
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
                for (char* c = open_p + 1; c < close_p; c++) if (!isdigit((unsigned char)*c)) is_uid = false;
                if (is_uid) memmove(open_p, close_p + 1, strlen(close_p + 1) + 1);
            } else {
                char* close_b = strchr(open_p, ']');
                char* term = close_b ? close_b : (open_p + strlen(open_p));
                if (term > open_p) {
                    bool is_uid = true;
                    for (char* c = open_p + 1; c < term; c++) {
                        if (!isdigit((unsigned char)*c)) { is_uid = false; break; }
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
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    addr.sun_path[0] = '\0';
    strncpy(addr.sun_path + 1, IPC_SOCKET_NAME, sizeof(addr.sun_path) - 2);
    socklen_t addr_len = offsetof(struct sockaddr_un, sun_path) + 1 + strlen(IPC_SOCKET_NAME);
    if (connect(sock, (struct sockaddr*)&addr, addr_len) < 0) {
        perror("连接注入器 IPC 服务失败");
        return;
    }
    write(sock, "LIST_INJECTED", 13);
    shutdown(sock, SHUT_WR);
    struct pollfd pfd = { .fd = sock, .events = POLLIN };
    if (poll(&pfd, 1, 1000) <= 0) {
        if (!api_mode) fprintf(stderr, "未获取到响应\n");
        close(sock);
        return;
    }
    char resp[8192];
    ssize_t n = read(sock, resp, sizeof(resp) - 1);
    close(sock);
    if (n <= 0) {
        if (!api_mode) fprintf(stderr, "未获取到响应\n");
        return;
    }
    resp[n] = '\0';
    if (api_mode) {
        char *done_line = NULL;
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
        char esc[8192];
        json_escape_str(resp, esc, sizeof(esc));
        char data_buf[8192 + 128];
        if (has_done) {
            snprintf(data_buf, sizeof(data_buf),
                "{\"raw\":\"%s\",\"done\":{\"total\":%d}}", esc, done_total);
        } else {
            snprintf(data_buf, sizeof(data_buf), "{\"raw\":\"%s\"}", esc);
        }
        json_api_finish(true, "\"list-injected\"", data_buf);
        return;
    }
    int total = 0;
    char* line = strtok(resp, "\n");
    printf("\n已注入应用列表:\n");
    printf("%-4s %-40s %-7s %-8s %-5s %-5s %-5s\n",
           "序号", "包名", "PID", "UID", "重定向", "隐藏", "只读");
    printf("%s\n", "---- --------------------------------------- ------- -------- ----- ----- -----");
    int idx = 1;
    while (line) {
        if (strncmp(line, "APP|", 4) == 0) {
            char pkg[256]; int pid, uid, r, h, ro;
            if (sscanf(line, "APP|%255[^|]|%d|%d|%d|%d|%d", pkg, &pid, &uid, &r, &h, &ro) == 6) {
                printf("%-4d %-40s %-7d %-8d %-5d %-5d %-5d\n",
                       idx++, pkg, pid, uid, r, h, ro);
            }
        } else if (strncmp(line, "DONE|", 5) == 0) {
            sscanf(line + 5, "%d", &total);
        }
        line = strtok(nullptr, "\n");
    }
    printf("\n共计 %d 个应用已注入\n", total);
}

static void handle_list_users(bool api_mode) {
    config_lock_read();
    int count = g_active_user_count;
    if (api_mode) {
        char data_buf[4096];
        size_t pos = 0;
        pos += snprintf(data_buf + pos, sizeof(data_buf) - pos,
            "{\"count\":%d,\"users\":[", count);
        for (int i = 0; i < count; i++) {
            int uid = g_active_users[i];
            int app_cnt = 0;
            for (int j = 0; j < g_app_cfg_count; j++) {
                if (g_app_cfgs[j]->user_id == uid) app_cnt++;
            }
            if (i > 0) pos += snprintf(data_buf + pos, sizeof(data_buf) - pos, ",");
            pos += snprintf(data_buf + pos, sizeof(data_buf) - pos,
                "{\"uid\":%d,\"app_count\":%d}", uid, app_cnt);
        }
        pos += snprintf(data_buf + pos, sizeof(data_buf) - pos, "]}");
        config_unlock_read();
        json_api_finish(true, "\"list-users\"", data_buf);
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
}

static void stream_logs(const char* stream_cmd) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(LOG_TCP_PORT);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
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
    struct sigaction sa = { .sa_handler = sigint_handler };
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
    char buf[8192];
    char line_buf[8192];
    size_t line_pos = 0;
    int epfd = epoll_create1(0);
    if (epfd < 0) { perror("epoll_create1"); close(sock); return; }
    struct epoll_event ep_ev = { .events = EPOLLIN, .data.fd = sock };
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

int main(int argc, char *argv[]) {
    if (argc < 2) usage(argv[0]);
    bool api_mode = false;
    bool force_uid = false;
    bool static_mode = false;
    char *level_arg = NULL;
    char *pos_args[10] = {NULL};
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
            level_arg = argv[++i];
        } else if (strcmp(argv[i], "--uid") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "错误: --uid 需要指定用户 ID\n");
                usage(argv[0]);
            }
            user_id = atoi(argv[++i]);
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
            json_api_error(api_mode, "\"get-app-rules\"", "用法: log_ctl get-app-rules <pkg> [--uid uid] [api]");
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
            json_api_error(api_mode, "\"set-rule\"", "用法: log_ctl set-rule <pkg> <type> <value> [--uid uid] [api]");
            return 1;
        }
        handle_set_rule(api_mode, pos_args[1], pos_args[2], pos_args[3], user_id);
        return 0;
    }
    if (strcmp(pos_args[0], "remove-rule") == 0) {
        if (pos_idx < 4) {
            json_api_error(api_mode, "\"remove-rule\"", "用法: log_ctl remove-rule <pkg> <type> <index> [--uid uid] [api]");
            return 1;
        }
        int index = atoi(pos_args[3]);
        handle_remove_rule(api_mode, pos_args[1], pos_args[2], index, user_id);
        return 0;
    }
    if (strncmp(pos_args[0], "stream", 6) == 0) {
        const char *level = level_arg ? level_arg : "0";
        char stream_cmd[64] = {0};
        if (strcmp(pos_args[0], "stream-io") == 0) {
            snprintf(stream_cmd, sizeof(stream_cmd), "STREAM_IO:%s", level);
        } else if (strcmp(pos_args[0], "stream-sys") == 0) {
            snprintf(stream_cmd, sizeof(stream_cmd), api_mode ? "STREAM_SYS_API:%s" : "STREAM_SYS:%s", level);
        } else if (strcmp(pos_args[0], "stream-logcat") == 0) {
            snprintf(stream_cmd, sizeof(stream_cmd), "STREAM_LOGCAT:%s", level);
        } else if (strcmp(pos_args[0], "stream-all") == 0) {
            snprintf(stream_cmd, sizeof(stream_cmd), "STREAM_ALL:%s", level);
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
    if (strcmp(pos_args[0], "stream-config") == 0) {
        handle_stream_config(api_mode);
        return 0;
    }
    if (strcmp(pos_args[0], "log-count") == 0) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in log_addr;
        memset(&log_addr, 0, sizeof(log_addr));
        log_addr.sin_family = AF_INET;
        log_addr.sin_port = htons(LOG_TCP_PORT);
        inet_pton(AF_INET, "127.0.0.1", &log_addr.sin_addr);
        if (connect(sock, (struct sockaddr*)&log_addr, sizeof(log_addr)) < 0) {
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
                snprintf(data_buf, sizeof(data_buf),
                    "{\"io\":%d,\"sys\":%d,\"logcat\":%d}", io_total, sys_total, logcat_total);
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
    
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("创建 socket 失败");
        return 1;
    }
    struct sockaddr_in log_addr;
    memset(&log_addr, 0, sizeof(log_addr));
    log_addr.sin_family = AF_INET;
    log_addr.sin_port = htons(LOG_TCP_PORT);
    inet_pton(AF_INET, "127.0.0.1", &log_addr.sin_addr);
    if (connect(sock, (struct sockaddr*)&log_addr, sizeof(log_addr)) < 0) {
        perror("连接日志服务失败");
        close(sock);
        return 1;
    }
    char cmd[128];
    if (strstr(pos_args[0], "search") != NULL) {
        const char *key = "";
        const char *limit = "100";
        const char *offset = "0";
        if (pos_idx > 1) key = pos_args[1];
        if (pos_idx > 2) limit = pos_args[2];
        if (pos_idx > 3) offset = pos_args[3];
        const char *level = level_arg ? level_arg : "-1";
        snprintf(cmd, sizeof(cmd), "QUERY_%s:%s:%s:%s:%s\n",
                 strstr(pos_args[0], "io") ? "IO" : "SYS",
                 level, key, limit, offset);
    } else if (strstr(pos_args[0], "clear") != NULL) {
        snprintf(cmd, sizeof(cmd), "CLEAR_%s\n", strstr(pos_args[0], "io") ? "IO" : "SYS");
    } else {
        close(sock);
        usage(argv[0]);
        return 1;
    }
    write(sock, cmd, strlen(cmd));
    shutdown(sock, SHUT_WR);
    struct pollfd pfd = { .fd = sock, .events = POLLIN };
    if (poll(&pfd, 1, 5000) <= 0) {
        close(sock);
        return 1;
    }
    
    size_t cap = 65536;
    char *resp = malloc(cap);
    if (!resp) { close(sock); return 1; }
    size_t total = 0;
    ssize_t n;
    while ((n = read(sock, resp + total, cap - 1 - total)) > 0) {
        total += (size_t)n;
        if (total >= cap - 1) {
            cap *= 2;
            char *tmp = realloc(resp, cap);
            if (!tmp) { free(resp); close(sock); return 1; }
            resp = tmp;
        }
    }
    if (total > 0) {
        resp[total] = '\0';
        if (api_mode) {
            char *done_line = NULL;
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
            
            size_t raw_len = strlen(resp);
            size_t esc_cap = raw_len * 6 + 1;
            char *esc = malloc(esc_cap);
            if (!esc) { free(resp); close(sock); return 1; }
            json_escape_str(resp, esc, esc_cap);
            size_t data_cap = esc_cap + 256;
            char *data_buf = malloc(data_cap);
            if (!data_buf) { free(esc); free(resp); close(sock); return 1; }
            if (has_done) {
                snprintf(data_buf, data_cap,
                    "{\"raw\":\"%s\",\"done\":{\"total\":%d,\"remaining\":%d}}",
                    esc, done_total, done_remaining);
            } else {
                snprintf(data_buf, data_cap, "{\"raw\":\"%s\"}", esc);
            }
            json_api_finish(true, (strncmp(pos_args[0], "search", 6) == 0) ? "\"search\"" : "\"clear\"", data_buf);
            free(data_buf);
            free(esc);
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