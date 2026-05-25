#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <stddef.h>
#include <ctype.h>
#include <signal.h>

#include "common.h"

static volatile int g_running = 1;

void sigint_handler(int sig) {
    (void)sig;
    g_running = 0;
}

void usage(const char* prog) {
    printf("用法: %s <command> [args]\n", prog);
    printf("\n日志查询命令:\n");
    printf("  search-io|search-sys [key] [limit] [offset] [level] [-u] [api]\n");
    printf("    level: 日志级别过滤: 0=DEBUG, 1=INFO, 2=ERROR (仅 search-sys 有效，默认全部)\n");
    printf("  clear-io|clear-sys\n");
    printf("\n流式日志命令（实时输出，Ctrl+C 停止）:\n");
    printf("  stream-io\n");
    printf("  stream-sys\n");
    printf("  stream-logcat\n");
    printf("  stream-all\n");
    printf("\n注入状态命令:\n");
    printf("  list-injected [api]\n");
    printf("\n选项:\n  -u    始终显示 UID\n");
    exit(1);
}

void process_and_print(char* line, int force_uid, int api_mode) {
    char* p = strstr(line, "[fuse_daemon] ");
    if (p) memmove(p, p + 14, strlen(p + 14) + 1);

    char* open_b = strchr(line, '[');
    if (open_b && !force_uid) {
        char* open_p = strchr(open_b, '(');
        char* close_p = strchr(open_b, ')');
        if (open_p && close_p && open_p < close_p) {
            int is_uid = 1;
            for (char* c = open_p + 1; c < close_p; c++) if (!isdigit(*c)) is_uid = 0;
            if (is_uid) memmove(open_p, close_p + 1, strlen(close_p + 1) + 1);
        }
    }
    printf("%s\n", line);
    fflush(stdout);
}

static void handle_list_injected(int api_mode) {
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
        printf("%s", resp);
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
        line = strtok(NULL, "\n");
    }
    printf("\n共计 %d 个应用已注入\n", total);
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

    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);

    FILE* fp = fdopen(sock, "r");
    if (!fp) {
        perror("fdopen");
        close(sock);
        return;
    }

    char* line = NULL;
    size_t len = 0;
    ssize_t read_len;

    while (g_running && (read_len = getline(&line, &len, fp)) != -1) {
        if (read_len > 0 && line[read_len - 1] == '\n') line[read_len - 1] = '\0';
        process_and_print(line, 0, 0);
    }

    free(line);
    fclose(fp);  
}

int main(int argc, char *argv[]) {
    if (argc < 2) usage(argv[0]);

    int api_mode = 0, force_uid = 0;
    char *pos_args[5] = {NULL};
    int pos_idx = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "api") == 0) api_mode = 1;
        else if (strcmp(argv[i], "-u") == 0) force_uid = 1;
        else if (pos_idx < 5) pos_args[pos_idx++] = argv[i];
    }

    if (pos_args[0] && strncmp(pos_args[0], "stream", 6) == 0) {
        const char* cmd = NULL;
        if (strcmp(pos_args[0], "stream-io") == 0) cmd = "STREAM_IO";
        else if (strcmp(pos_args[0], "stream-sys") == 0) cmd = "STREAM_SYS";
        else if (strcmp(pos_args[0], "stream-logcat") == 0) cmd = "STREAM_LOGCAT";
        else if (strcmp(pos_args[0], "stream-all") == 0) cmd = "STREAM_ALL";
        else usage(argv[0]);

        stream_logs(cmd);
        return 0;
    }

    if (pos_args[0] && strcmp(pos_args[0], "list-injected") == 0) {
        handle_list_injected(api_mode);
        return 0;
    }

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

    char cmd[1024] = {0};
    if (pos_args[0] && strncmp(pos_args[0], "search", 6) == 0) {
        int is_io = (strstr(pos_args[0], "io") != NULL);
        snprintf(cmd, sizeof(cmd)-1, "%s:%s:%s:%s:%s\n",
            is_io ? "QUERY_IO" : "QUERY_SYS",
            pos_args[1] ? pos_args[1] : "",
            pos_args[2] ? pos_args[2] : "500",
            pos_args[3] ? pos_args[3] : "0",
            !is_io && pos_args[4] ? pos_args[4] : "-1");
    } else if (pos_args[0] && strncmp(pos_args[0], "clear", 5) == 0) {
        snprintf(cmd, sizeof(cmd)-1, "CLEAR_%s\n", strstr(pos_args[0], "io") ? "IO" : "SYS");
    } else { close(sock); usage(argv[0]); }

    write(sock, cmd, strlen(cmd));
    shutdown(sock, SHUT_WR);

    struct pollfd pfd = { .fd = sock, .events = POLLIN };
    if (poll(&pfd, 1, 1000) <= 0) {
        close(sock);
        return 1;
    }

    char resp[16384];
    size_t total = 0;
    while (total < sizeof(resp) - 1) {
        ssize_t n = read(sock, resp + total, sizeof(resp) - 1 - total);
        if (n <= 0) break;
        total += n;
    }
    if (total > 0) {
        resp[total] = '\0';
        char* line = strtok(resp, "\n");
        while (line) {
            if (strncmp(line, "DONE|", 5) == 0) {
                if (!api_mode) {
                    int total, remain;
                    if (sscanf(line + 5, "%d|%d", &total, &remain) == 2)
                        fprintf(stderr, "\n[统计] 总数: %d | 剩余: %d\n", total, remain);
                }
                break;
            } else if (strcmp(line, "OK") != 0) {
                process_and_print(line, force_uid, api_mode);
            }
            line = strtok(NULL, "\n");
        }
    }
    close(sock);
    return 0;
}