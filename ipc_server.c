#define _GNU_SOURCE
#include "ipc_server.h"
#include "common.h"
#include "injector.h"
#include "inject_target.h"
#include "mount_manager.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <pthread.h>
#include <errno.h>
#include <stddef.h>

struct IpcTask { char pkg[256]; int pid; uid_t uid; int client_fd; };
struct ListInjectedTask { int client_fd; };

static void* handle_ipc_task(void* arg) {
    struct IpcTask* task = (struct IpcTask*)arg;
    int pid = task->pid; char* pkg = task->pkg; uid_t uid = task->uid; int client_fd = task->client_fd;
    if (client_fd >= 0) { send(client_fd, "OK", 2, MSG_NOSIGNAL); close(client_fd); }

    int match = is_target_app(pkg, uid, pid, 1);
    if (!match) { free(task); return NULL; }
    if (kill(pid, 0) != 0) { free(task); return NULL; }
    if (access("/storage/emulated/", F_OK) != 0) { free(task); return NULL; }

    const char* mnt_src = get_active_mnt_src();
    if (!mnt_src) { LOG_ERR("IPC: 全局 FUSE 不可用，无法为 %s 挂载", pkg); free(task); return NULL; }

    perform_app_mount(pkg, pid, uid, mnt_src, "IPC通知");
    free(task); return NULL;
}

static void* handle_list_injected_thread(void* arg) {
    struct ListInjectedTask* task = (struct ListInjectedTask*)arg; int client_fd = task->client_fd; free(task);
    handle_list_injected(client_fd); close(client_fd); return NULL;
}

void* ipc_server_thread(void* arg) {
    (void)arg; int sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0); 
    if (sock < 0) return NULL;
    struct sockaddr_un addr = { .sun_family = AF_UNIX }; addr.sun_path[0] = '\0';
    strncpy(addr.sun_path + 1, IPC_SOCKET_NAME, sizeof(addr.sun_path)-2);
    socklen_t addr_len = offsetof(struct sockaddr_un, sun_path) + 1 + strlen(IPC_SOCKET_NAME);
    if (bind(sock, (struct sockaddr*)&addr, addr_len) < 0) { close(sock); return NULL; }
    listen(sock, 20); LOG("IPC 服务已启动");

    while (!g_should_exit) {
        int client = accept(sock, NULL, NULL); 
        if (client < 0) { usleep(100000); continue; }
        char buf[512] = {0}; ssize_t n = read(client, buf, sizeof(buf) - 1);
        if (n <= 0) { close(client); continue; }
        
        char pkg[256]; int pid = 0, uid = 0;
        if (sscanf(buf, "REPORT %255s %d %d", pkg, &pid, &uid) == 3 || sscanf(buf, "REQ %255s %d %d", pkg, &pid, &uid) == 3) {
            if (!g_passive_mode) {
                g_passive_mode = 1;
                LOG("已接收到IPC通知，切换到被动模式，停止周期扫描");
            }
            if (is_isolated_uid(uid) || strstr(pkg, "_zygote") != NULL || strchr(pkg, ':') != NULL) { send(client, "OK", 2, MSG_NOSIGNAL); close(client); continue; }
            char clean_pkg[256]; strncpy(clean_pkg, pkg, sizeof(clean_pkg) - 1); char* colon = strchr(clean_pkg, ':'); if (colon) *colon = '\0';
            if (uid >= 10000) update_uid_map(uid, clean_pkg);
            struct IpcTask* task = (struct IpcTask*)malloc(sizeof(struct IpcTask));
            if (task) {
                strncpy(task->pkg, pkg, sizeof(task->pkg) - 1); task->pid = pid; task->uid = uid; task->client_fd = client; 
                pthread_t tid; if (pthread_create(&tid, NULL, handle_ipc_task, task) == 0) { pthread_detach(tid); continue; }
                else { send(client, "OK", 2, MSG_NOSIGNAL); close(client); free(task); }
            } else { send(client, "OK", 2, MSG_NOSIGNAL); close(client); }
            continue; 
        }
        if (strncmp(buf, "LIST_INJECTED", 13) == 0) {
            struct ListInjectedTask* task = malloc(sizeof(struct ListInjectedTask));
            if (task) { task->client_fd = client; pthread_t tid; if (pthread_create(&tid, NULL, handle_list_injected_thread, task) == 0) { pthread_detach(tid); continue; } free(task); }
            close(client); continue;
        }
        if (strncmp(buf, "FUSE_ALIVE", 10) == 0 || strncmp(buf, "FUSE_EXIT", 9) == 0) { close(client); continue; }
        close(client);
    }
    close(sock); return NULL;
}