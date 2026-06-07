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
#include <errno.h>
#include <stddef.h>
#include <fcntl.h>

int ipc_server_init() {
    int sock = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0); 
    if (sock < 0) return -1;

    struct sockaddr_un addr = { .sun_family = AF_UNIX }; 
    addr.sun_path[0] = '\0';
    strncpy(addr.sun_path + 1, IPC_SOCKET_NAME, sizeof(addr.sun_path) - 2);
    socklen_t addr_len = offsetof(struct sockaddr_un, sun_path) + 1 + strlen(IPC_SOCKET_NAME);

    if (bind(sock, (struct sockaddr*)&addr, addr_len) < 0) { 
        close(sock); 
        return -1; 
    }

    if (listen(sock, 20) < 0) {
        close(sock);
        return -1;
    }

    LOG_DBG("IPC 服务已启动");
    return sock;
}

void ipc_server_cleanup(int sock_fd) {
    if (sock_fd >= 0) {
        close(sock_fd);
    }
}

void handle_ipc_client_readable(int client_fd) {
    // 设置严格的 500ms 读写超时，防止异常客户端引发挂起
    struct timeval tv = { .tv_sec = 0, .tv_usec = 500000 };
    setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    char buf[512] = {0}; 
    ssize_t n = read(client_fd, buf, sizeof(buf) - 1);
    if (n <= 0) { 
        close(client_fd); 
        return; 
    }
    
    char pkg[256]; 
    int pid = 0, uid = 0;
    if (sscanf(buf, "REPORT %255s %d %d", pkg, &pid, &uid) == 3 || sscanf(buf, "REQ %255s %d %d", pkg, &pid, &uid) == 3) {
        if (!g_passive_mode) {
            g_passive_mode = true;
            LOG("已接收到IPC通知，切换到被动模式，停止周期扫描");
        }
        if (is_isolated_uid(uid) || strstr(pkg, "_zygote") != nullptr) { 
            send(client_fd, "OK", 2, MSG_NOSIGNAL); 
            close(client_fd); 
            return; 
        }
        
        char clean_pkg[256]; 
        strncpy(clean_pkg, pkg, sizeof(clean_pkg) - 1); 
        clean_pkg[sizeof(clean_pkg) - 1] = '\0';
        char* colon = strchr(clean_pkg, ':'); 
        if (colon) *colon = '\0';

        if (uid >= 10000) update_uid_map(uid, clean_pkg);

        send(client_fd, "OK", 2, MSG_NOSIGNAL);
        close(client_fd); // 快速释放客户端连接

        bool match = is_target_app(pkg, uid, pid, true);
        if (!match) return;
        if (kill(pid, 0) != 0) return;
        if (access("/storage/emulated/", F_OK) != 0) return;

        const char* mnt_src = get_active_mnt_src();
        if (!mnt_src) { 
            LOG_ERR("IPC: 全局 FUSE 不可用，无法为 %s 挂载", pkg); 
            return; 
        }

        // 同步进行应用命名空间挂载（非阻塞系统级操作）
        perform_app_mount(pkg, pid, uid, mnt_src, "IPC通知");
        return; 
    }

    if (strncmp(buf, "LIST_INJECTED", 13) == 0) {
        handle_list_injected(client_fd);
        close(client_fd);
        return;
    }

    if (strncmp(buf, "FUSE_ALIVE", 10) == 0 || strncmp(buf, "FUSE_EXIT", 9) == 0) { 
        close(client_fd); 
        return; 
    }

    close(client_fd);
}