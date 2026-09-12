/* SPDX-License-Identifier: GPL-3.0-or-later */
/* 版权所有 (C) 2026 huniangitb <3361107168@qq.com> */
/*
 * zygisk_module.cpp — 新应用创建通知（Zygisk 模块）
 *
 * injector 发现新应用有两条途径：周期扫描 /proc 找 zygote 子进程（主动模式），
 * 以及本模块的 IPC 通知（被动模式）。injector 收到首次通知即置 g_passive_mode
 * 并永久停止周期扫描（src/injector/injector.c 的 maybe_periodic_scan），此后
 * 新应用的发现完全依赖本模块。
 *
 * 链路：
 *   app 进程  preAppSpecialize → connectCompanion → "REQ <pkg> <pid> <uid>"
 *   companion（root）           → nsp_ipc_socket  → "REPORT <pkg> <pid> <uid>"
 *   injector  ipc_server.c 解析后挂载/还原
 *
 * 因被动模式会关掉轮询，本模块必须 64/32 位双 ABI 部署：只装 64 位时，任何
 * 一个 64 位应用触发被动模式后，跑在 32 位 zygote 上的应用既收不到通知也等
 * 不到扫描，将彻底漏注入。构建见 meson.build 的 zygisk 段。
 *
 * 本文件运行在 zygote fork 出的应用进程内，必须零项目依赖（不链接 nsp_util/
 * common，不引入 STL）——故下方 IPC 名称与 UDS 地址填充为本地实现，改动时须
 * 与项目侧保持同步，见各自注释。
 */
#include <android/log.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <sys/poll.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>

#include "zygisk.hpp"

#define LOG_TAG "Zygisk_NSProxy"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)

/* 必须与 include/common.h 的 IPC_SOCKET_NAME 同值（抽象命名空间地址）。
   本模块不可 include common.h——它代含 nsp_comm.h 等十余个头，会把项目
   运行时拖进 zygote 子进程。 */
#define IPC_SOCKET_NAME "nsp_ipc_socket"

/* 抽象命名空间 UDS 地址填充。等价于项目的 nsp_uds_abstract_addr()
   （src/core/nsp_util.c），含同一处修正：地址长度按**截断后**实际写入的
   内容计算，而非 strlen(name)——名称超长时后者会让长度越过 sun_path 的
   真实内容，造成内核侧越界读。 */
static socklen_t uds_abstract_addr(struct sockaddr_un *addr, const char *name) {
    memset(addr, 0, sizeof(*addr));
    addr->sun_family = AF_UNIX;
    addr->sun_path[0] = '\0';
    strncpy(addr->sun_path + 1, name, sizeof(addr->sun_path) - 2);
    addr->sun_path[sizeof(addr->sun_path) - 1] = '\0';
    return (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 +
                       strlen(addr->sun_path + 1));
}

/* 普通用户应用判定。上界 90000 与 injector 的 is_isolated_uid()
   （src/injector/inject_target.c，90000–99999 为 isolated）对齐：isolated
   进程上报后必被 injector 丢弃，在此提前过滤可省去一次 IPC 往返。
   下界 10000 对应 AID_APP_START，其下为系统应用。 */
static bool is_user_app(uint32_t uid) {
    uint32_t app_id = uid % 100000;
    return app_id >= 10000 && app_id < 90000;
}

/* ============================ Companion（root 权限） ============================ */

static void companion_handler(int client_fd) {
    char buf[1024];
    ssize_t len = read(client_fd, buf, sizeof(buf) - 1);
    if (len <= 0) {
        close(client_fd);
        return;
    }
    buf[len] = '\0';

    char pkg_name[256];
    int pid = 0, uid = 0;
    if (sscanf(buf, "REQ %255s %d %d", pkg_name, &pid, &uid) != 3) {
        close(client_fd);
        return;
    }

    /* 转发给 injector。app 进程自身无权连接 injector 的 socket，故经本
       companion（root）中转。 */
    int inj_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (inj_fd >= 0) {
        struct sockaddr_un addr;
        socklen_t addr_len = uds_abstract_addr(&addr, IPC_SOCKET_NAME);

        struct timeval tv = { .tv_sec = 1, .tv_usec = 500000 };
        setsockopt(inj_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(inj_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        if (connect(inj_fd, (struct sockaddr *)&addr, addr_len) == 0) {
            char report_msg[512];
            int msg_len = snprintf(report_msg, sizeof(report_msg),
                                   "REPORT %s %d %d", pkg_name, pid, uid);
            if (write(inj_fd, report_msg, msg_len) > 0) {
                /* 等 injector 的 ACK：确保其已受理再放行应用继续 specialize，
                   否则应用可能先于挂载完成访问存储。读失败不改变结果（上报
                   已发出），仅记日志。 */
                char ack[16];
                ssize_t ack_len = read(inj_fd, ack, sizeof(ack));
                if (ack_len > 0) {
                    LOGD("Companion: 已上报 %s (PID:%d, UID:%d)", pkg_name, pid, uid);
                } else {
                    LOGD("Companion: %s 上报后未收到 ACK", pkg_name);
                }
            }
        }
        close(inj_fd);
    }

    write(client_fd, "OK", 2);
    close(client_fd);
}

/* ============================ Zygisk 模块（应用进程） ============================ */

class AppReporterModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        if (!is_user_app(args->uid)) {
            return;
        }

        const char *nice_name = nullptr;
        if (args->nice_name != nullptr) {
            nice_name = env->GetStringUTFChars(args->nice_name, nullptr);
        }
        const char *final_name = nice_name ? nice_name : "unknown";

        int fd = api->connectCompanion();
        if (fd >= 0) {
            char req_buf[512];
            int req_len = snprintf(req_buf, sizeof(req_buf),
                                   "REQ %s %d %d", final_name, getpid(), args->uid);
            if (write(fd, req_buf, req_len) > 0) {
                /* 等 companion 完成中转（上限 1s）：specialize 阶段阻塞会拖慢
                   应用冷启动，故设上限而非无限等待。 */
                struct pollfd pfd = { .fd = fd, .events = POLLIN, .revents = 0 };
                poll(&pfd, 1, 1000);
                LOGI("App [%s] (UID:%u) 已上报", final_name, args->uid);
            }
            close(fd);
        }

        if (nice_name) {
            env->ReleaseStringUTFChars(args->nice_name, nice_name);
        }
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *) override {
        /* 上报已完成，卸载自身以保持应用进程纯净 */
        api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
    }

private:
    zygisk::Api *api = nullptr;
    JNIEnv *env = nullptr;
};

REGISTER_ZYGISK_MODULE(AppReporterModule)
REGISTER_ZYGISK_COMPANION(companion_handler)
