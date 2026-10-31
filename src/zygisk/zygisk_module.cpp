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

#define LOG_TAG   "Zygisk_NSProxy"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

/* 必须与 include/common.h 的 IPC_SOCKET_NAME 同值（抽象命名空间地址）。
   本模块不可 include common.h——它代含 nsp_comm.h 等十余个头，会把项目
   运行时拖进 zygote 子进程。 */
#define IPC_SOCKET_NAME "nsp_ipc_socket"

/* 协议版本：2 = 支持"pre 回 DEFER、post 发 POST"的两段式补挂载。
   injector 只在收到 >=2 的 proto 时才允许延迟应答；旧模块（不带 proto）走
   原有的"就地挂载 + 异步重试"路径，故新 injector 与旧模块组合零回归。 */
#define NSP_ZYGISK_PROTO 2

/* 各段等待上限（都必须有界，任何一段超时都按"放行应用"处理，绝不挂死）。
   companion 侧等 injector：REQ 只需一次快速尝试，POST 可能要等 vold 把
   /storage/emulated 装配进应用命名空间（~1s），故给足余量。 */
/* 逐段放宽，保证"内层先裁决、外层后超时"的严格顺序——否则外层先超时会把
   injector 正在做的挂载晾在半空（应用已放行、视图稍后才到，等于没修）：
     injector POST 预算 250ms + 子进程余量 800ms ≈ 1.05s
     < companion POST 1.5s < module POST 2s
     pre 通道 injector 只裁决、**不挂载**（立即回 DEFER），实际往返 < 10ms
     < companion REQ 0.8s < module REQ 1.2s
   原则：应用主线程上的等待必须小于"能感知"的量级。旧值（pre 3.5s / post 8s、
   injector 内部 POST 再等 1800ms）在视图迟迟不出现的设备上意味着每次冷启动
   固定多等 1.8s，正是"冷启动明显变慢"的来源；现在长等待与重试全部落在
   injector 的后台通道里，这里只做短等 + fail-open。 */
#define COMPANION_REQ_TIMEOUT_MS  800
#define COMPANION_POST_TIMEOUT_MS 1500
#define MODULE_REQ_TIMEOUT_MS     1200
#define MODULE_POST_TIMEOUT_MS    2000

/* 抽象命名空间 UDS 地址填充。等价于项目的 nsp_uds_abstract_addr()
   （src/core/nsp_util.c），含同一处修正：地址长度按**截断后**实际写入的
   内容计算，而非 strlen(name)——名称超长时后者会让长度越过 sun_path 的
   真实内容，造成内核侧越界读。 */
static socklen_t uds_abstract_addr(struct sockaddr_un* addr, const char* name) {
    memset(addr, 0, sizeof(*addr));
    addr->sun_family = AF_UNIX;
    addr->sun_path[0] = '\0';
    strncpy(addr->sun_path + 1, name, sizeof(addr->sun_path) - 2);
    addr->sun_path[sizeof(addr->sun_path) - 1] = '\0';
    return (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + strlen(addr->sun_path + 1));
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

/* 从 injector 读应答动词（OK/ERR/DEFER），超时或无应答一律回落 "ERR"。
   应答是短字符串且不带换行，读到即返回。 */
static void companion_wait_reply(int fd, int timeout_ms, char* out, size_t outsz) {
    snprintf(out, outsz, "ERR");
    struct pollfd pfd = {.fd = fd, .events = POLLIN, .revents = 0};
    if (poll(&pfd, 1, timeout_ms) <= 0) return;
    char buf[16] = {0};
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    if (n <= 0) return;
    buf[n] = '\0';
    if (strcmp(buf, "OK") == 0 || strcmp(buf, "DEFER") == 0) {
        snprintf(out, outsz, "%s", buf);
    }
}

/* 单条连接上最多处理两个请求（pre 的 REQ → post 的 POST）：应用在
   post-specialize 已经处于应用沙箱域，**无法**再 connect 到 zygiskd
   （connectCompanion 会失败），故必须复用 pre-specialize 建立的那条连接。
   读超时保证"收到 DEFER 却不来 POST"的连接最终被回收。 */
/* DEFER 后 post-specialize 一定紧跟（同一进程内连续两个回调），5s 足够覆盖
   极端调度延迟；更长的空闲只意味着应用没走到 post，白占一个 companion 线程。 */
#define COMPANION_IDLE_TIMEOUT_S 5

static void companion_handler(int client_fd) {
    struct timeval rtv = {.tv_sec = COMPANION_IDLE_TIMEOUT_S, .tv_usec = 0};
    setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &rtv, sizeof(rtv));

    char buf[1024];
    for (;;) {
        ssize_t len = read(client_fd, buf, sizeof(buf) - 1);
        if (len <= 0) {
            close(client_fd);
            return;
        }
        buf[len] = '\0';

        /* 应用侧两个动词：
           - REQ ：pre-specialize 上报，injector 决定"就地挂载（OK）"还是
                   "视图未就绪、等 post 再来（DEFER）"；
           - POST：post-specialize 补挂载，injector 会阻塞到视图就绪再挂，
                   然后回 OK/ERR。
           两者都原样转发（REQ→REPORT、POST→POST），并把 injector 的应答原样
           回给应用——应答即"应用能否继续往下跑"的唯一信号。 */
        char verb[8] = {0}, pkg_name[256] = {0}, proto[32] = {0};
        int pid = 0, uid = 0;
        int nf = sscanf(buf, "%7s %255s %d %d %31s", verb, pkg_name, &pid, &uid, proto);
        if (nf < 4) {
            close(client_fd);
            return;
        }
        bool is_post = (strcmp(verb, "POST") == 0);
        const char* fwd_verb = is_post ? "POST" : "REPORT";
        int timeout_ms = is_post ? COMPANION_POST_TIMEOUT_MS : COMPANION_REQ_TIMEOUT_MS;

        /* 转发给 injector。app 进程自身无权连接 injector 的 socket，故经本
           companion（root）中转。 */
        char reply[16];
        snprintf(reply, sizeof reply, "ERR");
        int inj_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (inj_fd >= 0) {
            struct sockaddr_un addr;
            socklen_t addr_len = uds_abstract_addr(&addr, IPC_SOCKET_NAME);

            struct timeval tv = {.tv_sec = timeout_ms / 1000 + 1, .tv_usec = 0};
            setsockopt(inj_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            setsockopt(inj_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

            if (connect(inj_fd, (struct sockaddr*)&addr, addr_len) == 0) {
                char report_msg[512];
                int msg_len = (nf >= 5) ? snprintf(report_msg, sizeof(report_msg), "%s %s %d %d %s",
                                                   fwd_verb, pkg_name, pid, uid, proto)
                                        : snprintf(report_msg, sizeof(report_msg), "%s %s %d %d",
                                                   fwd_verb, pkg_name, pid, uid);
                if (write(inj_fd, report_msg, msg_len) > 0) {
                    /* 等 injector 的应答：REQ 等它决定 OK/DEFER；POST 等它把
                       挂载做完。读失败不改变结果（上报已发出），按 ERR 放行。 */
                    companion_wait_reply(inj_fd, timeout_ms, reply, sizeof reply);
                }
            }
            close(inj_fd);
        }

        LOGD("Companion: %s %s (PID:%d, UID:%d) → %s", verb, pkg_name, pid, uid, reply);
        write(client_fd, reply, strlen(reply));
        /* 只有 DEFER 才继续留在连接上等 POST；OK/ERR 即本条连接使命结束 */
        if (strcmp(reply, "DEFER") != 0) break;
    } /* for (;;) */
    close(client_fd);
}

/* ============================ Zygisk 模块（应用进程） ============================ */

class AppReporterModule : public zygisk::ModuleBase {
  public:
    void onLoad(zygisk::Api* api, JNIEnv* env) override {
        this->api = api;
        this->env = env;
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs* args) override {
        if (!is_user_app(args->uid)) {
            return;
        }

        const char* nice_name = nullptr;
        if (args->nice_name != nullptr) {
            nice_name = env->GetStringUTFChars(args->nice_name, nullptr);
        }
        const char* final_name = nice_name ? nice_name : "unknown";

        snprintf(pkg_, sizeof pkg_, "%s", final_name);
        uid_ = args->uid;
        pending_ = false;

        companion_fd_ = api->connectCompanion();
        int fd = companion_fd_;
        if (fd >= 0) {
            char req_buf[512];
            int req_len = snprintf(req_buf, sizeof(req_buf), "REQ %s %d %u %d", final_name,
                                   getpid(), args->uid, NSP_ZYGISK_PROTO);
            if (write(fd, req_buf, req_len) > 0) {
                /* 等 injector 的判决（上限 1.2s）：OK = 无需挂载，可直接继续；
                   DEFER = 目标应用，交 post-specialize 补挂载。injector 的 pre
                   通道只裁决不挂载（此阶段还在 zygote 的挂载 ns 里，不能挂）。 */
                char reply[16] = {0};
                bool answered = false;
                struct pollfd pfd = {.fd = fd, .events = POLLIN, .revents = 0};
                if (poll(&pfd, 1, MODULE_REQ_TIMEOUT_MS) > 0) {
                    ssize_t rn = read(fd, reply, sizeof(reply) - 1);
                    if (rn > 0) {
                        reply[rn] = '\0';
                        answered = true;
                    }
                }
                /* 只有拿到明确的 "OK" 才算"无需补挂载"。没应答（injector 忙/连接
                   异常）或收到 ERR 时必须把连接留着在 post 再试一次：injector 的
                   pre 通道只裁决不挂载，缺了这次 POST 应用整个生命周期都没有代理
                   视图（旧实现"超时按 OK"会静默吞掉 DEFER，真机表现就是"存储
                   没被代理/是空的"）。 */
                pending_ = !(answered && strcmp(reply, "OK") == 0);
            }
            /* DEFER 时**保留**连接：post-specialize 已处于应用沙箱域，无法再
               connectCompanion，只能复用这条 pre-specialize 建立的连接。 */
            if (!pending_) {
                close(fd);
                companion_fd_ = -1;
            }
        }

        if (nice_name) {
            env->ReleaseStringUTFChars(args->nice_name, nice_name);
        }
        LOGI("App [%s] (UID:%u) 上报完成%s", final_name, args->uid,
             pending_ ? "：视图未就绪，post-specialize 补挂载" : "");
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs*) override {
        /* v1 补挂载：pre-specialize 时 injector 回 DEFER 的进程在这里阻塞等待，
           直到 injector 在**应用命名空间内**把 /storage/emulated 换成项目 FUSE。
           本回调仍早于应用 Java 代码（Application.onCreate）执行，因此应用的
           首次写入就能看到代理视图——这正是把"异步重试队列"搬到 zygisk 的目的。
           只在 pending_ 时发起 IPC：未命中配置的应用、v2/v3（全局替换）以及
           injector 不在线的情况都不会多一次往返，也不会被阻塞。 */
        if (pending_) {
            pending_ = false;
            int fd = companion_fd_;
            companion_fd_ = -1;
            if (fd >= 0) {
                char req_buf[512];
                int req_len = snprintf(req_buf, sizeof(req_buf), "POST %s %d %u %d", pkg_, getpid(),
                                       uid_, NSP_ZYGISK_PROTO);
                if (write(fd, req_buf, req_len) > 0) {
                    char reply[16] = {0};
                    struct pollfd pfd = {.fd = fd, .events = POLLIN, .revents = 0};
                    if (poll(&pfd, 1, MODULE_POST_TIMEOUT_MS) > 0) {
                        ssize_t rn = read(fd, reply, sizeof(reply) - 1);
                        if (rn > 0) reply[rn] = '\0';
                    }
                    LOGI("App [%s] (PID:%d) 补挂载结果: %s", pkg_, getpid(),
                         reply[0] ? reply : "无应答");
                }
                close(fd);
            } else {
                LOGI("App [%s] 补挂载失败: 无可用 companion 连接", pkg_);
            }
        }
        /* 上报已完成，卸载自身以保持应用进程纯净 */
        api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
    }

  private:
    zygisk::Api* api = nullptr;
    JNIEnv* env = nullptr;
    /* 跨 pre/post 的进程级状态：pkg/uid 用于 POST 报文，pending_ 标记"pre 收到
       DEFER、需要 post 补挂载"。 */
    char pkg_[256] = {0};
    uint32_t uid_ = 0;
    bool pending_ = false;
    /* pre-specialize 建立、在 DEFER 时保留到 post-specialize 的 companion 连接。
       post 阶段已降权进应用沙箱域，无法再 connect 到 zygiskd，只能复用。 */
    int companion_fd_ = -1;
};

REGISTER_ZYGISK_MODULE(AppReporterModule)
REGISTER_ZYGISK_COMPANION(companion_handler)
