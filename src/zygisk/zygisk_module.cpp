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
#include <stdlib.h>
#include <time.h>

#include "zygisk.hpp"

#define LOG_TAG   "Zygisk_NSProxy"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

/* 必须与 include/common.h 的 IPC_SOCKET_NAME 同值（抽象命名空间地址）。
   本模块不可 include common.h——它代含 nsp_comm.h 等十余个头，会把项目
   运行时拖进 zygote 子进程。 */
#define IPC_SOCKET_NAME "nsp_ipc_socket"

/* 协议版本：3 = pre 只裁决、post **不再回连**的补挂载。
   injector 只在收到 >=2 的 proto 时才允许延迟应答；旧模块（不带 proto）走
   原有的"就地挂载 + 异步重试"路径，故新 injector 与旧模块组合零回归。
   2 → 3 的差别：v2 靠"保留 pre 建立的 companion 连接、post 再发 POST"，
   而 ZygiskNext 1.3.4+ 会把 preAppSpecialize 返回后仍持有的 companion fd 直接
   关闭（Companion API 使用不当），post 再写就是写已关闭的 fd。v3 改为 pre 拿完
   判决即关闭连接，post 在本地等待自己的命名空间出现代理视图（injector 收到
   pre 通知后就在后台盯着这个进程的 ns，一变即挂）。 */
#define NSP_ZYGISK_PROTO 3

/* 各段等待上限（都必须有界，任何一段超时都按"放行应用"处理，绝不挂死）。
   唯一硬约束：**injector 没有应答（未启动/崩溃/忙）时，本模块不得产生任何等待**。
   pre 拿不到明确的 DEFER 就直接放行；只有 injector 明确回 DEFER 才在 post 做一次
   很短的本地等待（上限 100ms、10ms 步进）。

   启动高峰期 zygote 会连续 specialize 几十个进程（冷启动实测 60 个，含 SystemUI
   与 launcher），而 injector 要到 boot_completed 之后才由 service.sh 拉起：这段
   窗口里每个进程都拿不到应答。若按"没应答就等满上界"处理，每个进程都要空转
   1.5s 解析 mountinfo，开机会被拖慢几十秒，锁屏/桌面也跟着晚出来。 */
#define COMPANION_REQ_TIMEOUT_MS  150
#define COMPANION_POST_TIMEOUT_MS 1500
#define MODULE_REQ_TIMEOUT_MS     200
/* post-specialize 本地等待"自己的命名空间出现代理视图"的上限。injector 的盯梢线程
   在 ns 切换后立即挂载（实测 0–9ms），这里等 100ms 只覆盖慢设备上的装配窗口；
   等不到就放行（应用继续用原生视图），由 injector 的后台重试队列补挂。 */
#define MODULE_PROXY_WAIT_MS      100

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

/* 本进程的 /storage/emulated 是否已经是项目代理视图：mountinfo 里该挂载点的
   fstype 是 injector 挂载时指定的 subtype（fuse.fuse_daemon）。v1 逐应用挂载
   完成后才会出现；v3 全局替换下开机即有。读失败按"未就绪"处理（fail-open：
   调用方只会在超时后放行，不会因此拒绝启动应用）。 */
static bool storage_is_proxied(void) {
    FILE* fp = fopen("/proc/self/mountinfo", "re");
    if (fp == nullptr) return false;
    char* line = nullptr;
    size_t cap = 0;
    bool found = false;
    while (getline(&line, &cap, fp) > 0) {
        if (strstr(line, " /storage/emulated ") != nullptr &&
            strstr(line, "fuse.fuse_daemon") != nullptr) {
            found = true;
            break;
        }
    }
    free(line);
    fclose(fp);
    return found;
}

/* 有界等待代理视图就绪（10ms 步进）。返回已等待的毫秒数；0 = 立即可用。
   步长不宜再小：每次探测都要整表解析 mountinfo，2ms 步进在上限 1.5s 时等于每个
   进程做 750 次全表解析，启动高峰会把 CPU 和 mountinfo 读锁一起打满。10ms 步进
   在上限 100ms 内只做 10 次，足够覆盖"挂载在 0–9ms 内完成"的常态。 */
static long wait_storage_proxied(int timeout_ms) {
    long waited = 0;
    while (!storage_is_proxied()) {
        if (waited >= timeout_ms) break;
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 10 * 1000 * 1000};
        nanosleep(&ts, nullptr);
        waited += 10;
    }
    return waited;
}

/* 是否上报该进程给 injector。
 *
 * **不在模块侧硬编码"只处理 uid >= 10000"**：那是 injector 的配置语义
 * （[GLOBAL] SKIP_SYSTEM_APPS，默认 ON），硬编码会让用户显式写
 * SKIP_SYSTEM_APPS OFF 也永远不生效——系统应用（如 uid 1000 的 Settings）
 * 连上报机会都没有：v1 无法注入、v2 也没机会被还原（会一直停在项目视图上，
 * 真机实测确认过）。
 *
 * 这里只保留两种"必然无意义"的过滤，其余全部上报、由 injector 按配置裁决：
 *   - uid 0：init/kernel 线程 fork 出来的，不是应用进程；
 *   - isolated 区（app_id 90000–99999，与 injector 的 is_isolated_uid 对齐）：
 *     injector 必丢弃，提前过滤只是为了省一次 IPC 往返。 */
static bool should_report(uint32_t uid) {
    uint32_t app_id = uid % 100000;
    if (uid == 0) return false;
    return app_id < 90000;
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
        /* MSG_NOSIGNAL：应用侧读完应答就关连接（v3 起 pre 阶段必定关闭），此刻
           写回会命中 EPIPE——默认 SIGPIPE 会把 companion 线程连带进程打死。 */
        send(client_fd, reply, strlen(reply), MSG_NOSIGNAL);
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
        if (!should_report(args->uid)) {
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
        answered_ = false;
        reply_ok_ = false;

        int fd = api->connectCompanion();
        if (fd >= 0) {
            char req_buf[512];
            int req_len = snprintf(req_buf, sizeof(req_buf), "REQ %s %d %u %d", final_name,
                                   getpid(), args->uid, NSP_ZYGISK_PROTO);
            if (write(fd, req_buf, req_len) > 0) {
                /* 等 injector 的判决（上限 200ms）：OK = 无需挂载，可直接继续；
                   DEFER = 目标应用，injector 已在后台盯着本 pid 的命名空间，本进程
                   到 post 再等自己的视图出现。pre 通道只裁决不挂载——此刻还在
                   zygote 的挂载 ns 里，挂上去会被之后 fork 的每个应用继承。 */
                char reply[16] = {0};
                struct pollfd pfd = {.fd = fd, .events = POLLIN, .revents = 0};
                if (poll(&pfd, 1, MODULE_REQ_TIMEOUT_MS) > 0) {
                    ssize_t rn = read(fd, reply, sizeof(reply) - 1);
                    if (rn > 0) {
                        reply[rn] = '\0';
                        answered_ = true;
                    }
                }
                /* 只有明确的 DEFER 才需要在 post 再等一次。没应答（injector 还没启动
                   / 崩溃 / 忙）或收到 ERR 时一律直接放行：等待在这种情形下毫无意义，
                   而启动高峰期每个进程多等上界就会把开机拖成"卡死"。
                   注意不能反过来"没应答算 pending"——这正是上一版的缺陷。 */
                pending_ = (answered_ && strcmp(reply, "DEFER") == 0);
                reply_ok_ = (answered_ && strcmp(reply, "OK") == 0);
            }
            /* 连接只在本回调内使用，返回前必须关闭（见 NSP_ZYGISK_PROTO 注释：
               ZygiskNext 1.3.4+ 会关掉 preAppSpecialize 返回后仍持有的 companion
               fd，留着它就是"Companion API 使用不当"，且 post 再写必失败）。 */
            close(fd);
        }

        if (nice_name) {
            env->ReleaseStringUTFChars(args->nice_name, nice_name);
        }
        if (pending_) {
            LOGI("App [%s] (UID:%u) 上报完成：injector 已受理（DEFER），post-specialize 补挂载",
                 final_name, args->uid);
        } else if (!answered_) {
            LOGI("App [%s] (UID:%u) 上报完成：未收到 injector 判决，直接放行", final_name,
                 args->uid);
        } else if (reply_ok_) {
            LOGI("App [%s] (UID:%u) 上报完成：无需补挂载（OK）", final_name, args->uid);
        } else {
            LOGI("App [%s] (UID:%u) 上报完成：injector 未受理（ERR），直接放行", final_name,
                 args->uid);
        }
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs*) override {
        /* v1 补挂载：pre-specialize 时 injector 回 DEFER 的进程在这里等自己的
           /storage/emulated 变成项目 FUSE（injector 侧在 ns 切换的瞬间挂载）。
           本回调仍早于应用 Java 代码（Application.onCreate）执行，因此应用的
           首次写入就能看到代理视图。只在 pending_ 时等待：未命中配置的应用、
           v2/v3（全局替换）与 injector 不在线的情况都不会多一次等待。 */
        if (pending_) {
            pending_ = false;
            /* 本进程已在自己的挂载命名空间里：injector 在收到 pre 通知后就盯着这个
               pid 的 ns，切换完成的第一时间挂载。这里只等"自己的视图就绪"这个
               本地事实（不访问任何 fd/IPC），等到即继续，等不到由 injector 的后台
               重试队列补挂——绝不把应用卡死在 specialize 上。 */
            long waited = wait_storage_proxied(MODULE_PROXY_WAIT_MS);
            if (storage_is_proxied()) {
                LOGI("App [%s] (PID:%d) 补挂载完成: 代理视图在 %ldms 内就绪", pkg_, getpid(),
                     waited);
            } else {
                LOGI("App [%s] (PID:%d) 补挂载未就绪: %dms 内未见代理视图，已放行（后台重试补挂）",
                     pkg_, getpid(), MODULE_PROXY_WAIT_MS);
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
    /* pre 是否真的收到 injector 的应答（区分"ERR/超时放行"与"明确 OK"） */
    bool answered_ = false;
    bool reply_ok_ = false;
};

REGISTER_ZYGISK_MODULE(AppReporterModule)
REGISTER_ZYGISK_COMPANION(companion_handler)
