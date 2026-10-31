#ifndef IPC_SERVER_H
#define IPC_SERVER_H

/**
 * 初始化单线程非阻塞 IPC 监听 Socket
 * 成功返回 Socket FD，失败返回 -1
 */
int ipc_server_init();

/**
 * 清理 IPC 监听资源
 */
void ipc_server_cleanup(int sock_fd);

/**
 * 同步、非阻塞地处理客户端连接上的数据请求
 */
void handle_ipc_client_readable(int client_fd);

/* v1 挂载的就绪等待预算（POST 与旧模块就地挂载共用）。
 *
 * 为什么是 250ms 而不是 1800ms：这段等待发生在**应用主线程**里（zygisk 的
 * postAppSpecialize 阻塞等 ACK），1800ms 会让"视图迟迟不出现"的设备每次冷启动
 * 固定多等 1.8s，然后失败、再排重试——真机上被报成"冷启动明显变慢"。实测健康
 * 设备在 post 阶段视图已经就绪（挂载只要 1~3ms），250ms 足够覆盖抖动；等不到
 * 就立即 fail-open（应用先用原生视图跑起来），由后台重试队列补挂（静默、有界）。
 *
 * zygisk 侧的等待上限比它更长，保证"injector 先裁决、模块后超时"的顺序。 */
#define IPC_MOUNT_READINESS_MS 250

/* v1 挂载通道（纯函数决策，便于直编单测）：
 *   IPC_CHAN_DEFER  = pre-specialize 的 REPORT 预探测（proto>=2）：**只裁决不挂载**，
 *       立即回 DEFER。此刻应用还在 zygote 的挂载命名空间里——部分 ROM 该 ns 里
 *       就有 /storage/emulated，在这里挂载等于把项目 FUSE 装进 zygote ns，之后
 *       fork 的每个应用（含非目标）都会继承它，且 cleanup 只会在应用自己的 ns
 *       里卸载，这份挂载没人能清。应用自己的 ns 要到 post-specialize 才成立。
 *   IPC_CHAN_POST   = post-specialize 的 POST：唯一的挂载时机，预算
 *       IPC_MOUNT_READINESS_MS，失败排重试。
 *   IPC_CHAN_LEGACY = 旧模块（无 proto）的 REPORT 与应用直连的 REQ：就地挂载，
 *       同预算（旧值 1000ms，冷启动可感知），失败仍排重试，语义不变。 */
typedef enum {
    IPC_CHAN_DEFER = 0,
    IPC_CHAN_POST = 1,
    IPC_CHAN_LEGACY = 2,
} IpcChannel;

IpcChannel ipc_plan_channel(bool is_post, bool is_report, int proto);
/* 该通道的就绪预算（ms，正值）。IPC_CHAN_DEFER 不挂载，返回 0 */
int ipc_channel_readiness(IpcChannel ch);

/* v2 非目标应用还原的时序决策（纯函数，便于直编单测）。
 *
 * 关键事实：pre-specialize 时应用命名空间里**还没有**项目视图——还原只会命中
 * "顶层非项目 FUSE → 跳过"，靠 10ms 步进轮询去猜时间（旧实现）既慢又不可靠。
 * 应用自己的 ns 由 vold 在 specialize 期间装配，模块在 post-specialize（仍早于
 * 应用 Java 代码）掌握这个时刻：因此新协议下 pre 阶段**不还原、不轮询**，直接回
 * DEFER 让模块在 post 再通知一次，injector 收到 POST 立刻异步还原并立即 ACK。
 *
 *   IPC_RESTORE_ON_POST = pre 阶段（REPORT+proto>=2）：回 DEFER，等 post 通知
 *   IPC_RESTORE_NOW     = post 阶段：立刻派发还原，ACK 不等它（不阻塞）
 *   IPC_RESTORE_INLINE  = 旧模块（无 proto）/ REQ：没有 post 通知可用，只能就地
 *                         派发 + 有界快等（IPC_RESTORE_INLINE_MS）
 */
typedef enum {
    IPC_RESTORE_ON_POST = 0,
    IPC_RESTORE_NOW = 1,
    IPC_RESTORE_INLINE = 2,
} IpcRestorePlan;

IpcRestorePlan ipc_plan_restore(bool is_post, bool is_report, int proto);

#endif