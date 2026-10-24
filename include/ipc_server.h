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

/* v1 就绪等待预算（post-specialize 的 POST 用）：覆盖 ColorOS 型 ROM 上 vold
   装配应用命名空间 ~1s 的延迟，留 0.8s 余量。zygisk 侧的等待上限比它更长，
   保证"injector 先裁决、模块后超时"的顺序。 */
#define IPC_POST_READINESS_MS 1800

/**
 * v1 挂载的就绪预算与失败语义决策（纯函数，便于直编单测）。
 *   - POST（post-specialize 补挂载）：预算 IPC_POST_READINESS_MS，失败才排重试；
 *   - REPORT + proto>=2（pre-specialize 快速尝试）：预算 0（只查一次），
 *     未就绪回 DEFER，由 zygisk 在 post-specialize 重发 POST；
 *   - 旧模块（无 proto）/ REQ（应用直连的历史通道）：预算 1000，维持原行为。
 * 返回 readiness_ms；*defer_on_fail 置位表示失败时应回 DEFER 而非 ERR。
 */
int ipc_plan_readiness(bool is_post, bool is_report, int proto, bool* defer_on_fail);

#endif