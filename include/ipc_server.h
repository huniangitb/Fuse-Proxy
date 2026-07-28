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

#endif