#ifndef NSP_COMM_H
#define NSP_COMM_H
/* nsp_comm —— 全进程统一的发后即忘通讯线程（epoll 驱动）
 *
 * 归属约束：调用线程（FUSE worker / 主循环）只做一件事——
 *   nsp_comm_post(ch, data, len)
 * 该函数永不阻塞：堆上拷贝载荷 → 无锁/短临界区入队 → 仅空转非空时写一次
 * eventfd。连接管理、非阻塞重连、指数退避、输出队列、背压丢弃全部收在
 * comm 线程内部（epoll: eventfd + timerfd）。
 *
 * 通道（NSP_CH__N 个，drain 优先级 IPC > LOG > BCAST；ALIVE/EXIT 生命线优先）：
 *   LOG   —— 日志行（载荷由 common.c 组帧，见 nsp_log_emit 契约）
 *   IPC   —— 发后即忘 IPC 短消息（FUSE_ALIVE/EXIT 等）
 *   BCAST —— 广播扇出（injector 配置 / log_monitor 实时推送的字节 + 控制消息）
 *
 * 背压语义：满环覆盖最旧 + dropped 计数（drain 结束时经 report 回调上报一次，
 * 各后端自行决定上报通道；计数经 nsp_comm_dropped 随时可查）。
 * 顺序语义：单生产者保序，多生产者允许乱序（单调递增即可，不做全局 FIFO）。
 *
 * fork 说明：fork 子进程内 comm 线程不可达（同 log sender 旧约束），子进程
 * 沿用 g_log_forward_fd 管道回传，父进程侧再 post（见 common.c）。
 */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
    NSP_CH_LOG = 0,
    NSP_CH_IPC = 1,
    NSP_CH_BCAST = 2,
    NSP_CH__N
} nsp_ch_t;

/* 后端（实现运行于 comm 线程；register 可在 init 前后调用） */
typedef struct {
    void *ctx;
    /* 建链：true=可发送。阻塞式 connect（含短超时）亦可，跑在 comm 线程不影响生产者 */
    bool (*ensure_link)(void *ctx);
    /* 发送单条：0=成功，<0=链路断开（core 标记 down + 退避，本批剩余计 dropped） */
    int (*emit)(void *ctx, const void *data, size_t len);
    /* fini 时调用，可 NULL */
    void (*fini)(void *ctx);
    /* 本 drain 轮有覆盖丢弃时调用一次（ch, 本轮丢弃数），可 NULL */
    void (*report)(nsp_ch_t ch, uint64_t n, void *ctx);
} nsp_comm_backend_t;

int nsp_comm_init(void);   /* 幂等：拉起线程 + epoll(eventfd+timerfd) */
int nsp_comm_register(nsp_ch_t ch, const nsp_comm_backend_t *be);
/* 永不阻塞。fini 开始后调用只计 dropped、不写 fd（fini 后 post 安全） */
void nsp_comm_post(nsp_ch_t ch, const void *data, size_t len);
void nsp_comm_fini(void);  /* 停接收 + 全量 drain + join，幂等 */
uint64_t nsp_comm_dropped(nsp_ch_t ch);

#endif
