#ifndef NSP_FUSE_RECOVER_H
#define NSP_FUSE_RECOVER_H

/* FUSE 崩溃恢复的两段式：事件循环只发请求与收结果，「重启序列」在专属 worker 上跑。

   动机：注入器只有一条事件循环线程，周期性 tick 里内联的崩溃恢复会做一串秒级慢活——
   等旧 daemon 退出的 10ms×50 轮询、SIGKILL 后 50ms、ns_force_umount_stale 之后最多
   20×20ms 的卸载复核、fork+exec 新实例，以及 cleanup_all_target_apps() 对全进程表
   逐个核挂载。这段时间里 pre-hook 判定、挂载派发、IPC ACK 全部停住：一次慢恢复放大成
   整进程无响应，而 zygisk 侧 pre-hook 的 IPC 超时只有 100ms，超时即走 fail-open。

   语义（刻意保守）：
     - request 绝不阻塞调用线程，也不在调用线程上执行回调；
     - 至多一个 worker：重复请求合并成「再来一轮」，突发多次 tick 只跑 1~2 轮；
     - 完成结果通过 eventfd 交回调用线程，take() 只回答「这一轮确实跑完了」（事件循环
       用它记一条完成日志）；「重挂所有追踪应用」这类只有循环线程才写的记账由调用方在
       发请求时就置好，不依赖本次回报——新实例的就绪事件可能早于回报；
     - 起线程失败时 request() 返回 false，调用方按旧行为内联执行——宁可慢一次，
       也不能把一次崩溃恢复丢掉（否则追踪应用会一直停在 ENOTCONN 的旧挂载上）。 */

#include <stdbool.h>

typedef void (*NspFuseRecoverFn)(void* ctx);

/* 装配回调并创建就绪 eventfd（>=0 供 epoll 注册）。fn 为空或创建失败返回 -1，
   调用方退回内联恢复。可重复调用（幂等）；shutdown 之后可再次 start。 */
int nsp_fuse_recover_start(NspFuseRecoverFn fn, void* ctx);

/* 非阻塞请求一次重启。已排队或正在跑时只置「再来一轮」。
   返回 false 表示 worker 起不来（调用方应内联执行）；返回 true 表示已排队。 */
bool nsp_fuse_recover_request(void);

/* 取走一次完成通知（worker 跑完一轮时置位）。没有则返回 false。 */
bool nsp_fuse_recover_take(void);

/* 停线程并 join：会等手上那一轮跑完（最长一次恢复序列），不取消。
   只在进程退出的收尾阶段调用；可重复调用。 */
void nsp_fuse_recover_shutdown(void);

#endif /* NSP_FUSE_RECOVER_H */
