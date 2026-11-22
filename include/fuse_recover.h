/* FUSE 维护 worker：事件循环只发请求与收结果，所有「改挂载表 / 扫全进程」的慢活在
   同一条 worker 上串行跑。

   动机：注入器只有一条事件循环线程。它同时承载 zygisk pre-hook 判定、挂载派发与 IPC
   ACK（pre-hook 的 IPC 超时只有 100ms，超时即 fail-open），任何秒级慢活跑在上面都会
   放大成整进程无响应。已知的慢活有三段：
     - 崩溃恢复：等旧 daemon 退出的轮询 + SIGKILL 宽限 + 卸载复核 + fork/exec + 全进程清理；
     - 启动扫描：injector 重启后逐进程修存量断连挂载；
     - 重挂：FUSE 就绪后对全进程表逐个核规则并挂载。
   三者都会改挂载表、都会遍历全进程，所以**只能串行**：放两个线程反而让同一应用刚挂上
   又被清理（同时改 fast_pid 缓存与追踪表）。这里用一条 worker + 任务位表达「这一轮要跑
   哪几段」，顺序由回调固定。

   语义（刻意保守）：
     - request 绝不阻塞调用线程，也不在调用线程上执行回调；
     - 至多一个 worker：重复请求按位合并成「再来一轮」，突发多次 tick 只跑 1~2 轮；
       合并必须按位 OR——用赋值会把先到的任务覆盖掉（一次崩溃恢复就此丢失）；
     - 完成结果通过 eventfd 交回调用线程，take() 返回这一轮跑完的任务位（0 = 没跑完）；
       「重挂所有追踪应用」这类只有循环线程才写的记账由调用方在发请求时就置好，不依赖
       本次回报——新实例的就绪事件可能早于回报；
     - 起来线程失败时 request() 返回 false，调用方按旧行为内联执行——宁可慢一次，
       也不能把一次恢复或一次重挂丢掉。 */

#ifndef NSP_FUSE_RECOVER_H
#define NSP_FUSE_RECOVER_H

#include <stdbool.h>

/* 任务位。循环线程按当时的状态组合，worker 按固定顺序执行（恢复 → 启动扫描 → 重挂）。 */
#define NSP_FUSE_JOB_RECOVER (1u << 0)      /* 崩溃恢复：清残留 → 起新实例 */
#define NSP_FUSE_JOB_STARTUP_SCAN (1u << 1) /* 就绪后：修复存量断连挂载 */
#define NSP_FUSE_JOB_REMOUNT (1u << 2)      /* 就绪后：重挂全部追踪应用 */
#define NSP_FUSE_JOB_MEDIA (1u << 3)      /* 媒体实例：停旧 + 按当前配置决定是否重拉 */
#define NSP_FUSE_JOB_ALL \
    (NSP_FUSE_JOB_RECOVER | NSP_FUSE_JOB_STARTUP_SCAN | NSP_FUSE_JOB_REMOUNT | \
     NSP_FUSE_JOB_MEDIA)

typedef void (*NspFuseRecoverFn)(unsigned jobs, void* ctx);

/* 装配回调并创建就绪 eventfd（>=0 供 epoll 注册）。fn 为空或创建失败返回 -1，
   调用方退回内联执行。可重复调用（幂等）；shutdown 之后可再次 start。 */
int nsp_fuse_recover_start(NspFuseRecoverFn fn, void* ctx);

/* 非阻塞请求 jobs（未知位被忽略，jobs==0 直接返回 false）。已排队或正在跑时按位并入
   「再来一轮」。返回 false 表示 worker 起不来（调用方应内联执行）；true 表示已排队。 */
bool nsp_fuse_recover_request(unsigned jobs);

/* 取走完成通知，返回这一轮跑完的任务位（已在跑的多轮按位累积）；没有则返回 0。 */
unsigned nsp_fuse_recover_take(void);

/* 停线程并 join：会等手上那一轮跑完（最长一次恢复序列），不取消。
   只在进程退出的收尾阶段调用；可重复调用。 */
void nsp_fuse_recover_shutdown(void);

#endif /* NSP_FUSE_RECOVER_H */
