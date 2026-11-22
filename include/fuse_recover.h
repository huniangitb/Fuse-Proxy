/* FUSE 维护 worker：事件循环只发请求与收结果，「改挂载表 / 扫全进程」的慢活在一条
   worker 上串行跑。任务位与语义见下方定义与 docs/architecture.md。 */

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
