/* SPDX-License-Identifier: GPL-3.0-or-later */
/* 版权所有 (C) 2026 huniangitb <3361107168@qq.com> */
#ifndef NSP_FD_CLOSE_QUEUE_H
#define NSP_FD_CLOSE_QUEUE_H

#include <pthread.h>
#include <stdatomic.h>

/* 内部队列：发布和领取只持短锁；消费者复制整个批次后独占这些 fd，锁外
 * close。consumed 是领取水位，不是关闭完成水位。复用环槽不会改写私有批次。
 * 满时只回收旧批，当前 fd 保留在调用者，绝不提前关闭或制造发布缺口。
 * 单次慢 close 只拖领取者/其私有批次，不通过队列锁阻止其他消费者或生产者。
 * flush 返回不代表其他领取者的 close 已完成，close 本身没有时间上界。 */
#define FD_CLOSE_QUEUE_CAP 64
#define FD_CLOSE_QUEUE_MASK (FD_CLOSE_QUEUE_CAP - 1)

typedef struct {
    pthread_mutex_t lock;
    int fds[FD_CLOSE_QUEUE_CAP];
    _Atomic unsigned next;
    _Atomic unsigned ready;
    _Atomic unsigned consumed;
} FdCloseQueue;

/* 静态实例用 {.lock = PTHREAD_MUTEX_INITIALIZER}；不要重复初始化。 */
void fdq_init(FdCloseQueue* q);
void fdq_defer(FdCloseQueue* q, int fd);
void fdq_flush(FdCloseQueue* q);

/* backing 专用的线程所有权。调用者必须保证 legacy transport、非重入，且
 * 每次挂接前同 worker 已在 getattr 入口清理上次请求的 fd。成功才转移 fd
 * 所有权；失败仍由调用者处理，且不得向 reply 发布该 fd。其他线程的 flush
 * 不可关闭它。正常 worker 退出由 TSD 析构清尾；单线程 main 须显式 flush。
 * 只适用于同步发送回复，不能用在先准备 SQE 后异步提交的 io-uring transport。 */
bool fdq_thread_defer(int fd);
void fdq_thread_flush(void);

/* 仅在相关线程全部停止时替换；nullptr 恢复 close(2)。 */
typedef int (*FdqCloseFn)(int fd);
void fdq_set_close_fn(FdqCloseFn fn);

#endif /* NSP_FD_CLOSE_QUEUE_H */
