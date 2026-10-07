/* SPDX-License-Identifier: GPL-3.0-or-later */
/* 版权所有 (C) 2026 huniangitb <3361107168@qq.com> */
#ifndef NSP_FD_CLOSE_QUEUE_H
#define NSP_FD_CLOSE_QUEUE_H

/* ================= 延迟 close 环形队列（daemon 内部件） =================
 * 用途：Android backing 路径把 fd 交给内核后不能立即 close（内核可能在
 * reply 发送完成前仍引用它），但也不能无限期持有，故入队，等下一次 FUSE
 * 回调时机统一回收（见 fuse_daemon.c 的 vfs_defer_close）。
 *
 * 并发模型：**多生产者 / 多消费者**——FUSE worker 线程在 getattr/access/
 * readdir/open 入口都会 flush（默认 2 个 worker，注释里旧称「单消费者」与
 * 实际不符，正是重复 close 缺陷的来源）。两条必须守住的不变量：
 *
 * 1) 每个入队 fd 恰好被 close 一次。消费批次由互斥锁独占领取；且
 *    `consumed` 是**完成水位**——关闭全部完成后才推进。若先推进再关闭，
 *    生产者可在旧槽位尚未 close 时复用同一槽位，把待关 fd 顶掉（漏关一个
 *    fd 并误关新 fd）。
 * 2) 队列满**不阻塞、不制造「被放弃的槽位」、更不提前关闭本次 fd**。
 *    旧实现「满则立即 close 该 fd」把正确性问题写成了性能取舍——队列存在的
 *    唯一理由就是内核可能在 reply 发送完成前仍引用该 fd，立即 close 会让内核
 *    拿到已关闭的 fd，且 fd 号可被另一 worker 的 open 立刻复用（backing 挂到
 *    无关文件）。现改为：满时先**促消费腾位**（回收已完成批次；必要时让出 CPU
 *    等在途占号者发布）后重试占号；仅当预算内回收无进展（需 worker 数 ≥ 容量，
 *    稳态不可达）才 loud 告警 + 兜底直关。
 *    同时 `ready` 水位只由真正写入过槽位的生产者推进——旧实现先占号再判满，
 *    占号者直接返回会让 `ready` 永久缺这一格，后续生产者自旋等待一个
 *    永不发布的槽位，多个 FUSE worker 一起挂死。
 *
 * 空队列 fast path 不加锁（稳态零原子写，保持原设计意图）。
 * 注意：`fdq_defer` 在饱和路径上会调用 `fdq_flush`（生产者兼任一次消费者）——
 * 回收的是**更早回调**留下的 fd，与本次 defer 的 fd 无关，故安全且不会自锁。 */

#include <pthread.h>
#include <stdatomic.h>

/* 队列深度（2 的幂）。满时不提前关闭本次 fd：先促消费腾位后重试占号，
   兜底才降级为直接 close（需 worker 数 ≥ 容量，稳态不可达）。 */
#define FD_CLOSE_QUEUE_CAP 64
#define FD_CLOSE_QUEUE_MASK (FD_CLOSE_QUEUE_CAP - 1)

typedef struct {
    pthread_mutex_t lock; /* 消费侧独占领取 + 与生产者的满判定互斥 */
    int fds[FD_CLOSE_QUEUE_CAP];
    _Atomic unsigned next;     /* 生产分配水位（CAS 递增占号） */
    _Atomic unsigned ready;    /* 生产发布水位（槽位写入后按序推进） */
    _Atomic unsigned consumed; /* 消费完成水位（关闭完成后推进） */
} FdCloseQueue;

/* 独立实例（单测）初始化。静态实例请直接
   `= {.lock = PTHREAD_MUTEX_INITIALIZER}`（其余字段零值即初始态），
   勿对已初始化的实例再调本函数。 */
void fdq_init(FdCloseQueue* q);

/* 延迟关闭一个 fd：队列满则先促消费腾位后重试，绝不提前关闭该 fd、也绝不
   无限阻塞（回收无进展时 loud 告警 + 兜底直关）。 */
void fdq_defer(FdCloseQueue* q, int fd);

/* 回收全部待关闭 fd；可被多线程并发调用（空队列走无锁快速路径）。 */
void fdq_flush(FdCloseQueue* q);

/* 测试注入点：替换实际 close(2)。真实 fd 上的重复 close 只在 fd 号被复用
   后才可观测（表现为误关无关资源），无法确定性断言，故单测用计数器验证
   「每个 fd 恰好关闭一次」。传 NULL 恢复默认 close(2)。 */
typedef int (*FdqCloseFn)(int fd);
void fdq_set_close_fn(FdqCloseFn fn);

#endif /* NSP_FD_CLOSE_QUEUE_H */
