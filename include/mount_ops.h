/* 挂载表写者串行化（src/injector/mount_ops.c）。
 *
 * 维护 worker（恢复 / 启动扫描 / 重挂 / 媒体实例）、审计 worker 与事件循环的
 * 失败重试派发都会改「进程的挂载视图 + pid 缓存」：三者交错会出现「刚挂上又被
 * 清理」、同一次进程遍历被两条线程各改一遍。这里给挂载操作一把全局互斥，
 * 语义是「一轮挂载操作独占」，不是「每次 syscall 独占」。
 *
 * 事件循环侧**只能**用 mount_ops_try_begin()：等锁等于把唯一循环按在一个可能
 * 数十秒的审计轮上（那正是要消除的放大）。抢不到就把自己的活推到几十毫秒后。
 */
#ifndef NSP_INJECTOR_MOUNT_OPS_H
#define NSP_INJECTOR_MOUNT_OPS_H

#include <stdbool.h>

/* 阻塞获取（只在 worker 线程上调用）。可重复获取同一把锁=未定义，故各轮之间必须配对。 */
void mount_ops_begin(void);
void mount_ops_end(void);

/* 非阻塞获取：成功返回 true（调用方必须 mount_ops_end）；失败返回 false，调用方不得
 * 触碰挂载视图，应把自己的工作重新排队。 */
bool mount_ops_try_begin(void);

#endif /* NSP_INJECTOR_MOUNT_OPS_H */