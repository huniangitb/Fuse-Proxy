/* uid.map 后台落盘（src/injector/uid_cache_writer.c）。
 *
 * uid.map 是启动期缓存：权威视图在 injector 的内存表里，磁盘只决定「重启后第一批
 * 应用上报前是否已经知道 uid→包名」。落盘要写整表 + fsync + rename，宿主实测
 * 首次映射 58.9ms（p90 108.3ms、max 133.4ms），而它原本发生在 IPC ACK 路径上、
 * 还持着 uid 表互斥：一个慢 fsync 就把事件循环的其它 ACK 和命中路径的并发读者
 * 一起拖住（实测并发命中被拖到 2583ms）。
 *
 * 因此把磁盘动作整体搬到独立线程：调用方只更新内存表 + 置位请求，微秒级返回；
 * 落盘线程取一份快照整表重写，多次请求合并成一轮。语义代价只有「最终落盘」：
 * 进程在落盘完成前被杀，这批映射要等下次上报重新学习（与原来写失败后的行为一致）。
 */
#ifndef NSP_INJECTOR_UID_CACHE_WRITER_H
#define NSP_INJECTOR_UID_CACHE_WRITER_H

#include "uid_map.h"

/* 取一份当前内存表快照：返回 malloc 出来的副本与条目数（副本归落盘线程 free）。
 * 回调在落盘线程上执行，调用方须自行取锁拷贝，不得在回调里做任何 I/O。 */
typedef UidMapEntry* (*UidCacheSnapshotFn)(int* count_out);

/* 在单线程初始化阶段调用；线程起不来时只记一次错误并退化为不落盘（内存表仍权威）。 */
void uid_cache_write_init(UidCacheSnapshotFn snapshot);

/* 请求把当前内存表整表落盘。只置位 + 唤醒，不碰磁盘、不阻塞调用方。 */
void uid_cache_write_request(void);

/* 等已请求的写入轮全部落地（有界等待，超时只记日志）。 */
void uid_cache_write_flush(void);

/* 冲刷未完成的写入并回收落盘线程。 */
void uid_cache_write_shutdown(void);

#endif /* NSP_INJECTOR_UID_CACHE_WRITER_H */