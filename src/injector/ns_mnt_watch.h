/* SPDX-License-Identifier: GPL-3.0-or-later */
/* 版权所有 (C) 2026 huniangitb <3361107168@qq.com> */
#ifndef NS_MNT_WATCH_H
#define NS_MNT_WATCH_H

/*
 * ns_mnt_watch — 挂载表变化的**事件源**（poll 语义，不需要周期读文件）
 *
 * /proc/<pid>/mountinfo 的 poll 实现在内核里（fs/proc_namespace.c 的
 * mounts_poll）对比该命名空间的 ns->event 与文件打开时的快照：两者不一致就
 * 回报 EPOLLERR，并在回报的同时更新快照。于是对同一份 mountinfo 反复 poll，
 * 「每次挂载表变化」恰好换来一次可读，没有变化时一次都不返回——挂载事件本身
 * 就是唤醒源，不必按固定周期把整份挂载表读一遍来比对新旧。
 *
 * 唯一的用法约束：注册进 epoll 时 **events 必须为 0**。
 * mounts_poll 对任何打开都置 EPOLLIN|EPOLLRDNORM（文件恒可读），把 EPOLLIN
 * 带进注册掩码就成了电平触发的忙轮询；EPOLLERR 不受掩码约束（epoll 无条件
 * 回报），只留它才是纯粹的「挂载表变了」通知。
 *
 * 命名空间按 pid 选：pid 取自哪个进程的 /proc，就用那个进程所在命名空间的
 * 挂载表（pid=1 即 init 命名空间）。返回值是一个普通 fd，用后 close()。
 */

/* 打开 ns_pid 所在命名空间的挂载表事件源；失败返回 -1 并保留 errno
   （调用方据此退回周期复查，不影响功能） */
int ns_mnt_watch_open(int ns_pid);

#endif /* NS_MNT_WATCH_H */
