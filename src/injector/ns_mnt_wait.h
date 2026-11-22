/* SPDX-License-Identifier: GPL-3.0-or-later */
/* 版权所有 (C) 2026 huniangitb <3361107168@qq.com> */
#ifndef NS_MNT_WAIT_H
#define NS_MNT_WAIT_H

#include <stdbool.h>
#include <sys/types.h>

/*
 * ns_mnt_wait — 有界等待某个进程换掉自己的挂载命名空间
 *
 * 场景：pre 阶段拿到的 pid 还在 zygote 的挂载命名空间里，此刻挂载会污染之后
 * fork 的每个应用；应用自己的命名空间要到 specialize 完成才成立，判据就是
 * /proc/<pid>/ns/mnt 的 (dev, ino) 变掉。这个等待必须**有界**——应用可能一直
 * 不换，等的人不能陪着挂死。
 *
 * 事件源与精度的分工（都是内核实现给出的约束，不是取舍）：
 *  - 命名空间切换**不产生任何 poll 事件**：ns/mnt 的 inode 换掉不会让被盯的
 *    那份 mountinfo 变脏，旧命名空间的 fd 更看不到新命名空间里的挂载变化，
 *    inotify 盯 /proc/<pid>/ns 也静默。所以「换没换」只能靠 stat 复核。
 *  - /proc/<pid>/mountinfo 的 poll 实现（见 ns_mnt_watch.h）在该命名空间每次
 *    mount/umount 后回报一次 EPOLLERR：应用自己的命名空间成立之后 vold 往往
 *    紧接着往里装配 /storage，这类变化能让等待提前醒来复核。注册掩码必须为 0
 *    （mounts_poll 恒置 EPOLLIN，带进掩码就成了忙轮询）。
 *  - 剩下的精度由节拍给出：ppoll 的纳秒超时在切换高发窗口内按
 *    NS_MNT_WAIT_ARM_FAST_US 走，之后退回 NS_MNT_WAIT_ARM_US（与旧的 2ms 步进
 *    同粒度，长等待的唤醒次数不因此变多）。节拍上限即检测精度的上界。
 *  - 事件源打不开（或 poll 报错）就退回纯节拍等待：功能不押在事件源上。
 */

/* 取 pid 当前所在的挂载命名空间身份；失败保留 errno 并返回 false。
   这个二元组就是「还没换命名空间」的基线。 */
bool ns_mnt_wait_capture(int pid, dev_t* ns_dev, ino_t* ns_ino);

/* 有界等待 pid 换掉 (ns_dev, ns_ino)：budget_ms 到点必返回，返回实际等过的
   微秒数；*switched 写结束事实（true = 等到了切换）。进程中途退出按「没换」
   结束。budget_ms <= 0 时只复核一次。 */
long ns_mnt_wait_switch(int pid, dev_t ns_dev, ino_t ns_ino, long budget_ms, bool* switched);

#endif /* NS_MNT_WAIT_H */
