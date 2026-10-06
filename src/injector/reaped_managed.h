#ifndef NSP_REAPED_MANAGED_H
#define NSP_REAPED_MANAGED_H

#include <stdbool.h>
#include <sys/types.h>

/* 受管子进程（fuse_daemon）的收尸留档。
 *
 * 背景：fuse_daemon 退出后，注入器的恢复路径（check_and_recover_fuse）要靠
 * waitpid(pid) 的返回确认"确实退出了"并 dump 崩溃 backtrace。而通用收尸
 * （reap_zombies 的 waitpid(-1)）会抢先把它收走——之后 waitpid(pid) 返回
 * ECHILD，恢复逻辑仍在（kill(pid,0) 早已失败，照常重挂），但崩溃现场不再进
 * 日志环（sys.log / log_ctl 查不到）。waitpid(-1) 无法"跳过指定子进程"，故收尸
 * 时把受管子进程的退出状态留档，供恢复路径复核：语义等价于"无论收尸先后，
 * 恢复路径都能拿到状态"。
 *
 * 单线程主循环使用（signalfd 的 SIGCHLD 分支与定时分支同在主循环），无内部锁；
 * 槽位数固定，溢出时不再新增（保留最先回收的若干受管子进程状态）。 */

/* 记录一个受管子进程的退出状态（收尸先到）。同 pid 重复写入视为幂等覆盖。 */
void reaped_managed_put(pid_t pid, int status);

/* 复核受管子进程是否已退出：先查留档（收尸先到则命中并消费），再 waitpid 兜底
 * （收尸未到）。命中即清槽；status_out 可空。pid<=0 恒返回 false。 */
bool reaped_managed_exited(pid_t pid, int* status_out);

#endif /* NSP_REAPED_MANAGED_H */
