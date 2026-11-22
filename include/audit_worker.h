#ifndef NSP_AUDIT_WORKER_H
#define NSP_AUDIT_WORKER_H

/* 配置重载后的「对运行中应用对账」是慢活：逐个 tracked 应用做 is_target_app 判定 +
 * 挂载/卸载/还原，慢盘、挂起的命名空间子进程、几十个在跑的应用叠起来就是数百毫秒
 * 到数秒。它原先内联在注入器唯一的事件循环线程上，于是**一次慢对账 = 所有应用的
 * pre-hook 判定与挂载派发停摆**。这里把它挪到至多一个后台 worker：调用线程只做一次
 * 拷贝入队（µs 级），绝不等待、绝不在调用线程上同步执行。
 *
 * 语义（刻意保守，与 async_refresh 同构）：
 *   - 请求合并：worker 在跑时新请求并入它下一轮，突发 N 次重载只跑 1~2 轮；
 *   - 变更集合取并集（同一 pkg/user_id 去重）；「整体变化」与具体条目**同时保留**：
 *     worker 先按具体变更精确重挂、再做 tracked 全量扫描（全量扫描只走 tracked 表，
 *     运行中但未追踪的应用只有具体那一轮碰得到，提前丢掉就是漏对账）；
 *   - 集合溢出（超过 NSP_AUDIT_MAX_CHANGED 条）时退化成全量扫描：超限条目无法逐条
 *     送达，交由全量扫描与下一次重载兜底；
 *   - 跑的那一刻按**当前**注入方法重新选审计粒度（模式可能在排队期间被切走）；
 *   - worker 空闲 200ms 自行退出，不常驻；起线程失败绝不在调用线程同步跑（宁可少
 *     对账一次，也不把事件循环卡住），但待跑集合保留，下一请求重新拉起 worker 补上。
 */

#include <stdbool.h>

#include "config_parser.h" /* ChangedPkg：入队变更集合（pkg_name + user_id） */

/* 一次入队能携带的变更条目上限；超限时 worker 升级成全量扫描（见上） */
#define NSP_AUDIT_MAX_CHANGED 128

/* 派发一次对账请求。changed/count 描述本次重载的变更集合，global_reset=true 表示
 * 规则视图整体变化（跑全量审计）。count<=0 且 global_reset=false 也合法：v1 逐应用
 * 模式下每次重载都要做一次全量对账。调用线程只拷贝入队，不等待。 */
void nsp_audit_request(const ChangedPkg* changed, int count, bool global_reset);

/* 是否还有 worker 在跑（诊断/测试用，不参与生产决策） */
bool nsp_audit_active(void);

/* 停止接新请求并等当前 worker 退出（含它手上那一轮对账，可能长达一次挂载预算）。
 * 未开始的那一轮丢弃：进程随后就做退出清理，下一次启动的全量扫描会补上。
 * 只在进程退出的收尾阶段调用。 */
void nsp_audit_shutdown(void);

#endif /* NSP_AUDIT_WORKER_H */
