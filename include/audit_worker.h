#ifndef NSP_AUDIT_WORKER_H
#define NSP_AUDIT_WORKER_H

/* 配置重载后的运行中应用对账：至多一个后台 worker，调用线程只拷贝入队（µs 级），
 * 不等待、不在调用线程上同步执行。语义与取舍见 docs/architecture.md。 */

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
