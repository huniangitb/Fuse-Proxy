#ifndef NSP_ASYNC_REFRESH_H
#define NSP_ASYNC_REFRESH_H

/* 把「可能阻塞数百毫秒到数秒的外部查询」挪出调用线程：请求合并 + 至多一个后台
   worker。调用线程只做一次入队（µs 级），绝不等待回调完成，因此一次慢查询不会
   把事件循环（注入器唯一循环、pre-hook 判定、挂载派发）一起冻住。 */

#include <stdbool.h>

typedef void (*NspAsyncRefreshFn)(void* ctx);

/* 装配唯一回调（一次性，之后的 request 都用它）。fn 为空表示未装配，请求全丢弃。
   必须在任何 nsp_async_refresh_request() 之前、且在 daemonize（fork）之后调用。 */
void nsp_async_refresh_init(NspAsyncRefreshFn fn, void* ctx);

/* 非阻塞请求一次刷新。已有 worker 在跑时只置「再来一轮」标记（不新起线程）；
   起线程失败绝不在调用线程上同步执行（待刷标记保留，下一次请求重新拉起 worker）。*/
void nsp_async_refresh_request(void);

/* 是否还有 worker 在跑（诊断/测试用，不参与生产决策） */
bool nsp_async_refresh_active(void);

/* 停止接新请求，并等当前 worker 退出（含它手上那一轮回调，可能长达一次查询预算）。
   只在进程退出的收尾阶段调用。 */
void nsp_async_refresh_shutdown(void);

#endif /* NSP_ASYNC_REFRESH_H */
