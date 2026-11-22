#ifndef NSP_RELOAD_STAGE_H
#define NSP_RELOAD_STAGE_H

/* 配置视图的两段式重载：事件循环只发请求与提交，「读盘 + pm 用户探测」在专属
   worker 上完成。

   动机：注入器只有一条事件循环线程，配置重载路径里内联 config_read_view() 会
   同步扫主配置/App-rules/模块 conf（多次 fopen，慢盘上每次几十毫秒），并且先调
   scan_active_users() → `pm list users`（预算 800ms，binder 抖动时吃满）。这段时间
   里 pre-hook 判定、挂载派发、IPC ACK 全部停住：一次慢读放大成整进程无响应，而
   zygisk 侧 pre-hook 的 IPC 超时只有 100ms，超时即走 fail-open——应用这一次启动
   看到的是系统存储视图，不是代理视图。

   语义（刻意保守）：
     - request 绝不阻塞调用线程，也不在调用线程上读盘；
     - 至多一个 worker 线程，重复请求合并成「再来一轮」，突发 N 次写只读 1~2 轮；
     - 槽里只保留最新一份视图（未取走的旧视图在发布新视图时释放）；
     - 提交仍在事件循环上做（config_commit_prepared 会改全局发布视图），但那时
       读盘已完成，写锁只罩内存构建；
     - 读失败与「读到空视图」都算一次有效结果（count==0 也交给调用方提交），
       否则空配置会让重载被静默丢弃。 */

#include <stdbool.h>

#include "config_parser.h" /* NspCfgRec */

/* 启动读取 worker 并返回就绪 eventfd（<0 表示失败，调用方退回内联读——
   宁可慢一次也不能丢重载）。config_path 会被拷贝。可重复调用（幂等）；
   shutdown 之后可再次 start（测试里多轮起停）。 */
int nsp_reload_stage_start(const char* config_path);

/* 非阻塞请求一次读取。worker 正在读时只置「再来一轮」。 */
void nsp_reload_stage_request(void);

/* 取走已备好的视图（最新一份）。没有可取结果返回 false；取到即转移所有权，
   调用方用 config_free_view(recs, count) 释放。空视图（count==0、recs==NULL）
   也算取到，returns true。 */
bool nsp_reload_stage_take(NspCfgRec** recs, int* count);

/* 停线程并 join（会等手上那一轮读完，最长一次读盘+pm 预算），丢弃未取走的视图。
   只在进程退出的收尾阶段调用；可重复调用。 */
void nsp_reload_stage_shutdown(void);

#endif /* NSP_RELOAD_STAGE_H */
