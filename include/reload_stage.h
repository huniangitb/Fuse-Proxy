#ifndef NSP_RELOAD_STAGE_H
#define NSP_RELOAD_STAGE_H

/* 配置视图两段式重载：事件循环只发请求与提交，「读盘 + pm 用户探测」在专属 worker
   上完成。语义与取舍见 docs/architecture.md。 */

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
