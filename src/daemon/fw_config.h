#ifndef FW_CONFIG_H
#define FW_CONFIG_H
/*
 * fw_config.h — 框架侧配置持有者（读取 + 热重载 + 按订阅下发）
 *
 * 职责边界：**读取**完全在框架（文件 I/O + inotify + 行级词法/段头识别，
 * 见 config_read_view），模块不再读文件、不再跑 inotify；**规则索引**仍由各
 * 模块按需从扁平视图重建。
 *
 * 但框架**自己也需要一份索引**：`MONITOR` 是配置开关而非路径决策，它的作用域
 * 合并（应用显式 > 类别显式 > 全局）必须与模块是否加载无关地生效——否则模块
 * 未加载/被 ban 时 `[USER_APPS:0] MONITOR OFF` 的否决会静默失效。故框架在重载
 * 时用 config_build_from_view 自建 AppConfig（与模块同一份实现），仅用于回答
 * 这一个问题；路径决策（REDIRECT/HIDE/RO）仍归模块。
 *
 * 线程模型：inotify 监听线程在配置变更后读出新视图，然后经 reload 钩子
 * （loader 注册）在**同一线程**内同步推送给各活跃模块；同时模块加载线程也会
 * 独立推送首份视图（module_prepare）。故下发视图为**不可变 + 引用计数的快照**
 * （见 fw_config_view_acquire/release）：任一在飞回调持有的视图都不会被并发
 * 重载释放，模块在回调内看到的视图始终一致。
 */
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include "nsp_cfg_view.h"

/* 初始化：读取 rules_path 并启动监听线程。rules_path 为 --rules= 值。
   返回 0 成功；视图为空（主文件缺失且无 App-rules）仍算成功。 */
int fw_config_init(const char* rules_path);
void fw_config_shutdown(void);

/* 当前主视图（框架持有，仅在下次重载前有效）。count_out 可 NULL。 */
const NspCfgRec* fw_config_recs(int* count_out);
uint64_t fw_config_generation(void);

/* 按模块订阅过滤出的视图（记录与字符串均为快照私有副本）。
   **取用即持引用**：acquire 返回的视图在 release 之前始终有效，不受并发重载
   影响（旧实现返回指向订阅表的借用指针，解锁后即可能被重载线程释放 → UAF）。
   acquire 返回的指针必须原样交给 release；未知模块或快照创建失败返回 NULL。
   订阅为空 = 不过滤（申请全部）。 */
const NspModuleConfig* fw_config_view_acquire(const char* module_name);
void fw_config_view_release(const NspModuleConfig* view);

/* IO 监控开关（框架权威）：按 uid→包名做三层合并——应用段显式 > 类别段显式
   （USER_APPS[:uid] / SYSTEM_APPS）> `[GLOBAL]`。**不依赖任何模块**：模块未加载/被 ban、路径无 <uid>/ 用户层、模块
   未命中规则时同样给出正确值。结果按 uid 缓存，重载时随代际失效。

   uid<10000 或包名不可解析（system/unknown/过短/zygote）时只认 SYSTEM_APPS 与
   `[GLOBAL]`——与模块侧同一口径（类别判定复用 sys_pkgs.cache / uid<10000）。 */
bool fw_config_monitor_for(uid_t uid, pid_t tid);

/* 订阅与监听注册（loader 在模块 init 期间以其名转发；名称须与目录名一致）。
   订阅仅在首次注册时生效（重复注册忽略），监听可覆盖。 */
void fw_config_set_subscription(const char* module_name, const char* const* types, int count);
void fw_config_set_listener(const char* module_name, void (*cb)(const NspModuleConfig*));
/* 取已注册的监听器（loader 需经围栏调用它，故须拿到函数指针）；无则 NULL */
void (*fw_config_listener_for(const char* module_name))(const NspModuleConfig*);
/* 模块卸载时清理其订阅/监听/过滤视图 */
void fw_config_forget_module(const char* module_name);

/* 重载钩子：fw_config 读到新视图后调用（loader 在此遍历活跃模块推送）。
   钩子内旧视图仍有效。 */
void fw_config_set_reload_hook(void (*hook)(void));

#endif /* FW_CONFIG_H */
