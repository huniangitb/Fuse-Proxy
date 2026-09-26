#ifndef FW_CONFIG_H
#define FW_CONFIG_H
/*
 * fw_config.h — 框架侧配置持有者（读取 + 热重载 + 按订阅下发）
 *
 * 职责边界：**读取**完全在框架（文件 I/O + inotify + 行级词法/段头识别，
 * 见 config_read_view），模块不再读文件、不再跑 inotify；**建索引**仍在模块
 * （各模块由扁平视图重建自己的规则索引）。
 *
 * 框架自身不建 AppConfig：它只持有扁平视图并按模块订阅过滤后下发，故不需要
 * 规则对象/trie（那是模块的索引表示）。
 *
 * 线程模型：inotify 监听线程在配置变更后读出新视图，然后经 reload 钩子
 * （loader 注册）在**同一线程**内同步推送给各活跃模块——推送期间旧视图仍有效，
 * 推送完成才释放旧视图，故模块在回调内看到的视图始终一致。
 */
#include <stdbool.h>
#include <stdint.h>
#include "nsp_cfg_view.h"

/* 初始化：读取 rules_path 并启动监听线程。rules_path 为 --rules= 值。
   返回 0 成功；视图为空（主文件缺失且无 App-rules）仍算成功。 */
int fw_config_init(const char* rules_path);
void fw_config_shutdown(void);

/* 当前主视图（框架持有，仅在下次重载前有效）。count_out 可 NULL。 */
const NspCfgRec* fw_config_recs(int* count_out);
uint64_t fw_config_generation(void);

/* 按模块订阅过滤出的视图（浅拷贝记录，字符串仍指向主视图）。
   返回的 NspModuleConfig 由本模块持有，直到下次重载或 shutdown；未知模块
   返回 NULL。订阅为空 = 不过滤（申请全部）。 */
const NspModuleConfig* fw_config_view_for(const char* module_name);

/* 框架侧兜底用的**全局** MONITOR 开关：取主视图中 `[GLOBAL]` 段内最后一条
   MONITOR 记录（ON/1 为开），无记录为关。
 *
   语义边界（勿扩大使用）：只用于「规则模块未参与本次决策」时的监控开关兜底
   ——规则模块未加载/被 ban、路径无 <uid>/ 用户层、模块返回未命中这三种情形
   下模块根本没机会说话，而 MONITOR 是**配置开关而非路径决策**，绑在决策有效性
   上会让文件读写照常正常、只有 IO 监控日志静默消失。模块命中时一律以模块自己的
   三层合并（应用 > 类别 > 全局）为准；此处**不重复实现**那套作用域语义——
   类别/应用段的否决需要 uid→包名映射，那是模块的索引职责。 */
bool fw_config_global_monitor(void);

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
