#ifndef FW_PKG_H
#define FW_PKG_H
/*
 * fw_pkg.h — 框架侧 uid → 包名解析
 *
 * uid→包名是**配置语义**的输入（应用段/类别段的匹配键、日志的 `[pkg(uid)]`
 * 标签），不是模块的私有索引：`MONITOR` 这类纯配置开关必须与模块是否加载无关
 * 地生效，否则模块缺失时 `[USER_APPS:0] MONITOR OFF` 的否决会静默失效。
 * 故映射归框架，算法与模块 br_get_app_cfg 同源（uid.map 优先，回退 /proc
 * Tgid + cmdline），使两侧对同一请求得到同一个包名。
 *
 * 数据来源：injector 落盘的 `CONFIG_DIR/uid.map`（应用启动时增量写入），
 * 缺失时回退 /proc。框架只读文件，不写 uid.map。
 */
#include <stdbool.h>
#include <sys/types.h>

/* 加载 uid.map 并清空缓存。开机与每次规则重载各调一次（uid.map 随应用启动
   增长，规则重载是既有的低频同步点）。 */
void fw_pkg_reload(void);
void fw_pkg_shutdown(void);

/* uid → 包名。out 恒被写入非空展示名（不可解析时为 "unknown"）。
   返回 true = 名称可用于应用段/类别段匹配；false 表示：
     - uid < NSP_SYSTEM_APP_UID_MIN（out="system"，仍属 SYSTEM_APPS 类别）；
     - 名称过短 / 含 zygote / 含 <pre-（等价模块 br_get_app_cfg 的不可解析分支）。
   tid 为请求者线程 id（0 表示未知，仅用 uid.map）。 */
bool fw_pkg_resolve(uid_t uid, pid_t tid, char* out, size_t size);

/* 同 fw_pkg_resolve，但**不做** uid<10000 的系统伪包短路：照常按 uid.map →
   /proc Tgid+cmdline 解析出真实包名（如 uid 1000 的 com.android.settings），
   供规则匹配层在系统应用上命中显式应用段（[pkg] 段）。解析失败同样返回
   false 且 out 写入尽力得到的名称。 */
bool fw_pkg_resolve_exact(uid_t uid, pid_t tid, char* out, size_t size);

#endif /* FW_PKG_H */
