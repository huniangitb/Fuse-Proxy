#ifndef SYS_PKG_H
#define SYS_PKG_H
#include <stdbool.h>

/* 系统应用包名表（支撑 [SYSTEM_APPS] 类别判定与 SKIP_SYSTEM_APPS）。
 *
 * 数据同源：`pm list packages -s`，失败回退 `uid < 10000`（与原
 * inject_target.c 内联实现一致，本文件为其跨进程共享抽取）。
 * 跨进程约束：fuse_daemon 受限环境 popen("pm ...") 可能经 binder 挂起
 * （见 br_rules_init 注释），故 pm 查询只允许 injector 做并落盘到
 * CONFIG_DIR/sys_pkgs.cache；fuse_daemon（内建引擎与后端模块）只读
 * 文件、永不 popen。无表时行为 = pm 查询失败（uid<10000 回退）。
 * 查询侧统一归一 `:process` 后缀与 pm 行内冒号，调用方直接传原始包名；
 * NULL/空串返回 false。
 * 查询路径只查已发布表：sys_pkg_is_system 永不读 CONFIG_DIR/sys_pkgs.cache、
 * 永不 fork pm；冷缓存与 1s 复查到期时由后台装载线程读文件（from_query），
 * 线程创建失败退回同步装载。sys_pkg_cleanup 之后不留表也不留装载线程。 */
void sys_pkg_init(bool allow_pm);
void sys_pkg_cleanup(void);
bool sys_pkg_is_system(const char* pkg);
/* 刷新：injector 重载路径调（pm→内存+落盘）；非 allow_pm 进程为重读文件 */
void sys_pkg_refresh(void);

#endif
