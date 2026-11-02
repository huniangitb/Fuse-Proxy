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

/* uid 是否为**特权应用**：来源 /data/system/packages.list 的 seinfo 字段
   （SELinux MAC 标签，由系统按签名/分区判定），以 "platform" 开头即 platform
   签名（system/priv-app/共享签名；实测 DocumentsUI/Settings 为
   "platform:privapp:…"，普通应用恒为 "default:…"）。
   用途：跨应用隔离的自动豁免——DocumentsUI 等文件中介的本职就是访问他包
   /Android/data，逐包手工写规则不可维护，按 Android 自己的权限体系放行。
   fail-safe：packages.list 不可读或该 uid 无行 → false（不豁免）。
   结果按 uid 缓存；fw_pkg_reload（规则重载）后随 gen 失效重读。 */
bool fw_pkg_is_privileged(uid_t uid);

/* uid 是否持有 **MANAGE_EXTERNAL_STORAGE**（"所有文件访问"，Android 11+ 的 All
   files access）。来源：AppOpsService 自身——该权限是 appop，AOSP 14+ 不再落
   /data/system/appops.xml，设备上也没有任何可读的状态文件，故按 uid 解析出包名
   后跑一次 cmd appops get <pkg>（root 直跑，实测约 40ms，与 legacy storage 共用
   同一次查询）。输出 "Uid mode: …: allow" 与 "…: allow" 两种形态都算持有。
   用途：与 fw_pkg_is_privileged 同一个豁免位——安装器/文件管理器/应用商店这类
   持有 All files access 的应用，本职就是读他包 /Android/data（如安装器读 IM
   落盘的 apk），按 Android 自己的授权放行，而不是逐包写规则。
   fail-safe：packages.list 查不到该 uid、命令缺失或执行失败 → false（不豁免）。
   结果按 uid 缓存（命中/未命中都缓存），fw_pkg_reload 后随 gen 失效重查；
   另有 30s 有效期——appops 模式是运行期可变的（用户在设置里随时授予/撤销），
   只靠 gen 失效会让授权在重启 daemon 前一直不生效。
   锁纪律：自持独立互斥量 g_ext_fill_lock，函数体内只碰 packages.list 解析与
   posix_spawn，不调用任何其它 fw_pkg 缓存函数。 */
bool fw_pkg_manages_external(uid_t uid);

/* uid 是否处于 **legacy storage** 模式（targetSdk ≤ 29 的旧式整盘访问，appop
   LEGACY_STORAGE 为 allow）。与 fw_pkg_manages_external 共用同一份 appops 查询
   与同一个 uid 槽位，判定口径一致。
   用途：同上——legacy storage 应用在 AOSP 里本来就看得见他包 /Android/data，
   本项目把它们判成不可见属于收紧过度。
   fail-safe 与缓存策略同 fw_pkg_manages_external。 */
bool fw_pkg_has_legacy_storage(uid_t uid);

/* 仅测试：替换 appop 查询实现（GNU 测试环境没有 /system/bin/cmd）。传 nullptr
   恢复生产查询；两个钩子任一非空即走钩子路径，未设的那个按 false 处理。 */
void fw_pkg_set_manage_external_probe(bool (*fn)(const char* pkg));
void fw_pkg_set_legacy_storage_probe(bool (*fn)(const char* pkg));

/* 包名 → uid（/data/system/packages.list 的 "pkg uid ..." 行，与
   fw_pkg_is_privileged 同一份文件、同一个路径钩子）。
   用途：FUSE 事件通道的消费方（MPM）跑在 MediaProvider 进程内，SO_PEERCRED
   拿到的是那个进程的 uid——com.google.android.providers.media.module /
   com.android.providers.media 既不是 system(1000) 也不是 media_rw(1023)
   （实测 uid=10277，OPD2404/Android16），默认白名单写死必然把它拒掉，通道等于
   开不起来。故 daemon 启动时按包名解析出 uid 后追加进白名单。
   **只认解析出来的 uid**：包名不可由请求方声明，白名单也不接受名字。
   fail-safe：packages.list 不可读或无该包 → false（调用方只少这一项，通道其余
   照旧）。结果按 (包名, 代际) 缓存，fw_pkg_reload（配置重载）后随 gen 重解析。
   锁纪律：自持独立互斥量，函数体内只做 packages.list 解析，不调用任何会回头
   取 g_fill_lock / g_priv_fill_lock 的函数（那两条路径会反过来调本函数，
   嵌套即死锁）。 */
bool fw_pkg_uid_for_package(const char* pkg, uid_t* out);

/* 仅测试：把 packages.list 的读取路径换掉（生产代码永不调用；GNU 测试环境
   没有 /data/system）。传 nullptr 恢复默认路径。 */
void fw_pkg_set_packagelist_path(const char* path);

#endif /* FW_PKG_H */
