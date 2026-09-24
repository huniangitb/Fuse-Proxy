/* SPDX-License-Identifier: GPL-3.0-or-later WITH Fuse-Proxy-module-exception */
#ifndef NSP_CONSTANTS_H
#define NSP_CONSTANTS_H
/*
 * nsp_constants.h — 跨进程 / 跨模块共享业务常量的唯一出处
 *
 * 定位：零依赖（不 include 任何项目头，无函数/类型声明），框架各进程、
 * dlopen 热插拔模块与独立二进制（rule_server/log_ctl 等）均可直接引入。
 * 判定标准只有一条：同一业务语义在多个 TU 出现字面量才收在此处；仅单处
 * 消费的私有常量不属此列（YAGNI）。
 *
 * 平台根（NSP_CONFIG_DIR / NSP_STORAGE_BASE / NSP_LOG_DIR）随 TARGET_ANDROID
 * 切换，与 common.h 的 CONFIG_DIR / STORAGE_BASE / LOG_DIR、nsp_module.h 的
 * 同名别名同值——后者均以本头为唯一出处。
 */

/* ================= uid 布局（Android 多用户） =================
 * uid = user_id * NSP_PER_USER_UID_STRIDE + app_id；app_id < NSP_SYSTEM_APP_UID_MIN
 * 为系统 uid（AID_APP_START 以下），普通应用 app_id 自 10000 起。
 * 注意：NSP_PER_USER_UID_STRIDE 是「每用户 uid 跨度」（除法取 user_id、
 * 取模取 app_id），不用于 uid 合法上界校验。 */
#define NSP_SYSTEM_APP_UID_MIN  10000
#define NSP_PER_USER_UID_STRIDE 100000

/* ================= Android 存储路径 =================
 * 应用可见的外部存储根（/sdcard 的规范路径）。与真实物理存储根
 * NSP_STORAGE_BASE（/data/media）是两回事：前者是规则路径与挂载点的公共
 * 前缀，后者是 FUSE 内部读写目标。GNU 下同样参与规则路径解析，故不做
 * 平台条件编译（它是路径字面量而非平台根）。 */
#define NSP_ANDROID_EMULATED_ROOT "/storage/emulated"

/* ================= 应用规则目录名 =================
 * uid 0 → <NSP_CONFIG_DIR>/App-rules；uid > 0 → <NSP_CONFIG_DIR>/App-rules-<uid>
 * （路径合成见 nsp_util.h 的 nsp_app_rule_dir/nsp_app_rule_path） */
#define NSP_APP_RULES_DIRNAME "App-rules"

/* ================= 缓冲区上限 =================
 * NSP_CONFIG_LINE_MAX：配置/规则文件单行上限（docs/config.md「单行 ≤2048 字节」，
 *   超长行不参与段/键匹配）；NSP_LOG_MSG_MAX：单条日志消息上限（common.c 组帧
 *   缓冲与 log_monitor 存储槽一致，避免两侧上限漂移导致截断）。 */
#define NSP_CONFIG_LINE_MAX 2048
#define NSP_LOG_MSG_MAX     4096

/* ================= 平台根目录 =================
 * Android 用 /data/Namespace-Proxy（/data 可写）；GNU 无 /data，配置/日志/
 * 模块默认路径须可写，故用 /var/fuse-proxy；真实存储根同理（GNU 无 /data/media）。
 *
 * 两个根各自独立 #ifdef（而非同一分支内并列）：保证 `#define NSP_CONFIG_DIR
 * "/var/fuse-proxy"` 独占一行且无对齐填充——tests/test_config_snapshot.py 按
 * `^#define\s+NSP_CONFIG_DIR\s+"/var/fuse-proxy"\s*$` 在副本头中定向替换，
 * 与 AlignConsecutiveMacros 对齐后的写法解耦。 */
#ifdef TARGET_ANDROID
#define NSP_CONFIG_DIR "/data/Namespace-Proxy"
#else
#define NSP_CONFIG_DIR "/var/fuse-proxy"
#endif

#ifdef TARGET_ANDROID
#define NSP_STORAGE_BASE "/data/media"
#else
#define NSP_STORAGE_BASE "/var/fuse-proxy/storage"
#endif

#define NSP_LOG_DIR NSP_CONFIG_DIR "/log"

#endif /* NSP_CONSTANTS_H */
