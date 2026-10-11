#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "ftp_conf.h"
#include "ftp_backend.h"
#include "nsp_module.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <curl/curl.h>

/*
 * ftp_module.so — FTP 存储后端模块（由 fuse_daemon dlopen 加载）
 *
 * **不实现 FUSE**：框架（fuse_daemon）已实现 FUSE，
 * 本模块只提供"目标功能（FTP）的操作方法"（backend_*），框架在路径命中
 * （backend_match）时调用，最终执行仍由框架的 FUSE 回调驱动。
 *
 * 功能：按框架下发的配置注册每个 [服务器] 段的虚拟前缀：
 *   虚拟前缀 = /<段名>（如 /云盘）——FUSE 剥离 /0/ 后的原始路径直接命中，
 *   无需 REDIRECT 规则或变量。
 *
 * **配置来源（不读文件、不跑 inotify）**：配置的读取完全在框架侧——框架读
 *   <modules_dir>/ftp_module/ftp_module.conf（模块目录约定，见 docs/modules.md
 *   §6.1.1）后经扁平视图下发（NSP_CFG_REC_MODULE_FILE / MODULE_LINE，按 owner
 *   过滤只发给本模块）。本模块在 init 内注册 set_config_listener，框架在 init
 *   返回后立即回调一次，之后每次热重载再回调；回调内用视图重建后端前缀表。
 *   ftp.conf 变更因此由框架的 inotify 感知，模块自身不再持有任何监听线程。
 *
 * FTP 服务器不可用时由后台线程每 1 分钟重连探活。
 */

#define FTP_MODULE_NAME "ftp_module"

/* 运行期能力探测：本 libcurl 是否编入了 SFTP。
   编译期无法从 curl 头判断——CURL_VERSION_LIBSSH2 这个特性位在 curl 8.x 已
   删除（8.22 头文件里不存在），故查 curl_version_info()->protocols 里有没有
   "sftp"。没有时 proto=sftp 的段**整段跳过**（fail-closed）：静默退回明文
   ftp 会把账号密码发到错误的协议上，比连不上更糟。 */
static bool curl_supports_sftp(void) {
    curl_version_info_data* vi = curl_version_info(CURLVERSION_NOW);
    if (!vi || !vi->protocols) return false;
    for (const char* const* p = vi->protocols; *p; p++)
        if (strcmp(*p, "sftp") == 0) return true;
    return false;
}

static bool g_curl_has_sftp = false; /* init 内探测一次（curl_global_init 之后） */

/* 本模块配置内容的指纹（FNV-1a）：注入器规则等**他人**配置变化也会触发下发，
   指纹相同则跳过重建——后端表重建会释放既有后端对象，无谓重建会波及在途句柄。 */
static uint64_t g_cfg_fp = 0;
static bool g_cfg_seen = false;

/* 把一条 server 注册进后端表；能力/前置条件不满足则跳过该段（返回 false 表示跳过） */
static bool ftp_module_register_server(const FtpServerCfg* s) {
    if (s->sftp && !g_curl_has_sftp) {
        LOG_ERR("ftp_module: [%s] proto=sftp，但本 libcurl 未编入 SFTP（缺 libssh2），"
                "该段跳过", s->name);
        return false;
    }
    if (s->sftp && s->host_key_check) {
        /* 主机密钥校验开启却没有可读的 known_hosts：必然连不上，且 libcurl
           的报错（unknown host / failed verification）指不到配置。启动时
           loud 提示一次，给出补文件的命令与关闭开关——不是错误（文件可能
           稍后补齐），故 WRN。 */
        const char* kh = s->known_hosts[0] ? s->known_hosts : NSP_CONFIG_DIR "/known_hosts";
        if (access(kh, R_OK) != 0)
            LOG_WRN("ftp_module: [%s] host_key_check 开启但 %s 不可读（%s）——"
                    "主机密钥校验会失败；可执行 ssh-keyscan -p %d %s >> %s，"
                    "或在该段设 host_key_check = off",
                    s->name, kh, strerror(errno), s->port, s->host, kh);
    }
    if (ftp_backend_add(s) != 0) return false;
    LOG("ftp_module: 注册后端 /%s → %s://%s:%d%s (server=%s)", s->name,
        s->sftp ? "sftp" : "ftp", s->host, s->port, s->remote_dir, s->name);
    return true;
}

/* 由框架下发的视图重建后端前缀表（init 的首份推送与每次热重载共用）。
   视图只读且仅在回调期间有效（字符串归框架所有），故这里只读不留存。 */
static void ftp_module_apply_config(const NspModuleConfig* cfg) {
    if (!cfg) return;
    FtpServerList list;
    FtpConfParse st;
    ftp_conf_parse_begin(&st, &list, NULL);

    /* 第一遍：只对本模块的配置行取指纹，并记下框架给出的配置路径（标记无条件
       下发，文件缺失时也有确切路径可报）。他人记录（规则/段头/别的模块配置）
       变化与后端表无关，不该触发重建。 */
    const char* owner = NULL;
    bool have = false;
    uint64_t fp = 1469598103934665603ULL;
    for (int i = 0; i < cfg->count; i++) {
        const NspCfgRec* r = &cfg->recs[i];
        if (r->kind == NSP_CFG_REC_MODULE_FILE) {
            owner = r->text;
            if (owner && strcmp(owner, FTP_MODULE_NAME) == 0) st.path = r->file;
            continue;
        }
        if (r->kind != NSP_CFG_REC_MODULE_LINE) continue;
        if (!owner || strcmp(owner, FTP_MODULE_NAME) != 0) continue;
        have = true;
        for (const char* p = r->text; p && *p; p++)
            fp = (fp ^ (unsigned char)*p) * 1099511628211ULL;
        fp = (fp ^ '\n') * 1099511628211ULL;
    }
    if (g_cfg_seen && have && fp == g_cfg_fp) return; /* 逐字未变：不重建 */
    g_cfg_fp = fp;
    g_cfg_seen = have;

    if (!have) {
        /* 无自有配置（文件缺失/内容为空）：与「配置为空」同义，清空后端表并
           loud 告警——静默保留旧后端会让用户以为配置还生效。路径取自框架下发的
           标记（无条件下发），故提示是确切路径而非猜测。 */
        LOG_WRN("ftp_module: 未收到本模块的配置（%s）；无可用 server",
                st.path ? st.path
                        : "<modules_dir>/" FTP_MODULE_NAME "/" FTP_MODULE_NAME ".conf");
        ftp_backend_clear();
        return;
    }

    /* 第二遍：喂进与 ftp_conf_load 同一份行级状态机（语义只有一处实现） */
    owner = NULL;
    for (int i = 0; i < cfg->count; i++) {
        const NspCfgRec* r = &cfg->recs[i];
        if (r->kind == NSP_CFG_REC_MODULE_FILE) {
            owner = r->text;
            continue;
        }
        if (r->kind != NSP_CFG_REC_MODULE_LINE) continue;
        if (!owner || strcmp(owner, FTP_MODULE_NAME) != 0) continue;
        ftp_conf_parse_line(&st, r->text ? r->text : "");
    }
    ftp_conf_parse_end(&st);

    ftp_backend_clear();
    /* 后端表已动态化（加载器注册表 + FTP 后端指针数组均无 16 上限），
       有多少 server 注册多少；单段 add 失败（OOM）仅跳过该段 */
    for (int i = 0; i < list.count; i++) ftp_module_register_server(&list.servers[i]);
    ftp_conf_free(&list);
    if (ftp_backend_count() == 0)
        LOG_WRN("ftp_module: 无可用 server，请检查 %s",
                st.path ? st.path : "<modules_dir>/" FTP_MODULE_NAME "/" FTP_MODULE_NAME ".conf");
    else
        LOG("ftp_module: 后端就绪，共 %d 个", ftp_backend_count());
}

static int ftp_module_init(const NspFrameworkApi* api) {
    if (!api || api->api_version < NSP_FRAMEWORK_API_VERSION) return -1;
    /* libcurl 全局初始化必须在**任何** curl_easy_init 之前完成：不调则 libcurl
       走隐式初始化，而该路径非线程安全（文档明示），本模块的 easy 句柄由任意
       FUSE worker 线程经 ftp_easy_new 并发创建 → 有竞态。幂等（libcurl 内部
       引用计数，重复调用安全），故热重载重复 init 无碍。
       取舍：exit 侧**不**调 curl_global_cleanup——热重载会 dlclose 本 .so，
       若 cleanup 释放了全局 SSL/解析器状态，而其它仍映射的实例（或框架侧
       残留句柄）还在用，就会踩释放后的映射/状态。进程退出时由 libcurl 的
       析构器统一回收，不泄漏。 */
    curl_global_init(CURL_GLOBAL_DEFAULT);
    /* 能力探测须在 curl_global_init 之后（version_info 依赖全局初始化） */
    g_curl_has_sftp = curl_supports_sftp();
    LOG("ftp_module: libcurl %s（SFTP %s）", curl_version(),
        g_curl_has_sftp ? "可用" : "不可用：未编入 libssh2，proto=sftp 段会被跳过");

    /* 配置读取归属：模块不读文件、不跑 inotify。订阅 FTP 规则类型（本模块是
       FTP 后端，规则命中由框架分派；订阅同时把其它类型的规则挡在视图外），
       注册监听拿自己的配置——框架在 init 返回后立即回调一次完成首份装载。 */
    static const char* const sub_types[] = {"FTP"};
    if (api->subscribe_rules) api->subscribe_rules(sub_types, 1);
    if (!api->set_config_listener) {
        LOG_ERR("ftp_module: 框架未提供配置下发接口（api_version 过低），拒绝加载");
        return -1;
    }
    api->set_config_listener(ftp_module_apply_config);
    /* 持久化会话自动处理重连（ftp_session_ensure + NOOP 保活），无需 retry 线程 */
    return 0;
}

static void ftp_module_exit(void) {
    /* 无自有线程/监听可停（配置监听由框架持有，热重载会 dlclose 本 .so 之前
       先调本函数）。后端表与句柄在此释放。 */
    ftp_backend_clear();
    /* 不调 curl_global_cleanup：理由见 ftp_module_init 顶部注释（热重载
       dlclose 场景下清理全局状态会让仍在映射的实例踩空） */
}

static const NspModuleOps ftp_module_ops = {
    /* 后端 I/O：只提供方法，执行由框架 FUSE 回调驱动 */
    .backend_match = ftp_backend_match,     .backend_getattr = ftp_backend_getattr,
    .backend_readdir = ftp_backend_readdir, .backend_open = ftp_backend_open,
    .backend_read = ftp_backend_read,       .backend_write = ftp_backend_write,
    .backend_flush = ftp_backend_flush,     .backend_release = ftp_backend_release,
    .backend_create = ftp_backend_create,   .backend_unlink = ftp_backend_unlink,
    .backend_mkdir = ftp_backend_mkdir,     .backend_rmdir = ftp_backend_rmdir,
    .backend_rename = ftp_backend_rename,   .backend_truncate = ftp_backend_truncate,
};

/* 必须为非 static 动态符号（loader 经 dlsym 查找） */
const NspModuleInfo nsp_module_info = {
    .magic = NSP_MODULE_MAGIC,
    .abi_version = NSP_MODULE_ABI_VERSION,
    .name = FTP_MODULE_NAME,
    .version = "2.0-test",
    .init = ftp_module_init,
    .exit = ftp_module_exit,
    .ops = &ftp_module_ops,
};
