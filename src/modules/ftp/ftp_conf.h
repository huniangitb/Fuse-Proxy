#ifndef FTP_CONF_H
#define FTP_CONF_H
/*
 * ftp_conf.h — 模块配置解析（远程存储服务器账号配置：FTP / SFTP）
 *
 * 格式（INI 风格）：
 *   [云盘]
 *   host = ftp.example.com
 *   port = 21
 *   user = myuser
 *   password = mypass
 *   remote_dir = /
 *
 * SFTP（proto = sftp；port 默认 22，与 ftp 的 21 一样在未显式配置时按协议补）：
 *   [备份]
 *   proto = sftp
 *   host = nas.local
 *   user = backup
 *   key_file = /data/Namespace-Proxy/keys/backup.key
 *   key_pass = <私钥口令，可选>
 *   known_hosts = /data/Namespace-Proxy/known_hosts
 *   host_key_check = on        # 默认 on：主机密钥不匹配即拒连（fail-closed）
 *
 * 每个 [server] 段定义一个服务器；段名即虚拟前缀（虚拟前缀 = /<段名>，
 * FUSE 访问 /0/<段名>/... 直接命中）。支持 '#' 注释与空行；'=' 两侧允许空格。
 *
 * **配置来源**：模块不读文件、不跑 inotify（见 nsp_module.h 与 docs/modules.md
 * §6.1.1）。运行时配置由框架读 `<modules_dir>/ftp_module/ftp_module.conf` 后经
 * 扁平视图下发（`NSP_CFG_REC_MODULE_LINE`），模块把下发的行喂进 ftp_conf_parse_*；
 * `ftp_conf_load`（直接读文件）只保留给测试驱动与离线工具，**不在运行路径上**。
 */
#include <stdbool.h>
#include <limits.h>

#define FTP_CONF_MAX_SERVERS 16 /* 初容（动态翻倍起点），不再是硬上限 */
#define FTP_CONF_LINE_MAX 1024  /* 单行上限：超长行整行丢弃并整段作废（fail-closed） */

/* 服务器配置（FtpServerCfg：段名/协议/连接/远程根） */
typedef struct FtpServerCfg {
    char name[64]; /* 服务器名（ftp.conf 段名）：虚拟前缀 /<name> */
    char host[256];
    int port; /* 0 = 未显式配置；载入结束时按协议补默认（ftp 21 / sftp 22） */
    char user[64];
    char pass[128];
    char remote_dir[512]; /* 远程根目录（默认 "/"） */
    /* ---- SFTP（proto = sftp）专用；ftp 下全部忽略 ---- */
    bool sftp;             /* true = sftp://，false = ftp://（默认） */
    char key_file[512];    /* SSH 私钥文件（空 = 密码认证 / ssh-agent） */
    char key_pass[128];    /* 私钥口令（可选） */
    char known_hosts[512]; /* known_hosts 路径（空 = <CONFIG_DIR>/known_hosts） */
    bool host_key_check;   /* SSH 主机密钥校验（默认 true，fail-closed） */
    bool bad; /* 解析期标记：任一字段超长/非法即整段作废（见 ftp_conf.c），不参与连接 */
} FtpServerCfg;

/* 服务器表：动态数组（初容 16，按需翻倍），不再有 16 段硬上限。
   ftp_conf_load 成功时 malloc，调用方用 ftp_conf_free 释放。 */
typedef struct FtpServerList {
    FtpServerCfg* servers;
    int count;
    int cap; /* 容量（内部管理，调用方勿改） */
} FtpServerList;

/* 解析模块配置文件（<modules_dir>/ftp_module/ftp_module.conf）。返回 0 成功；
   负值失败（文件不可读/无 server 段）。
   成功时 out->servers 为堆数组（count>0；0 段时为 NULL），须 ftp_conf_free。
   **仅测试驱动/离线工具使用**：运行路径走配置下发（见下）。 */
int ftp_conf_load(const char* path, FtpServerList* out);
/* 释放 ftp_conf_load 产出的堆数组（NULL/空表安全） */
void ftp_conf_free(FtpServerList* list);

/* ---- 行级状态机：文件形态与配置下发视图共用同一份解析语义 ---- */
typedef struct {
    FtpServerList* out;
    char cur_section[128];
    bool cur_section_bad; /* 段名超长：整段跳过（不建 server，不消费键） */
    FtpServerCfg* cur;
    const char* path; /* 诊断用（文件形态 = 路径；视图形态 = 记录里的 file） */
    int lineno;
} FtpConfParse;

void ftp_conf_parse_begin(FtpConfParse* st, FtpServerList* out, const char* path);
/* 喂入一行（原始行：未去注释、未去首尾空白）。入参只读，内部复制后再处理。 */
void ftp_conf_parse_line(FtpConfParse* st, const char* line);
/* 读层已丢弃的超长行（> NSP_CONFIG_LINE_MAX，到不了 parse_line） */
void ftp_conf_parse_overlong(FtpConfParse* st);
/* 补默认端口 + 清理无效段。返回 0 表示有可用 server，负值表示无。 */
int ftp_conf_parse_end(FtpConfParse* st);

#endif /* FTP_CONF_H */
