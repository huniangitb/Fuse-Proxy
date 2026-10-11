#ifndef FTP_CONF_H
#define FTP_CONF_H
/*
 * ftp_conf.h — ftp.conf 解析（远程存储服务器账号配置：FTP / SFTP）
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
 */
#include <stdbool.h>
#include <limits.h>

#define FTP_CONF_MAX_SERVERS 16 /* 初容（动态翻倍起点），不再是硬上限 */

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

/* 解析 ftp.conf。返回 0 成功；负值失败（文件不可读/无 server 段）。
   成功时 out->servers 为堆数组（count>0；0 段时为 NULL），须 ftp_conf_free。 */
int ftp_conf_load(const char* path, FtpServerList* out);
/* 释放 ftp_conf_load 产出的堆数组（NULL/空表安全） */
void ftp_conf_free(FtpServerList* list);

/* 按段名查找 server；找到返回指针，否则 NULL */
FtpServerCfg* ftp_conf_find(FtpServerList* list, const char* name);

#endif /* FTP_CONF_H */
