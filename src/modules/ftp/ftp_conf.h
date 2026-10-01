#ifndef FTP_CONF_H
#define FTP_CONF_H
/*
 * ftp_conf.h — ftp.conf 解析（FTP 服务器账号配置）
 *
 * 格式（INI 风格）：
 *   [云盘]
 *   host = ftp.example.com
 *   port = 21
 *   user = myuser
 *   password = mypass
 *   remote_dir = /
 *
 * 每个 [server] 段定义一个 FTP 服务器；段名即虚拟前缀与变量名来源
 * （FTP_<段名>，虚拟前缀 = /<段名>，FUSE 访问 /0/<段名>/... 直接命中）。
 * 支持 '#' 注释与空行；'=' 两侧允许空格。
 */
#include <stdbool.h>
#include <limits.h>

#define FTP_CONF_MAX_SERVERS 16 /* 初容（动态翻倍起点），不再是硬上限 */

/* FTP 服务器配置（FtpServerCfg：段名/连接/远程根） */
typedef struct FtpServerCfg {
    char name[64]; /* 服务器名（ftp.conf 段名）：虚拟前缀 /<name> + 变量名 FTP_<name> */
    char host[256];
    int port;
    char user[64];
    char pass[128];
    char remote_dir[512]; /* 远程根目录（默认 "/"） */
    bool bad; /* 解析期标记：任一字段超长被截断即整段作废（见 ftp_conf.c），不参与连接 */
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
