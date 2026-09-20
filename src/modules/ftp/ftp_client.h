#ifndef FTP_CLIENT_H
#define FTP_CLIENT_H
/*
 * ftp_client.h — 最小 FTP 客户端（RFC 959 核心子集）
 *
 * 供 ftp_module 的 FTP-FUSE 使用：控制连接（USER/PASS/TYPE/PASV）、
 * 数据连接传输（LIST/RETR/STOR）、文件操作（DELE/MKD/RMD/RNFR/RNTO/SIZE/MDTM）。
 * 每次高层操作复用连接；失败返回负值，详情见 last_code / last_reply。
 */
#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>
#include <time.h>

typedef struct FtpConn {
    int ctrl_fd;           /* 控制连接 fd（-1 = 未连接） */
    int timeout_s;         /* 网络超时（秒） */
    int last_code;         /* 最近响应码（如 220/230/226/550） */
    char last_reply[2048]; /* 最近完整响应文本 */
    char pasv_host[256];   /* 原服务器主机名（PASV 数据连接使用，防返回不可达 IP） */
} FtpConn;

/* 连接 + 登录（匿名 user="anonymous"）。返回 0 成功；负值失败。 */
int ftp_connect(FtpConn* c, const char* host, int port, const char* user, const char* pass,
                int timeout_s);
void ftp_close(FtpConn* c);

/* 发一条命令并读完整响应；返回响应码（>=0），网络错误返回负值 */
int ftp_cmd(FtpConn* c, const char* cmd, const char* arg);

/* 被动模式数据连接：解析 PASV 端口并连接，随后发送传输命令
   （cmd = "LIST"/"RETR"/"STOR"，arg = 远程路径）。
   rest_off >= 0 时先发 REST（断点续传，仅 RETR 用）。
   返回数据 fd（调用方传输后须 ftp_data_finish）。失败返回负值。 */
int ftp_data_open(FtpConn* c, const char* cmd, const char* path, long long rest_off);
/* 等待数据传输完成（读 226）。返回 0 成功。 */
int ftp_data_finish(FtpConn* c);

/* ---- 高层操作（均为"完整往返"，内部用 ftp_data_open/finish） ---- */

/* 列出远程目录（LIST -la），原始文本写入 out（调用方 free）。返回 0 成功。 */
int ftp_list(FtpConn* c, const char* path, char** out, size_t* out_len);
/* 读远程文件一段：从 off 起读最多 size 字节到 buf，实际读入 *got。返回 0 成功。 */
int ftp_retr(FtpConn* c, const char* path, long long off, char* buf, size_t size, size_t* got);
/* 全量上传 buf 到远程文件（覆盖）。返回 0 成功。 */
int ftp_stor(FtpConn* c, const char* path, const char* buf, size_t size);
/* SIZE 查询。返回 0 成功，*size_out 填大小。 */
int ftp_size(FtpConn* c, const char* path, long long* size_out);
/* MDTM 查询。返回 0 成功，*out 填 mtime。 */
int ftp_mdtm(FtpConn* c, const char* path, time_t* out);
int ftp_dele(FtpConn* c, const char* path);                   /* 删除文件 */
int ftp_mkd(FtpConn* c, const char* path);                    /* 建目录 */
int ftp_rmd(FtpConn* c, const char* path);                    /* 删空目录 */
int ftp_rename(FtpConn* c, const char* from, const char* to); /* 重命名/移动 */

/* ---- LIST 输出解析（vsftpd 默认 Unix 风格） ---- */

typedef struct FtpEntry {
    char name[256];
    bool is_dir;
    long long size;
    time_t mtime;
} FtpEntry;

/* 解析 LIST -la 文本为条目数组，返回条目数（<= max；"."/".." 剔除） */
int ftp_parse_list(const char* text, FtpEntry* entries, int max);

#endif /* FTP_CLIENT_H */
