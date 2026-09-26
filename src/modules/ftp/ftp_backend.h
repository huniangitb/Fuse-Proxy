#ifndef FTP_BACKEND_H
#define FTP_BACKEND_H
/*
 * ftp_backend.h — FTP 存储后端操作方法（纯方法，无 FUSE 实现）
 *
 * 供 ftp_module.so（唯一形态：后端存储提供者，见 nsp_module.h）使用：
 * 只提供"目标功能（FTP）的操作方法"，由 fuse_daemon 框架在路径命中
 * （backend_match）时调用，最终执行（FUSE 回调）仍由框架实现。
 *
 * 虚拟前缀 = "/" + <服务器段名>（如 /云盘）：FUSE 剥离 /0/ 后的原始路径
 * （/云盘/xxx）直接命中，无需 REDIRECT 规则或变量。
 * 路径映射：前缀剥离 + remote_dir 拼接（如 /云盘/x → /upload/x）。
 *
 * 写路径沿用"本地临时文件缓存 + release 时 STOR 全量上传"（FTP 无随机写）。
 */
#include "ftp_conf.h"
#include "nsp_module.h"

/* 注册/清理后端（ftp_module.c 解析 ftp.conf 后调用）。
   虚拟前缀 = "/" + cfg->name（如 /云盘）：FUSE 剥离 /0/ 后的原始路径
   （/云盘/xxx）直接命中，无需 REDIRECT 规则或变量。 */
int ftp_backend_add(const FtpServerCfg* cfg);
void ftp_backend_clear(void);
int ftp_backend_count(void);
/* 每分钟重连探活：对每个后端尝试 FTP 连接（服务器恢复后无需重启模块） */
void ftp_backend_retry_all(void);

/* ---- NspModuleOps.backend_* 实现（由框架调用） ---- */
int ftp_backend_match(const char* path);
int ftp_backend_getattr(const char* path, struct stat* st);
int ftp_backend_readdir(const char* path, NspDirEntry* entries, int max);
int ftp_backend_open(const char* path, int flags, uint64_t* h);
int ftp_backend_read(uint64_t h, char* buf, size_t size, off_t off, size_t* got);
int ftp_backend_write(uint64_t h, const char* buf, size_t size, off_t off, size_t* wrote);
int ftp_backend_flush(uint64_t h);
int ftp_backend_release(uint64_t h);
int ftp_backend_create(const char* path, mode_t mode, uint64_t* h);
int ftp_backend_unlink(const char* path);
int ftp_backend_mkdir(const char* path, mode_t mode);
int ftp_backend_rmdir(const char* path);
int ftp_backend_rename(const char* from, const char* to);
int ftp_backend_truncate(const char* path, off_t size);

#endif /* FTP_BACKEND_H */
