#ifndef NSP_UTIL_H
#define NSP_UTIL_H
/* nsp_util —— 轻量公共工具（纯 libc，无项目全局依赖）
 *
 * 归属约束：本头声明的函数不得引用 common.h 的全局（g_*）、日志系统与配置
 * 状态，以便各二进制（含不链接 common.c 的 rule_server）与 dlopen 热插拔
 * 模块（ftp_module 等）均可直接链接 src/core/nsp_util.c 复用，避免各文件
 * 各写一份 UDS 样板 / trim / mkdir -p / daemonize。
 */
#include <stddef.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>

/* 去首尾空白（含 \r\n）：原地修改并返回首字符指针（ftp_conf trim 与
 * config_parser clean_path_string 的公共前半段） */
char *nsp_str_trim(char *s);

/* 全量发送循环（MSG_NOSIGNAL）：替代各处手写 while(send)（rule_server 等） */
void nsp_send_all(int fd, const char *buf, size_t len);

/* 填充抽象命名空间 UDS 地址并返回 bind/connect 长度：
 * 用法 struct sockaddr_un a; socklen_t n = nsp_uds_abstract_addr(&a, NAME); */
socklen_t nsp_uds_abstract_addr(struct sockaddr_un *addr, const char *name);

/* 递归建目录（最小实现，不继承 SELinux/属主；需属性继承用 common.c 的
 * mkdir_recursive_p）：替代 rule_server 私刻 mkdir_p */
int nsp_mkdir_p(const char *path, mode_t mode);

/* cgroup 逃逸（静默版：写入失败不打日志，调用方按需记录）：
 * 与 common.c escape_cgroup 同目标路径，供未链接 common.c 的进程复用 */
void nsp_escape_cgroup(void);

/* 双重 fork + setsid 后台化（含 SIGPIPE 忽略、关闭无关 fd、重定向标准流到
 * /dev/null）。preserve_fd >= 0 时保留该 fd（injector 保留全局根 fd）；
 * 传入 -1 则关闭全部。父进程直接 exit(0)，永不返回非零（失败 exit(1)）。 */
void nsp_daemonize(int preserve_fd);

#endif
