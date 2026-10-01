#ifndef NSP_UTIL_H
#define NSP_UTIL_H
/* nsp_util —— 轻量公共工具（纯 libc，无项目全局依赖）
 *
 * 归属约束：本头声明的函数不得引用 common.h 的全局（g_*）、日志系统与配置
 * 状态，以便各二进制（含不链接 common.c 的 rule_server）与 dlopen 热插拔
 * 模块（ftp_module 等）均可直接链接 src/core/nsp_util.c 复用，避免各文件
 * 各写一份 UDS 样板 / trim / mkdir -p / daemonize。
 */
#include <stdbool.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>

/* 去首尾空白（含 \r\n）：原地修改并返回首字符指针（ftp_conf trim 与
 * config_parser clean_path_string 的公共前半段） */
char* nsp_str_trim(char* s);

/* 全量发送循环（MSG_NOSIGNAL，内部重试 EINTR）：替代各处手写 while(send)。
 * 全部发出返回 true；出错或对端关闭返回 false（调用方自行决定是否关闭 fd）。 */
bool nsp_send_all(int fd, const char* buf, size_t len);

/* 填充抽象命名空间 UDS 地址并返回 bind/connect 长度：
 * 用法 struct sockaddr_un a; socklen_t n = nsp_uds_abstract_addr(&a, NAME); */
socklen_t nsp_uds_abstract_addr(struct sockaddr_un* addr, const char* name);

/* 递归建目录（最小实现，不继承 SELinux/属主；需属性继承用 common.c 的
 * mkdir_recursive_p）：替代 rule_server 私刻 mkdir_p */
int nsp_mkdir_p(const char* path, mode_t mode);

/* cgroup 逃逸（静默版：写入失败不打日志，调用方按需记录）：
 * 与 common.c escape_cgroup 同目标路径，供未链接 common.c 的进程复用 */
void nsp_escape_cgroup(void);

/* 双重 fork + setsid 后台化（含 SIGPIPE 忽略、关闭无关 fd、重定向标准流到
 * /dev/null）。preserve_fd >= 0 时保留该 fd（injector 保留全局根 fd）；
 * 传入 -1 则关闭全部。父进程直接 exit(0)，永不返回非零（失败 exit(1)）。 */
void nsp_daemonize(int preserve_fd);

/* 运行时线程语义化命名（/proc/<pid>/task/<tid>/comm）：各线程入口首行调用，
 * 替代默认继承的二进制程序名，便于崩溃日志 TID 归因与 top -H 排查。
 * 超 15 字节截断（TASK_COMM_LEN 上限），NULL/空串直接返回。 */
void nsp_set_thread_name(const char* name);

/* ---- 应用规则目录/文件路径合成（App-rules 家族）----
 *
 * config_dir 由调用方传入而非读取全局：编入多个二进制的 config_parser.c
 * 只链接 nsp_util 而不链接 common.c，不得依赖框架全局配置目录。
 * uid == 0 → <config_dir>/App-rules[/<pkg>.conf]；
 * uid != 0 → <config_dir>/App-rules-<uid>[/<pkg>.conf]。
 * 输出放不下时按 snprintf 语义截断（调用方按 PATH_MAX 级缓冲传入）。 */
void nsp_app_rule_dir(const char* config_dir, int uid, char* out, size_t sz);
void nsp_app_rule_path(const char* config_dir, int uid, const char* pkg, char* out, size_t sz);

/* 目录名是否属于 App-rules 家族（"App-rules" 或 "App-rules-<uid>"）：
 * 各目录扫描点（log_ctl/rule_server/config_publisher）共用，避免字面量漂移 */
bool nsp_is_app_rules_dirname(const char* name);

/* ---- 通用动态扩充（低内存快道 + 堆溢出）----
 *
 * 动机：散落的固定栈缓冲 + fgets/snprintf 截断是本仓最多的静默丢数据来源
 * （日志接收槽、配置长行切分、URL 合成等）。统一收敛到这三个原语：
 *  - 格式化需要精确大小时用 nsp_format_dynamic / nsp_snprintf_dyn：
 *    常见短输入走栈快道（零 malloc），超长才 malloc 精确大小；
 *  - 行式文件读取一律用 nsp_getline_capped：块内拼装 + 超长整行丢弃，
 *    长行永不裂成多条“碎片规则”（fgets 固定缓冲的经典错误）。
 * 纯 libc 实现（不依赖 common 全局/日志），模块亦可链接。 */

/* 动态格式化上限：单次格式化超过此值拒绝（防恶意 %s 撑爆内存）。
 * 与调用方传入的 max 取较小者生效；0 表只用本缺省。 */
#define NSP_DYN_FORMAT_MAX (1u * 1024u * 1024u)

/* 精确大小动态格式化：成功返回 malloc 缓冲（调用方 free），失败 NULL
 *（errno=ENOMEM / ENAMETOOLONG 超 max）。max=0 用缺省上限。 */
char* nsp_format_dynamic(size_t max, const char* fmt, ...);
char* nsp_vformat_dynamic(size_t max, const char* fmt, va_list ap);

/* 栈快道 + 堆溢出格式化：先试 fixed，放不下则 malloc 精确大小存入 *heap_out。
 * 返回 snprintf 语义的 need（≥0）；*heap_out=NULL 表内容在 fixed 内，
 * 非 NULL 表内容在堆内（调用方 free）。max 语义同上；出错返回负值。 */
int nsp_snprintf_dyn(char* fixed, size_t fixed_sz, char** heap_out, size_t max,
                     const char* fmt, ...);

/* 有界动态行读取：返回 1=读到有效行（换行已剥，行在 *buf，长度经 *out_len
 * 给出，可 NULL；空行亦返回 1 且长度为 0）；
 * 0=EOF（无更多行）；-1=I/O 或 OOM 错误；-2=超长整行已丢弃
 * （已消费至行尾/文件尾，调用方告警后跳过——与“超长行不参与匹配”对齐）。
 * *buf 按需 realloc 扩容（初值 NULL 且 *cap=0），峰值内存 ≤ max+块大小；
 * max=0 表不限制（仅用于必须保真的编辑器回写路径，慎用）。 */
int nsp_getline_capped(FILE* fp, char** buf, size_t* cap, size_t max, size_t* out_len);

/* 配置开关取值：**ON/1 为开，其余（含 NULL、缺省、OFF）一律为关**。
 * 这是 MONITOR / SANDBOX / GLOBAL_INJECT 等开关类规则词法的唯一出处——
 * 模块侧 parse_switch_rule 与框架侧 fw_config_monitor_for 的三层合并共用，
 * 防止 "ON"/"1" 字面量在各处漂移（漏写 "1" 会让 `MONITOR 1` 静默失效）。 */
bool nsp_switch_on(const char* val);

#endif
