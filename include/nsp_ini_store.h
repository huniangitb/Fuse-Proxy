#ifndef NSP_INI_STORE_H
#define NSP_INI_STORE_H
/*
 * nsp_ini_store.h — INI 段式配置文件行级存储
 *
 * 定位：纯 libc、零项目全局依赖的公共设施。**已退出模块 ABI**（模块 ABI V2
 * 起）：本实现只编入 rule_server（私有静态库），fuse_daemon 导出表不再提供
 * nsp_ini_* 符号，故第三方模块**不得**引用本 API——引用会在 dlopen 阶段因
 * 符号无法解析而被拒（详见 docs/modules.md §6.1）。模块侧请用 nsp_util 的
 * 行处理原语自建存储。
 *
 * 当前唯一使用者是 rule_server 控制面，实现"注释保留的行级读写"：
 *   - 读：按 [段名] / key 取值（value 语义与 ftp_conf 对齐：剥离行内 `#`
 *     注释后去首尾空白）；
 *   - 写：set/del 保持注释与空行原样，仅改目标行；save 经临时文件 + rename
 *     原子落盘（inotify 监听端永不读到半截文件）。
 *
 * 非目标：ON/OFF 后缀段头（如 [USER_APPS:0] OFF）超出通用范畴，
 * 仍由各调用方自备匹配器；重复段仅操作首个命中（调用方应避免写重复段）。
 */
#include <stdbool.h>
#include <stddef.h>

#include "nsp_constants.h"

/* 可解析行上限（= 配置规范单行上限，超长行原样保留但不参与段/键匹配） */
#define NSP_INI_MAX_LINE NSP_CONFIG_LINE_MAX

/* 不透明句柄（内部行数组可演进，不影响 ABI） */
typedef struct NspIniStore NspIniStore;

#ifdef __cplusplus
extern "C" {
#endif

/* 打开存储：只有文件不存在（ENOENT）视为空存储（路径已记住，set 后 save
 * 即创建）；参数非法/OOM/读取失败（EACCES/EMFILE/EIO 等，含读到一半失败）
 * 均返回 NULL 并保留 errno。调用方不得把 NULL 当空存储继续 save——那会用只含
 * 本次条目的内容覆盖整份文件。 */
NspIniStore* nsp_ini_open(const char* path);
void nsp_ini_close(NspIniStore* s);
const char* nsp_ini_path(const NspIniStore* s);

/* 段遍历（file 出现顺序，含 [GLOBAL] 等一切段头） */
int nsp_ini_section_count(const NspIniStore* s);
const char* nsp_ini_section_name(const NspIniStore* s, int idx);  /* 越界返回 NULL */
int nsp_ini_find_section(const NspIniStore* s, const char* name); /* 精确匹配，-1=无 */

/* 段内键遍历 */
int nsp_ini_key_count(const NspIniStore* s, int sec_idx);
const char* nsp_ini_key_name(const NspIniStore* s, int sec_idx, int key_idx);

/* 取值：0=命中（out 写入剥注释去空白后的值，out 可为 NULL 表仅探测存在性），
 * -1=段/键不存在 */
int nsp_ini_get(const NspIniStore* s, const char* section, const char* key, char* out, size_t sz);

/* 设值：段/键不存在则分别追加（段追文件尾、键追段尾），存在则首命中行改写为
 * `key = value` 规范形式；0=成功，-1=参数非法/OOM */
int nsp_ini_set(NspIniStore* s, const char* section, const char* key, const char* value);
/* 删键：0=已删，-1=不存在 */
int nsp_ini_del_key(NspIniStore* s, const char* section, const char* key);
/* 删段：连段头与其下属行一并移除（首命中段块）；0=已删，-1=不存在 */
int nsp_ini_del_section(NspIniStore* s, const char* section);

/* 原子落盘（tmp+rename）：0=成功，-1=IO 失败（原文件不动） */
int nsp_ini_save(const NspIniStore* s);

/* 通用合法性：非空、去空白后非空、不含 \n \r [ ]（段名/键名通用）；
 * 键名另禁 `=`；长度上限：段名/键名 255，值 2047（调用方可再收紧，如 FTP
 * 段名 ≤63 受 FtpServerCfg.name[64] 约束） */
bool nsp_ini_valid_section(const char* name);
bool nsp_ini_valid_key(const char* key);
bool nsp_ini_valid_value(const char* value);

#ifdef __cplusplus
}
#endif

#endif /* NSP_INI_STORE_H */
