#ifndef NSP_RULE_FILE_H
#define NSP_RULE_FILE_H
/*
 * nsp_rule_file.h — 规则配置文件的行级读写（公共抽象）
 *
 * 定位：与 nsp_util / nsp_ini_store 同约束的公共设施（纯 libc，零项目全局
 * 依赖），供规则控制面（rule_server）与 CLI（log_ctl）共用，消除两处各自
 * 私刻的行数组原语与段编辑逻辑。
 *
 * 覆盖两类写入形态：
 *   1. 段式文件（injector.conf）：[GLOBAL] / [USER_APPS:<uid>] / [SYSTEM_APPS]
 *      段内的开关与规则行；
 *   2. 无段文件（App-rules/<pkg>.conf）：整文件范围的开关替换与规则去重追加。
 *
 * 语义基准：以 rule_server 为准（它是权威控制面，其索引语义与 LIST 输出一致）。
 * 具体地：
 *   - 开关行在作用域内唯一：就地替换首个同类型行，无则插入（段式：段头后；
 *     无段：文件尾）；
 *   - 规则行去重范围为**整个文件**（同一行不在文件内出现两次）；
 *   - 按 (类型, 索引) 删除时索引**计入已停用行**（# 前缀），与 LIST 一致；
 *   - 落盘一律 tmp+rename 原子写，inotify 监听端永不读到半截文件。
 *
 * 所有写入函数在目标文件不存在时按空文件处理并创建之；**父目录须由调用方
 * 先行创建**（调用方掌握配置根目录语义，见各调用点的 mkdir）。
 *
 * 行缓冲以换行结尾（与写入格式一致），比较按整行 strcmp。
 */
#include <stdbool.h>
#include <stddef.h>

/* 返回值：0 成功；负值为错误码（与模块 ABI 的"负值错误"约定一致） */
#define NSP_RULE_FILE_OK      0
#define NSP_RULE_FILE_EINVAL  (-1) /* 参数非法 / 内存不足 */
#define NSP_RULE_FILE_ENOTFND (-2) /* 段或规则行未找到 */
#define NSP_RULE_FILE_EIO     (-3) /* 文件读写失败 */

/* 段头匹配方式（见 nsp_rule_file_upsert_in_section） */
typedef enum {
    /* 精确段头文本匹配，允许其后跟空白或 ON/OFF 后缀（[USER_APPS:0] OFF）。
       用于类别段——避免把 [USER_APPS] 与 [USER_APPS:0] 混淆。 */
    NSP_RULE_SEC_EXACT = 0,
    /* 段名前缀匹配，接受 [name] 与 [name:...] 两种形态（配置规范里的 [GLOBAL]
       兼容带参数的写法）。用于 GLOBAL 段。 */
    NSP_RULE_SEC_PREFIX = 1,
} NspRuleSectionMatch;

/* ==================== 行数组原语 ==================== */

/* 读取文件为行数组（保留行内空白与换行，不做 trim）。每行 strdup。
 * 文件不存在或读取失败：*out_count = *out_cap = 0，返回 NULL（调用方按空文件处理）。
 * 成功返回数组（调用方经 nsp_rule_file_free 释放）。 */
char** nsp_rule_file_read(const char* path, int* out_count, int* out_cap);

/* 原子落盘：写 <path>.tmp → fsync → rename。失败时清理 tmp 并保留原文件。
 * true = 成功，false = 失败（errno 有效）。 */
bool nsp_rule_file_write(const char* path, char** lines, int count);

/* 释放行数组（count 为元素数；lines 可为 NULL） */
void nsp_rule_file_free(char** lines, int count);

/* 在 pos 处插入 text 的副本，返回新行数；失败返回 NSP_RULE_FILE_EINVAL。
 * 容量不足时按需 realloc（*cap 原地更新）。 */
int nsp_rule_file_insert(char*** lines, int* cap, int count, int pos, const char* text);

/* 删除 pos 处的行（越界为空操作） */
void nsp_rule_file_remove(char** lines, int* count, int pos);

/* 追加 text 的副本到末尾，返回新行数；失败返回 NSP_RULE_FILE_EINVAL */
int nsp_rule_file_append(char*** lines, int* cap, int count, const char* text);

/* ==================== 段与类型匹配 ==================== */

/* 段头 [name] 或 [name:...] 的行号；未找到返回 NSP_RULE_FILE_ENOTFND */
int nsp_rule_file_find_section(char** lines, int count, const char* name);

/* 精确段头文本匹配（允许尾部空白或 ON/OFF 后缀，且须有边界——[USER_APPS:0]OFFX
 * 不算段头）；未找到返回 NSP_RULE_FILE_ENOTFND */
int nsp_rule_file_find_header(char** lines, int count, const char* hdr_text);

/* 段头之后、下一个段头之前查找开关行（大小写不敏感，类型名后须为空白/行尾）；
 * 未找到返回 NSP_RULE_FILE_ENOTFND */
int nsp_rule_file_find_switch(char** lines, int count, int header_idx, const char* type);

/* 类别段判定：[USER_APPS] / [SYSTEM_APPS]（大小写敏感，与 config_parser 一致） */
bool nsp_rule_file_is_category_pkg(const char* pkg);

/* 类别段名（不含方括号）：USER_APPS 恒带显式 :uid（uid<0 视为 0），
 * SYSTEM_APPS 无参。写入方经 nsp_rule_file_upsert_in_section 使用时由后者
 * 补方括号。 */
void nsp_rule_file_category_name(const char* pkg, int uid, char* out, size_t sz);

/* 该行是否是指定类型的规则行：跳过前导空白与可选 '#' 停用标记后按类型名
 * 大小写不敏感匹配，类型名后须为空白或行尾（避免 HIDE 匹配到 HIDEX） */
bool nsp_rule_file_line_is_type(const char* line, const char* type_name);

/* 定位第 index 条 type_name 规则的行号（**计入已停用行**，与 LIST 索引一致）；
 * 未找到返回 NSP_RULE_FILE_ENOTFND */
int nsp_rule_file_find_nth(char** lines, int count, const char* type_name, int index);

/* ==================== 段式文件写入 ==================== */

/* 在段内写入开关或规则行（injector.conf 的 GLOBAL / 类别段）。
 *
 *   sec_name    段名（不含方括号），如 "GLOBAL" / "USER_APPS:0" / "SYSTEM_APPS"。
 *               段头行由本函数按 "[sec_name]\n" 构造
 *   sec_match   段头匹配方式（GLOBAL 用 PREFIX 以兼容 [GLOBAL:...]；类别段用
 *               EXACT，避免把 [USER_APPS] 与 [USER_APPS:0] 混淆）
 *   is_switch   true=开关行（段内就地替换，无则插段头后）；
 *               false=规则行（全文件去重后插段头后）
 *   type_name   开关行的类型名（仅 is_switch 时用于段内定位，如 "MONITOR"）
 *   line        待写入的整行（须含结尾换行）
 *   out_changed 是否实际改动了文件（可 NULL）；内容已存在时返回成功但 false
 *
 * 段头缺失时追加 "段头 + 行" 到文件尾。0=成功；负值为错误码。 */
int nsp_rule_file_upsert_in_section(const char* path, const char* sec_name,
                                    NspRuleSectionMatch sec_match, bool is_switch,
                                    const char* type_name, const char* line, bool* out_changed);

/* ==================== 无段文件写入 ==================== */

/* 在无段结构文件（App-rules/<pkg>.conf）中写入开关或规则行：
 *   is_switch  true=就地替换文件中首个同类型开关行（保持唯一），无则追加；
 *              false=全文件去重后追加
 * 0=成功（*out_changed 表是否改动）；负值为错误码。 */
int nsp_rule_file_upsert_line(const char* path, bool is_switch, const char* type_name,
                              const char* line, bool* out_changed);

/* ==================== 按 (类型, 索引) 删除 ==================== */

/* 删除第 index 条 type_name 规则（索引计入已停用行）。
 * out_removed 非 NULL 时写入被删行的副本（截断到 removed_sz，含换行）。
 * 0=成功；NSP_RULE_FILE_ENOTFND=未找到该索引；负值为错误码。 */
int nsp_rule_file_remove_nth(const char* path, const char* type_name, int index, char* out_removed,
                             size_t removed_sz);

#endif /* NSP_RULE_FILE_H */
