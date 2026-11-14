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

/* 读取文件为行数组（保留行内空白，不做 trim）。每行 strdup。
 * 行尾换行已归一：文件末行缺少 \n 时会补齐，故数组内每行均以 \n 结尾
 * （避免"插到末行之后"的写入与之粘连成同一行）。
 * 文件不存在或读取失败：*out_count = *out_cap = 0，返回 NULL（调用方按空文件处理）。
 * 成功返回数组（调用方经 nsp_rule_file_free 释放）。
 * **注意**：NULL 同时表示「不存在」与「读失败」——编辑类入口须改用
 * nsp_rule_file_read_ex 区分，否则读失败会被当空文件、用「段头 + 1 条」覆盖
 * 整份规则文件（历史审计项 A10：读失败当空文件覆盖）。本函数保留给只读视图使用。 */
char** nsp_rule_file_read(const char* path, int* out_count, int* out_cap);

/* 同 nsp_rule_file_read，但经 out_err 区分「文件不存在」与「读取失败」：
 *   *out_err == 0           读取成功（空文件亦为 0，lines 可为 NULL / count 0）
 *   *out_err == ENOENT      文件不存在（可安全按空文件处理并新建）
 *   *out_err == 其他 errno  真失败（EACCES/EIO/ENOMEM…）
 * 编辑类入口在真失败时**必须放弃写入**并返回错误，不得覆盖既有文件。 */
char** nsp_rule_file_read_ex(const char* path, int* out_count, int* out_cap, int* out_err);

/* 原子落盘（写 <path>.tmp → fsync → rename → 目录 fsync）由本文件内部独占，
 * **不对外暴露**：对外唯一的写入路径是 nsp_rule_file_edit（见下），它把
 * 「取目录 flock → 读 → 改 → 原子写回」封成事务，使调用方在结构上无法拼出
 * 不带锁的读改写（§C6）。只读视图仍可经 nsp_rule_file_read/read_ex 获取。 */

/* 释放行数组（count 为元素数；lines 可为 NULL） */
void nsp_rule_file_free(char** lines, int count);

/* 在 pos 处插入 text 的副本，返回新行数；失败返回 NSP_RULE_FILE_EINVAL。
 * 容量不足时按需 realloc（*cap 原地更新）。 */
int nsp_rule_file_insert(char*** lines, int* cap, int count, int pos, const char* text);

/* 删除 pos 处的行（越界为空操作） */
void nsp_rule_file_remove(char** lines, int* count, int pos);

/* 追加 text 的副本到末尾，返回新行数；失败返回 NSP_RULE_FILE_EINVAL */
int nsp_rule_file_append(char*** lines, int* cap, int count, const char* text);

/* ==================== 唯一编辑入口（持锁读-改-写事务） ==================== */

/* 编辑回调：在目录 flock 事务内被调用（见 nsp_rule_file_edit）。
 *
 *   lines / count / cap : 当前文件的行数组。*lines 可被替换、*cap 随之更新
 *                         （nsp_rule_file_insert/append 扩容时会就地更新 *cap）。
 *                         每行以 \n 结尾，元素由 strdup 分配。
 *   ctx                 : 调用方上下文（原样透传）
 *   out_changed         : 回调置为「是否修改了行数组」；false 时事务跳过落盘
 *
 * 返回 NSP_RULE_FILE_OK 时由事务负责原子写回；负值 = 错误码（事务放弃写入，
 * 原文件保持不动）。**回调不得自行读写文件或取锁**——读入与写回统一由事务
 * 承担，这正是「忘记取锁」在结构上不可能发生的原因（§C6）。
 * 回调返回后行数组由事务释放，回调不得留存其指针。 */
typedef int (*NspRuleFileEditFn)(char*** lines, int* count, int* cap, void* ctx,
                                 bool* out_changed);

/* 规则文件编辑的**唯一入口**：取目录 flock → 读全文 → 调 fn → 原子写回 → 放锁。
 * 段式/无段 upsert、按索引删除、启用切换（及未来新增命令）全部是本原语的回调
 * 实现，故不存在「读-改-写却没取锁」的调用侧路径（§C6）。
 * 锁不可用时按 fail-open 继续（绝不因锁不可用而拒绝编辑）。
 * 读失败（非 ENOENT）时**不调用 fn**、不写文件，返回 NSP_RULE_FILE_EIO。
 * 0=成功（*out_changed 表是否实际改动并落盘）；负值为错误码。 */
int nsp_rule_file_edit(const char* path, NspRuleFileEditFn fn, void* ctx, bool* out_changed);

/* ==================== 段与类型匹配 ==================== */

/* 段头 [name] 或 [name:...] 的行号；未找到返回 NSP_RULE_FILE_ENOTFND */
int nsp_rule_file_find_section(char** lines, int count, const char* name);

/* 精确段头文本匹配（允许尾部空白或 ON/OFF 后缀，且须有边界——[USER_APPS:0]OFFX
 * 不算段头）；未找到返回 NSP_RULE_FILE_ENOTFND。
 * hdr_text 须为**不含换行**的段头文本（如 "[USER_APPS:0]"）：带 \n 会因"其后
 * 须为空白/ON/OFF"的判定与行内空白不再相等而失配。 */
int nsp_rule_file_find_header(char** lines, int count, const char* hdr_text);

/* 段头之后、下一个段头之前查找开关行（大小写不敏感，类型名后须为空白/行尾）；
 * 未找到返回 NSP_RULE_FILE_ENOTFND */
int nsp_rule_file_find_switch(char** lines, int count, int header_idx, const char* type);

/* 类别段判定：[USER_APPS] / [SYSTEM_APPS]（大小写敏感，与 config_parser 一致） */
bool nsp_rule_file_is_category_pkg(const char* pkg);

/* 应用规则**当前生效文件**的路径合成（rule_server 与 log_ctl 共用的唯一实现）：
 *   <pkg>.conf 存在（启用）→ 返回它；否则 <pkg>.conf.disabled 存在（停用）→
 *   返回它；两者皆无 → 返回 base <pkg>.conf（新建时用）。
 * 编辑（ADD/SET/REMOVE/TOGGLE）必须走这里：直接写 base <pkg>.conf 会在应用处于
 * 停用状态时新建一个 .conf，按解析语义（存在 .conf 即启用）等于静默把注入重新
 * 打开，同时 .disabled 里的规则被丢在一边。 */
void nsp_rule_file_app_active_path(const char* config_dir, int uid, const char* pkg, char* out,
                                   size_t sz);

/* 类别段名（不含方括号）：USER_APPS 恒带显式 :uid（uid<0 视为 0），
 * SYSTEM_APPS 无参。写入方经 nsp_rule_file_upsert_in_section 使用时由后者
 * 补方括号。 */
void nsp_rule_file_category_name(const char* pkg, int uid, char* out, size_t sz);

/* 该行是否是指定类型的规则行：跳过前导空白与可选 '#' 停用标记后按类型名
 * 大小写不敏感匹配，类型名后须为空白或行尾（避免 HIDE 匹配到 HIDEX） */
bool nsp_rule_file_line_is_type(const char* line, const char* type_name);

/* 定位第 index 条 type_name 规则的行号（**计入已停用行**，与 LIST 索引一致）；
 * 未找到返回 NSP_RULE_FILE_ENOTFND。
 * 索引为**整文件**全局序号——仅适用于无段文件（App-rules/<pkg>.conf）。段式文件
 * 请改用 nsp_rule_file_find_nth_scoped，否则与 GET 的段内索引口径不一致（§A5）。 */
int nsp_rule_file_find_nth(char** lines, int count, const char* type_name, int index);

/* ==================== 作用域（段内索引口径） ==================== */

/* 规则作用域：把「第 index 条」限定在某个段覆盖的行区间内，使编辑入口的索引
 * 口径与 GET/LIST 的展示索引一致（GET 类别段只回段内切片、GET GLOBAL 只回
 * [GLOBAL] 段——见 rule_server 的 build_category_json / build_global_json）。
 *
 *   sec_name == NULL  → 整文件（无段文件 App-rules/<pkg>.conf）；
 *   sec_name != NULL  → 该段覆盖的行区间，区间形状由 sec_match 决定：
 *     · NSP_RULE_SEC_PREFIX（GLOBAL）：**文件起始**到首个非本段段头；本段段头
 *       自身透明（不计为边界）。与解析器语义一致——首个段头之前的规则与
 *       [GLOBAL] 段内的规则同归全局（config_parser.c 的 cur 初值为
 *       &g_global_cfg_stage）。
 *     · NSP_RULE_SEC_EXACT（类别段）：精确段头之后到下一段头之前。
 *
 * 行首为 '[' 的行一律视为段边界（与既有切片实现一致；畸形段头同样断段）。 */
typedef struct {
    const char* sec_name; /* NULL = 整文件 */
    NspRuleSectionMatch sec_match;
} NspRuleScope;

/* 计算 scope 覆盖的行区间 [*out_beg, *out_end)（end 为独占上界）。
 * 整文件作用域恒成功；EXACT 段头缺失（段不存在）返回 false，出参不动。 */
bool nsp_rule_file_scope_range(char** lines, int count, const NspRuleScope* scope, int* out_beg,
                               int* out_end);

/* 在 scope 内定位第 index 条 type_name 规则的行号（计入已停用行）。
 * scope 为 NULL 或 sec_name 为 NULL 时等价于 nsp_rule_file_find_nth（整文件）。
 * 未找到返回 NSP_RULE_FILE_ENOTFND。 */
int nsp_rule_file_find_nth_scoped(char** lines, int count, const NspRuleScope* scope,
                                  const char* type_name, int index);

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

/* 同 nsp_rule_file_remove_nth，但索引限定在 scope 内（scope 为 NULL 时整文件）。
 * 全程持目录 flock 串行化读-改-写（§A6）。 */
int nsp_rule_file_remove_nth_scoped(const char* path, const NspRuleScope* scope,
                                    const char* type_name, int index, char* out_removed,
                                    size_t removed_sz);

/* ==================== 启用/停用（# 注释切换） ==================== */

/* 切换 scope 内第 index 条 type_name 规则的启用状态（索引计入已停用行）。
 *   enable=true  → 去掉行首 '#'（及其后空白）
 *   enable=false → 在行首插入 '#'（行变长，内部重建缓冲）
 * out_line 非 NULL 时写入改后整行（截断到 out_sz）；out_changed 表是否实际改动
 * （已处于目标状态时返回成功、false，且不落盘）。
 * 经 nsp_rule_file_edit 事务（唯一编辑入口，全程持目录 flock）——库不再对外
 * 暴露无锁写路径，调用侧无从拼出「读全文→改一行→覆盖写」（§C6）。
 * 0=成功；NSP_RULE_FILE_ENOTFND=未找到该索引；负值为错误码。 */
int nsp_rule_file_toggle_nth_scoped(const char* path, const NspRuleScope* scope,
                                    const char* type_name, int index, bool enable, char* out_line,
                                    size_t out_sz, bool* out_changed);

#endif /* NSP_RULE_FILE_H */
