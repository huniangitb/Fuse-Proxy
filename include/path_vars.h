#ifndef PATH_VARS_H
#define PATH_VARS_H
#include <stdbool.h>
#include <stddef.h>
#include "config_parser.h"

bool has_path_var(const char* s);
bool pkg_resolvable(const char* pkg);
bool is_system_abs_path(const char* path);
/* 外部存储根别名归一：/storage/emulated/<N>、/sdcard、/mnt/sdcard →
   以 '/' 开头的剩余路径（根为 "/"）；其余输入原样返回。 */
const char* nsp_strip_storage_prefix(const char* path);

/* NAME=VALUE 赋值解析。返回：
 *    1 = 是赋值行且解析成功（name/value 已填充）
 *    0 = 不是赋值行（调用方按规则行继续解析）
 *   -1 = 是赋值行但**值放不下** value[nval]（调用方应告警并丢弃该行：截断的值会让
 *        后续 $变量 展开得到更短前缀，规则匹配范围被放大——违反「放不下返回错误
 *        而非截断」红线）。 */
int parse_var_assignment(const char* line, char* name, size_t nname, char* value, size_t nval);

/* 展开 $变量 到 out。返回 true=完整写入；false=结果放不下 outsz（**已截断**，
 * out 仍以 NUL 结尾）。调用方须按 fail-closed 处理：规则匹配场景丢弃该规则、
 * 路径合成场景返回失败——截断后的前缀会放大规则范围（HIDE/RO 命中更多路径）。 */
bool expand_path_vars(const char* in, char* out, size_t outsz,
                      const AppConfig* app_cfg, const AppConfig* global_cfg,
                      const char* current_pkg);
void analyze_var_staticness(AppConfig* cfg, const AppConfig* global_cfg);
bool build_real_base_from_target(const char* target, int user_id, char* real_base, size_t sz,
                                 const AppConfig* app_cfg, const AppConfig* global_cfg,
                                 const char* current_pkg);

#endif