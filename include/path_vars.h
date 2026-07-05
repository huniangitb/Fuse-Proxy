#ifndef PATH_VARS_H
#define PATH_VARS_H
#include <stdbool.h>
#include <stddef.h>
#include "config_parser.h"

bool has_path_var(const char* s);
bool pkg_resolvable(const char* pkg);
bool is_system_abs_path(const char* path);
bool parse_var_assignment(const char* line, char* name, size_t nname, char* value, size_t nval);
size_t expand_path_vars(const char* in, char* out, size_t outsz,
                        const AppConfig* app_cfg, const AppConfig* global_cfg,
                        const char* current_pkg);
void analyze_var_staticness(AppConfig* cfg, const AppConfig* global_cfg);
bool build_real_base_from_target(const char* target, int user_id, char* real_base, size_t sz,
                                 const AppConfig* app_cfg, const AppConfig* global_cfg,
                                 const char* current_pkg);

#endif
