#include "path_vars.h"
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fail = 0;
#define CHECK(cond) do { if (!(cond)) { printf("FAIL line %d: %s\n", __LINE__, #cond); g_fail++; } } while(0)

static void test_has_path_var(void) {
    CHECK(has_path_var("/sdcard/$package/files") == true);
    CHECK(has_path_var("${base}/x") == true);
    CHECK(has_path_var("/sdcard/Android/data") == false);
    CHECK(has_path_var("") == false);
    CHECK(has_path_var(NULL) == false);
    CHECK(has_path_var("price=10") == false);
}

static void test_pkg_resolvable(void) {
    CHECK(pkg_resolvable(NULL) == false);
    CHECK(pkg_resolvable("") == false);
    CHECK(pkg_resolvable("system") == false);
    CHECK(pkg_resolvable("unknown") == false);
    CHECK(pkg_resolvable("com.foo") == true);
}

static void test_is_system_abs_path(void) {
    /* 根目录本身（无尾部斜杠） */
    CHECK(is_system_abs_path("/data") == true);
    CHECK(is_system_abs_path("/mnt") == true);
    CHECK(is_system_abs_path("/storage") == true);
    /* 带子路径 */
    CHECK(is_system_abs_path("/data/foo/bar") == true);
    CHECK(is_system_abs_path("/mnt/sdcard") == true);
    CHECK(is_system_abs_path("/storage/self") == true);
    /* 非系统根目录 */
    CHECK(is_system_abs_path("/sdcard") == false);
    CHECK(is_system_abs_path("/sdcard/foo") == false);
    CHECK(is_system_abs_path("/Android/data") == false);
    CHECK(is_system_abs_path("Android/data") == false);
    CHECK(is_system_abs_path("/") == false);
    CHECK(is_system_abs_path(NULL) == false);
    /* /datafoo 不应识别为 /data 根 */
    CHECK(is_system_abs_path("/datafoo") == false);
}

static void test_parse_var_assignment(void) {
    char name[128], val[256];
    /* 合法紧凑形式 */
    CHECK(parse_var_assignment("MY_DIR=/sdcard/x", name, sizeof name, val, sizeof val) == true);
    CHECK(strcmp(name, "MY_DIR") == 0);
    CHECK(strcmp(val, "/sdcard/x") == 0);
    /* VALUE 含空格与变量 */
    CHECK(parse_var_assignment("BASE=/sdcard/$package/files", name, sizeof name, val, sizeof val) == true);
    CHECK(strcmp(name, "BASE") == 0);
    CHECK(strcmp(val, "/sdcard/$package/files") == 0);
    /* 带前导空白 */
    CHECK(parse_var_assignment("  FOO=bar", name, sizeof name, val, sizeof val) == true);
    CHECK(strcmp(name, "FOO") == 0 && strcmp(val, "bar") == 0);
    /* 下划线/数字 */
    CHECK(parse_var_assignment("A_1=v", name, sizeof name, val, sizeof val) == true);
    CHECK(strcmp(name, "A_1") == 0);
    /* 非法：数字开头 */
    CHECK(parse_var_assignment("1ABC=v", name, sizeof name, val, sizeof val) == false);
    /* 非法：无 = */
    CHECK(parse_var_assignment("REDIRECT /a /b", name, sizeof name, val, sizeof val) == false);
    /* 非法：关键字 HIDE 后跟路径（首 token 无 =） */
    CHECK(parse_var_assignment("HIDE /x", name, sizeof name, val, sizeof val) == false);
    /* 带空格围绕 = 不识别（NAME 后是空格非 =） */
    CHECK(parse_var_assignment("X = y", name, sizeof name, val, sizeof val) == false);
}

static void test_expand_path_vars(void) {
    char out[1024];
    /* 无 $：原样 */
    expand_path_vars("/sdcard/x", out, sizeof out, NULL, NULL, "com.a");
    CHECK(strcmp(out, "/sdcard/x") == 0);
    /* $package */
    expand_path_vars("/sdcard/Android/data/$package/files", out, sizeof out, NULL, NULL, "com.a");
    CHECK(strcmp(out, "/sdcard/Android/data/com.a/files") == 0);
    /* ${package} */
    expand_path_vars("${package}/cache", out, sizeof out, NULL, NULL, "com.b");
    CHECK(strcmp(out, "com.b/cache") == 0);
    /* 未知变量保留字面 */
    expand_path_vars("/x/$foo/y", out, sizeof out, NULL, NULL, "com.a");
    CHECK(strcmp(out, "/x/$foo/y") == 0);
    /* 未闭合 ${ 保留字面 */
    expand_path_vars("/x/${pkg/y", out, sizeof out, NULL, NULL, "com.a");
    CHECK(strcmp(out, "/x/${pkg/y") == 0);
    /* $ 后非变量名字符，保留 $ */
    expand_path_vars("cost$5", out, sizeof out, NULL, NULL, "com.a");
    CHECK(strcmp(out, "cost$5") == 0);
    /* 多次出现 */
    expand_path_vars("$package/$package", out, sizeof out, NULL, NULL, "com.a");
    CHECK(strcmp(out, "com.a/com.a") == 0);

    /* 用户变量（构造 AppConfig） */
    AppConfig cfg = {0};
    char* n1 = strdup("BASE"); char* v1 = strdup("/sdcard/$package");
    cfg.var_names = &n1; cfg.var_values = &v1;
    char* r1 = NULL;
    cfg.var_resolved = &r1;
    bool st[] = {false};
    cfg.var_is_static = st;
    cfg.var_count = 1;
    expand_path_vars("$BASE/files", out, sizeof out, &cfg, NULL, "com.a");
    CHECK(strcmp(out, "/sdcard/com.a/files") == 0);
    free(n1); free(v1);

    /* ${name} 形式的用户变量（边界明确写法） */
    AppConfig cfg3 = {0};
    char* n3 = strdup("VAR"); char* v3 = strdup("/x/$package"); char* r3 = NULL;
    cfg3.var_names = &n3; cfg3.var_values = &v3; cfg3.var_resolved = &r3;
    bool st3[] = {false}; cfg3.var_is_static = st3; cfg3.var_count = 1;
    expand_path_vars("${VAR}/y", out, sizeof out, &cfg3, NULL, "com.a");
    CHECK(strcmp(out, "/x/com.a/y") == 0);
    free(n3); free(v3);

    /* app 覆盖 global */
    AppConfig g = {0};
    char* gn = strdup("V"); char* gv = strdup("/global"); char* gr = NULL;
    g.var_names = &gn; g.var_values = &gv; g.var_resolved = &gr;
    bool gst[] = {false}; g.var_is_static = gst; g.var_count = 1;
    AppConfig a = {0};
    char* an = strdup("V"); char* av = strdup("/app"); char* ar = NULL;
    a.var_names = &an; a.var_values = &av; a.var_resolved = &ar;
    bool ast[] = {false}; a.var_is_static = ast; a.var_count = 1;
    expand_path_vars("$V/x", out, sizeof out, &a, &g, "com.a");
    CHECK(strcmp(out, "/app/x") == 0);
    free(gn); free(gv); free(an); free(av);

    /* 循环引用：A=$B, B=$A（不展开为静态，运行时遇循环保留字面） */
    AppConfig c2 = {0};
    char* c2n[] = {"A", "B"};
    char* c2v[] = {"$B", "$A"};
    char* c2r[] = {NULL, NULL};
    c2.var_names = c2n; c2.var_values = c2v; c2.var_resolved = c2r;
    bool c2st[] = {false, false}; c2.var_is_static = c2st; c2.var_count = 2;
    expand_path_vars("$A", out, sizeof out, &c2, NULL, "com.a");
    CHECK(strcmp(out, "$A") == 0);
    /* 缓冲区截断：输出超长不越界，结果以 null 结尾 */
    char small[4];
    expand_path_vars("/sdcard/Android/data/$package", small, sizeof small, NULL, NULL, "com.a");
    CHECK(small[3] == '\0' && strncmp(small, "/sd", 3) == 0);
}

static void test_analyze_var_staticness(void) {
    /* 全局：STATIC=/sdcard/m（字面量）, DYN=/x/$package（动态）, NEST=$STATIC/c（静态） */
    AppConfig g = {0};
    char* gn[] = {"STATIC", "DYN", "NEST"};
    char* gv[] = {"/sdcard/m", "/x/$package", "$STATIC/c"};
    char* gr[] = {NULL, NULL, NULL};
    g.var_names = gn; g.var_values = gv; g.var_resolved = gr;
    bool gst[] = {false, false, false};
    g.var_is_static = gst; g.var_count = 3;
    analyze_var_staticness(&g, NULL);
    CHECK(g.var_is_static[0] == true);   /* STATIC 静态 */
    CHECK(g.var_is_static[1] == false);  /* DYN 动态 */
    CHECK(g.var_is_static[2] == true);   /* NEST 传递闭包仍静态 */
    CHECK(g.var_resolved[0] != NULL && strcmp(g.var_resolved[0], "/sdcard/m") == 0);
    CHECK(g.var_resolved[2] != NULL && strcmp(g.var_resolved[2], "/sdcard/m/c") == 0);
    CHECK(g.var_resolved[1] == NULL);    /* 动态不预计算 */
    /* 循环引用 → 动态 */
    AppConfig c2 = {0};
    char* cn[] = {"A", "B"};
    char* cv[] = {"$B", "$A"};
    char* cr[] = {NULL, NULL};
    c2.var_names = cn; c2.var_values = cv; c2.var_resolved = cr;
    bool cst[] = {false, false};
    c2.var_is_static = cst; c2.var_count = 2;
    analyze_var_staticness(&c2, NULL);
    CHECK(c2.var_is_static[0] == false && c2.var_is_static[1] == false);
    /* 展开后静态变量走 resolved（与递归展开结果一致） */
    char out[256];
    expand_path_vars("$NEST/files", out, sizeof out, &g, NULL, "com.a");
    CHECK(strcmp(out, "/sdcard/m/c/files") == 0);
    /* 释放预计算结果避免泄漏 */
    free(g.var_resolved[0]); g.var_resolved[0] = NULL;
    free(g.var_resolved[2]); g.var_resolved[2] = NULL;
}

static void test_build_real_base(void) {
    char base[PATH_MAX];
    /* 不含 $：? 前缀（相对当前 user 存储） */
    CHECK(build_real_base_from_target("?/Android/data", 0, base, sizeof base, NULL, NULL, "com.a") == true);
    CHECK(strcmp(base, "/data/media/0/Android/data") == 0);
    /* 不含 $：系统绝对 */
    CHECK(build_real_base_from_target("/data/foo", 10, base, sizeof base, NULL, NULL, "com.a") == true);
    CHECK(strcmp(base, "/data/foo") == 0);
    CHECK(build_real_base_from_target("/mnt", 10, base, sizeof base, NULL, NULL, "com.a") == true);
    CHECK(strcmp(base, "/mnt") == 0);
    /* 不含 $：相对 */
    CHECK(build_real_base_from_target("Android/data", 10, base, sizeof base, NULL, NULL, "com.a") == true);
    CHECK(strcmp(base, "/data/media/10/Android/data") == 0);
    /* 含 $：展开后系统绝对（/mnt/sdcard/com.a） */
    CHECK(build_real_base_from_target("/mnt/sdcard/$package", 10, base, sizeof base, NULL, NULL, "com.a") == true);
    CHECK(strcmp(base, "/mnt/sdcard/com.a") == 0);
    /* 含 $：展开后 /data 子路径 */
    CHECK(build_real_base_from_target("/data/$package", 10, base, sizeof base, NULL, NULL, "com.a") == true);
    CHECK(strcmp(base, "/data/com.a") == 0);
    /* 含 $ 未知变量 → 保留字面 $P → 相对（user 存储下） */
    AppConfig empty_cfg = {0};
    CHECK(build_real_base_from_target("$P", 10, base, sizeof base, &empty_cfg, NULL, "com.a") == true);
    CHECK(strcmp(base, "/data/media/10/$P") == 0);
    /* 含 $ 但包名不可解析 → 规则失效（返回 false） */
    CHECK(build_real_base_from_target("/x/$package", 10, base, sizeof base, NULL, NULL, "system") == false);
    CHECK(build_real_base_from_target("/x/$package", 10, base, sizeof base, NULL, NULL, "unknown") == false);
}

int main(void) {
    test_has_path_var();
    test_pkg_resolvable();
    test_is_system_abs_path();
    test_parse_var_assignment();
    test_expand_path_vars();
    test_analyze_var_staticness();
    test_build_real_base();
    if (g_fail) { printf("FAILED %d\n", g_fail); return 1; }
    printf("all passed\n");
    return 0;
}
