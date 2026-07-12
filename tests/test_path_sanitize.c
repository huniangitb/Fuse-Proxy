#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

static int g_fail = 0;
#define CHECK(cond) do { if (!(cond)) { printf("FAIL line %d: %s\n", __LINE__, #cond); g_fail++; } } while(0)

/* path_contains_invalid_chars 的功能与边界 */
static void test_contains_invalid(void) {
    /* 合法路径 */
    CHECK(path_contains_invalid_chars("/sdcard/Android/data/com.foo/files") == false);
    CHECK(path_contains_invalid_chars("/data/media/0/中文路径/文件.txt") == false);
    CHECK(path_contains_invalid_chars("/") == false);
    CHECK(path_contains_invalid_chars("") == false);
    CHECK(path_contains_invalid_chars(nullptr) == false);

    /* 控制字符为非法 */
    CHECK(path_contains_invalid_chars("/sdcard/\x07") == true);     /* BEL */
    CHECK(path_contains_invalid_chars("/sdcard/\x1f") == true);     /* US 分隔符 */
    CHECK(path_contains_invalid_chars("/sdcard/\x7f") == true);     /* DEL */
    CHECK(path_contains_invalid_chars("/sdcard/x\0y") == false);    /* 嵌入 NUL：被当作字符串终止，不视为非法 */

    /* 制表符 \t=0x09、换行 \n=0x0a、回车 \r=0x0d 在 0x08~0x20 范围内，
       按 path_char_is_invalid 实现 0x09/0x0a/0x0d 应判定为合法（跳过 0x08~0x09 与 0x0a~0x1f 的下界） */
    CHECK(path_contains_invalid_chars("/sdcard/x\ty") == false);   /* \t=0x09，实现允许 */
    CHECK(path_contains_invalid_chars("/sdcard/x\ny") == true);     /* \n=0x0a，介于 0x09 与 0x20 之间属非法 */
    CHECK(path_contains_invalid_chars("/sdcard/x\ry") == true);     /* \r=0x0d */

    /* Unicode 不间断空格 U+00A0 (0xC2 0xA0) */
    CHECK(path_contains_invalid_chars("/sdcard/\xc2\xa0") == true);
    /* Unicode 软连字符 U+00AD (0xC2 0xAD) */
    CHECK(path_contains_invalid_chars("/sdcard/\xc2\xad") == true);
    /* U+202E 强制 RTL 覆盖 (0xE2 0x80 0xAE) */
    CHECK(path_contains_invalid_chars("/sdcard/\xe2\x80\xae") == true);
    /* U+FEFF BOM (0xEF 0xBB 0xBF) */
    CHECK(path_contains_invalid_chars("/sdcard/\xef\xbb\xbf") == true);
}

/* path_sanitize 输出与截断保护 */
static void test_sanitize(void) {
    char out[256];

    /* 合法路径原样通过 */
    path_sanitize(out, sizeof(out), "/sdcard/合法.txt");
    CHECK(strcmp(out, "/sdcard/合法.txt") == 0);

    /* nullptr 输入 → 空 */
    path_sanitize(out, sizeof(out), nullptr);
    CHECK(out[0] == '\0');

    /* 含非法字符被剥离 */
    path_sanitize(out, sizeof(out), "/sd\x07""card/\xc2\xa0""file");
    CHECK(strcmp(out, "/sdcard/file") == 0);

    /* 多字节非法被整体跳过（U+202E 3 字节） */
    path_sanitize(out, sizeof(out), "a\xe2\x80\xae""b");
    CHECK(strcmp(out, "ab") == 0);

    /* 截断保护：输出超长不越界，结果以 null 结尾 */
    char small[4];
    path_sanitize(small, sizeof(small), "/sdcard/Android/data/com.foo/files");
    CHECK(small[sizeof(small) - 1] == '\0');
    CHECK(strncmp(small, "/sd", 3) == 0);

    /* size=0 安全不崩 */
    path_sanitize(nullptr, 0, "/x");
    char zero[1];
    path_sanitize(zero, 0, "/x");
}

int main(void) {
    test_contains_invalid();
    test_sanitize();
    if (g_fail) { printf("FAILED %d\n", g_fail); return 1; }
    printf("all passed\n");
    return 0;
}
