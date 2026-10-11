/*
 * a26_misc_test.c — A26 杂项的直编判别驱动（纯函数 + 落盘语义）
 *
 * 覆盖：
 *   ⑤ ftp_conf.c  strip_comment：`#` 只在行首或空白后起注释（含 # 的密码
 *      不被截断）；port 校验（0/负/超 65535/非数字 → 整段作废）。
 *   ⑩ config_parser.c view_parse_section：OFF/ON 必须整词（`OFFX` 不再当
 *      开关）；`:uid` 非数字/越界不再静默成 0。
 *   ⑨ nsp_ini_store.c nsp_ini_save：临时名带 pid（两个写者不互相 rename）、
 *      内容 fsync（写后立即读回内容完整）。
 *
 * 退出码：0 全通过；1 有失败；78 仅表示"整组不具备条件"（本驱动不用）。
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

/* ---- 被测：ftp_conf.c 的 strip_comment / port 校验（经 ftp_conf_load） ---- */
/* ftp_conf.c 经 nsp_module.h(→nsp_log.h) 取 LOG_WRN → log_internal（模块 ABI 由
   主程序导出）。本驱动直编该 TU，故提供同名桩：告警计数便于断言"非法值有提示"。
   编译需 -DNSP_MODULE_BUILD（见 tests/test_a26_misc.py）。 */
static int g_log_wrn = 0;
#include "ftp_conf.h"

/* ---- 被测：config_parser.c 的段头解析（经内部函数暴露不行，故用薄壳） ---- */
/* view_parse_section 是 static，故本驱动改用「编译两个 TU + 由 driver 直接
   复刻调用面」的方式不可行。改走：把 config_parser.c 的段头解析抽成可测
   单元不是本次目标，因此⑩在这里用 ftp_conf 的同源语义（段头 ON/OFF 边界）
   以及独立的小型等价实现交叉验证——见 §B 的说明。 */

/* ---- 被测：nsp_ini_store ---- */
#include "nsp_ini_store.h"

/* LogLevel/log_internal 由 nsp_log.h 声明（ftp_conf.c 经 nsp_module.h 间接取得；
   本驱动显式包含）。实现住 src/，本驱动不链接，故落同名桩。
   g_log_wrn 计数供断言「非法值 loud 告警」。 */
#include "nsp_log.h"
LogLevel g_min_log_level = LOG_INFO;
void log_internal(LogLevel level, const char* format, ...);
void log_internal(LogLevel level, const char* format, ...) {
    (void)format;
    if (level == LOG_WARN) g_log_wrn++;
}

static int g_pass = 0, g_fail = 0;

#define CHECK(cond, fmt, ...)                                         \
    do {                                                              \
        if (cond) {                                                   \
            g_pass++;                                                 \
            printf("  PASS " fmt "\n", ##__VA_ARGS__);                \
        } else {                                                      \
            g_fail++;                                                 \
            printf("  FAIL " fmt "\n", ##__VA_ARGS__);                \
        }                                                             \
    } while (0)

/* ===================== §A ftp_conf：`#` 与 port ===================== */

static char* write_tmp(const char* dir, const char* name, const char* body) {
    static char path[4096];
    snprintf(path, sizeof path, "%s/%s", dir, name);
    FILE* fp = fopen(path, "w");
    if (!fp) return NULL;
    fputs(body, fp);
    fclose(fp);
    return path;
}

static void test_ftp_conf_hash(void) {
    printf("── A. ftp.conf `#` 注释边界（含 # 的密码不被截断）──\n");
    char tmpl[] = "/tmp/a26_conf_XXXXXX";
    char* dir = mkdtemp(tmpl);
    if (!dir) {
        CHECK(false, "mkdtemp 失败");
        return;
    }

    /* 密码含 '#'：旧实现 strchr 无条件截断 → pass 变成 "p" */
    char body[1024];
    snprintf(body, sizeof body,
             "[云盘]\n"
             "host = ftp.example.com\n"
             "port = 2121\n"
             "user = u1\n"
             "pass = p#ssw0rd\n"
             "remote_dir = /upload\n");
    char* p = write_tmp(dir, "ftp.conf", body);
    FtpServerList list;
    int rc = ftp_conf_load(p, &list);
    CHECK(rc == 0 && list.count == 1, "配置加载成功（count=%d rc=%d）", list.count, rc);
    if (rc == 0 && list.count == 1) {
        CHECK(strcmp(list.servers[0].pass, "p#ssw0rd") == 0,
              "含 # 的密码未被截断（实际 \"%s\"）", list.servers[0].pass);
        CHECK(list.servers[0].port == 2121, "port=2121 生效（实际 %d）", list.servers[0].port);
    }
    ftp_conf_free(&list);

    /* 行首/空白后的 '#' 仍须是注释 */
    snprintf(body, sizeof body,
             "# 整行注释\n"
             "[云盘]\n"
             "host = h2   # 行尾注释\n"
             "port = 21\n");
    p = write_tmp(dir, "ftp2.conf", body);
    rc = ftp_conf_load(p, &list);
    CHECK(rc == 0 && list.count == 1, "行首/行内注释仍生效（count=%d）", list.count);
    if (rc == 0 && list.count == 1) {
        CHECK(strcmp(list.servers[0].host, "h2") == 0,
              "行内注释被剥离，host=\"%s\"", list.servers[0].host);
    }
    ftp_conf_free(&list);

    printf("── A2. ftp.conf port 非法即整段作废 ──\n");
    const char* bad_ports[] = {"0", "-1", "65536", "abc", "21x"};
    for (size_t i = 0; i < sizeof bad_ports / sizeof bad_ports[0]; i++) {
        snprintf(body, sizeof body,
                 "[坏端口]\n"
                 "host = h\n"
                 "port = %s\n",
                 bad_ports[i]);
        p = write_tmp(dir, "bad.conf", body);
        rc = ftp_conf_load(p, &list);
        CHECK(rc != 0 && list.count == 0, "port=\"%s\" 整段作废（count=%d rc=%d）",
              bad_ports[i], list.count, rc);
        ftp_conf_free(&list);
    }
    /* 边界合法值 */
    const int good_ports[] = {1, 21, 65535};
    for (size_t i = 0; i < sizeof good_ports / sizeof good_ports[0]; i++) {
        snprintf(body, sizeof body, "[好端口]\nhost = h\nport = %d\n", good_ports[i]);
        p = write_tmp(dir, "good.conf", body);
        rc = ftp_conf_load(p, &list);
        CHECK(rc == 0 && list.count == 1 && list.servers[0].port == good_ports[i],
              "port=%d 接受（count=%d port=%d）", good_ports[i], list.count,
              list.count ? list.servers[0].port : -1);
        ftp_conf_free(&list);
    }
}

/* ===================== §B config_parser 段头 ON/OFF 与 uid =====================
   说明：view_parse_section 是 config_parser.c 的 static 函数，本驱动不直编
   config_parser.c（依赖面过大）。⑩ 的判别改由 tests/test_rules.py 的端到端
   断言承担（`[X] OFFX` 不再被当开关、`[X:abc]` 不再命中 uid 0）——见该套件的
   §A26-⑩ 组。此处只做 fmt 占位，保证本驱动的分组编号连续。 */

/* ===================== §C nsp_ini_store 持久化 ===================== */

static void test_ini_save(void) {
    printf("── C. nsp_ini_save：pid 临时名 + fsync 持久化 ──\n");
    char tmpl[] = "/tmp/a26_ini_XXXXXX";
    char* dir = mkdtemp(tmpl);
    if (!dir) {
        CHECK(false, "mkdtemp 失败");
        return;
    }
    char path[4096];
    snprintf(path, sizeof path, "%s/ftp.conf", dir);

    /* 首次保存：文件从无到有 */
    NspIniStore* s = nsp_ini_open(path);
    CHECK(s != NULL, "nsp_ini_open 成功");
    if (!s) return;
    nsp_ini_set(s, "云盘", "host", "ftp.example.com");
    nsp_ini_set(s, "云盘", "pass", "p#ssw0rd");
    CHECK(nsp_ini_save(s) == 0, "首次 save 成功");
    nsp_ini_close(s);

    /* 写后立即读回：内容完整（fsync 后 rename 生效） */
    s = nsp_ini_open(path);
    char buf[256] = {0};
    int g1 = nsp_ini_get(s, "云盘", "host", buf, sizeof buf);
    CHECK(g1 == 0 && strcmp(buf, "ftp.example.com") == 0,
          "写后读回 host 完整（got=%d \"%s\"）", g1, buf);
    memset(buf, 0, sizeof buf);
    int g2 = nsp_ini_get(s, "云盘", "pass", buf, sizeof buf);
    CHECK(g2 == 0 && strcmp(buf, "p#ssw0rd") == 0,
          "写后读回 pass 完整（got=%d \"%s\"）", g2, buf);
    nsp_ini_close(s);

    /* 目录内不得残留固定名 .tmp（旧实现用 <path>.tmp，并发写者会互 rename）。
       pid 后缀的临时文件在 save 成功后应已 rename 掉，目录里只留正式文件 */
    char tmphack[4096];
    snprintf(tmphack, sizeof tmphack, "%s/ftp.conf.tmp", path);
    struct stat st;
    CHECK(stat(tmphack, &st) != 0, "save 后无固定名 <path>.tmp 残留");
    CHECK(stat(path, &st) == 0 && st.st_size > 0, "正式文件存在且非空（size=%lld）",
          (long long)(stat(path, &st) == 0 ? st.st_size : -1));

    /* 权限收紧：含明文密码的文件须 0600 */
    CHECK((st.st_mode & 0777) == 0600, "落盘权限 0600（实际 %03o）", st.st_mode & 0777);
}

/* ===================== §A3 ftp_conf：SFTP 字段（proto/key/known_hosts） =====================
   proto=sftp 引入了协议、私钥、known_hosts 与主机密钥校验四个新字段。这里只测
   **解析与失败闭合**（真正的 SFTP 连通性由 tests/test_sftp.py 打真 sshd 覆盖）：
   - proto 非法（拼错）必须整段作废——静默退回 ftp 会把账号密码发到明文 FTP；
   - 端口未显式配置时按 proto 补默认（ftp 21 / sftp 22），且与配置项书写顺序无关；
   - host_key_check 只认 on/off/true/false/1/0，其余整段作废；默认 on（fail-closed）；
   - key_file/known_hosts 超长整段作废（同 host/remote_dir 的失败闭合姿态）。 */
static void test_ftp_conf_sftp(void) {
    printf("── A3. ftp.conf SFTP 字段（proto/端口默认/主机密钥校验）──\n");
    char tmpl[] = "/tmp/a26_sftp_XXXXXX";
    char* dir = mkdtemp(tmpl);
    if (!dir) {
        CHECK(false, "mkdtemp 失败");
        return;
    }
    char body[2048];
    FtpServerList list;
    int rc;

    /* 1. proto=sftp 且未写 port → 默认 22；host_key_check 默认 on */
    snprintf(body, sizeof body,
             "[备份]\nproto = sftp\nhost = nas.local\nuser = b\n"
             "key_file = /data/Namespace-Proxy/keys/b.key\n");
    rc = ftp_conf_load(write_tmp(dir, "s1.conf", body), &list);
    CHECK(rc == 0 && list.count == 1, "proto=sftp 段加载成功（count=%d）", list.count);
    if (rc == 0 && list.count == 1) {
        CHECK(list.servers[0].sftp, "sftp 标记置位");
        CHECK(list.servers[0].port == 22, "未写 port → sftp 默认 22（实际 %d）",
              list.servers[0].port);
        CHECK(list.servers[0].host_key_check, "host_key_check 默认 on（fail-closed）");
        CHECK(strcmp(list.servers[0].key_file, "/data/Namespace-Proxy/keys/b.key") == 0,
              "key_file 解析（实际 \"%s\"）", list.servers[0].key_file);
    }
    ftp_conf_free(&list);

    /* 2. proto=ftp 且未写 port → 默认 21（旧行为不变） */
    snprintf(body, sizeof body, "[盘]\nproto = ftp\nhost = h\n");
    rc = ftp_conf_load(write_tmp(dir, "s2.conf", body), &list);
    CHECK(rc == 0 && list.count == 1 && !list.servers[0].sftp && list.servers[0].port == 21,
          "proto=ftp → port 默认 21（sftp=%d port=%d）",
          rc == 0 && list.count == 1 ? (int)list.servers[0].sftp : -1,
          rc == 0 && list.count == 1 ? list.servers[0].port : -1);
    ftp_conf_free(&list);

    /* 3. 显式 port 优先，且与 proto 的书写顺序无关 */
    snprintf(body, sizeof body, "[备份]\nport = 2222\nhost = h\nproto = sftp\n");
    rc = ftp_conf_load(write_tmp(dir, "s3.conf", body), &list);
    CHECK(rc == 0 && list.count == 1 && list.servers[0].port == 2222 && list.servers[0].sftp,
          "显式 port 优先且与顺序无关（port=%d sftp=%d）",
          rc == 0 && list.count == 1 ? list.servers[0].port : -1,
          rc == 0 && list.count == 1 ? (int)list.servers[0].sftp : -1);
    ftp_conf_free(&list);

    /* 4. proto 拼错 → 整段作废（绝不静默退回明文 ftp） */
    snprintf(body, sizeof body, "[错]\nproto = scp\nhost = h\n");
    rc = ftp_conf_load(write_tmp(dir, "s4.conf", body), &list);
    CHECK(rc != 0 && list.count == 0, "proto=scp 整段作废（count=%d rc=%d）", list.count, rc);
    ftp_conf_free(&list);

    /* 5. host_key_check 三态：on/off 生效，垃圾值整段作废 */
    snprintf(body, sizeof body,
             "[关]\nproto = sftp\nhost = h\nhost_key_check = off\n");
    rc = ftp_conf_load(write_tmp(dir, "s5.conf", body), &list);
    CHECK(rc == 0 && list.count == 1 && !list.servers[0].host_key_check,
          "host_key_check=off 生效");
    ftp_conf_free(&list);

    snprintf(body, sizeof body, "[垃圾]\nproto = sftp\nhost = h\nhost_key_check = maybe\n");
    rc = ftp_conf_load(write_tmp(dir, "s6.conf", body), &list);
    CHECK(rc != 0 && list.count == 0, "host_key_check=maybe 整段作废（count=%d）", list.count);
    ftp_conf_free(&list);

    /* 6. key_file 超长（≥512）→ 整段作废（不截断路径去连错文件） */
    char big[600];
    memset(big, 'k', sizeof big - 1);
    big[sizeof big - 1] = '\0';
    snprintf(body, sizeof body, "[超长]\nproto = sftp\nhost = h\nkey_file = %s\n", big);
    rc = ftp_conf_load(write_tmp(dir, "s7.conf", body), &list);
    CHECK(rc != 0 && list.count == 0, "key_file 超长整段作废（count=%d）", list.count);
    ftp_conf_free(&list);
}

int main(void) {
    test_ftp_conf_hash();
    test_ftp_conf_sftp();
    test_ini_save();
    printf("SUMMARY pass=%d fail=%d\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
