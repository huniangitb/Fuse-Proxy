#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A26 杂项判别（ftp_conf `#`/port + nsp_ini_store 落盘/读失败语义）

背景（review-findings-20261007 §A26 / 20261018 §R12、§R13）：
  ⑤ ftp_conf.c 的 strip_comment 曾用 `strchr(line,'#')` 无条件截断——含 `#` 的
     密码（`pass = p#ssw0rd`）被静默改成首段，服务器 530 拒绝而配置看不出异常；
     `port = 0/-1/65536/abc` 也被 atoi 照收，最终以 `ftp://host:0/` 交给 libcurl。
  ⑨ nsp_ini_store.c 的 nsp_ini_save 曾用固定名 `<path>.tmp`、无文件/目录 fsync，
     两个写者会互相 rename 掉对方未写完的临时文件；掉电时可能「rename 生效、
     内容为空/旧」。
  R12 nsp_ini_open 曾把 fopen 的任何失败都当「空存储」：EACCES/EMFILE/EIO 时
     调用方（rule_server）随后 save 会用只含本次条目的内容覆盖整份配置。
     本套件用 `--wrap=fopen` 让已存在文件返回 EACCES，断言返回 NULL（读失败）
     而不是非 NULL 空存储，且原文件逐字节不变；ENOENT 仍按空存储处理。
  R13 bool schema 字段的词法口径：控制面只接受 on/off/true/false/1/0 并归一为
     on/off；模块侧 ftp_conf 必须接受同一词表（这里直接验模块侧解析）。

本套件直编 ftp_conf.c（+ nsp_ini_store.c）并断言上述行为。
判别力：把 src/modules/ftp/ftp_conf.c 换回修复前版本（或把 strip_comment 改回
strchr 无条件截断），A 组立即失败（密码变成 "p"）；把 nsp_ini_store.c 换回修复前
版本，C 组的固定名 .tmp 残留断言失败、R12 组「EACCES 返回 NULL」断言失败。

前置：本机 cc。失败退出码 1。
"""

import os
import shlex
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DRIVER = os.path.join(ROOT, "tests", "fixtures", "a26_misc_test.c")
SRC = os.environ.get("A26_FTP_CONF_SRC", os.path.join(ROOT, "src", "modules", "ftp", "ftp_conf.c"))
INI_SRC = os.environ.get("A26_INI_SRC", os.path.join(ROOT, "src", "core", "nsp_ini_store.c"))
UTIL_SRC = os.path.join(ROOT, "src", "core", "nsp_util.c")
RUN_TIMEOUT = 120

# ---- R12 直编驱动：--wrap=fopen 让已存在文件在「读」模式返回 EACCES ----
R12_DRIVER = r"""
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "nsp_ini_store.h"

static const char* g_fail_path;
static int g_fail_errno;

FILE* __real_fopen(const char* path, const char* mode);
FILE* __real_fopen64(const char* path, const char* mode);

static int fail_match(const char* path, const char* mode) {
    return g_fail_path && strchr(mode, 'r') != NULL && strcmp(path, g_fail_path) == 0;
}
FILE* __wrap_fopen(const char* path, const char* mode) {
    if (fail_match(path, mode)) { errno = g_fail_errno; return NULL; }
    return __real_fopen(path, mode);
}
FILE* __wrap_fopen64(const char* path, const char* mode) {
    if (fail_match(path, mode)) { errno = g_fail_errno; return NULL; }
    return __real_fopen64(path, mode);
}

static int g_fail = 0;
#define CHECK(cond, msg) do { \
    if (cond) printf("  PASS %s\n", msg); \
    else { printf("  FAIL %s\n", msg); g_fail++; } \
} while (0)

static void read_all(const char* path, char* out, size_t sz) {
    out[0] = '\0';
    FILE* fp = fopen(path, "r");
    if (!fp) return;
    size_t n = fread(out, 1, sz - 1, fp);
    out[n] = '\0';
    fclose(fp);
}

int main(void) {
    char dir[] = "/tmp/a26_r12_XXXXXX";
    if (!mkdtemp(dir)) return 2;
    char path[4096];
    snprintf(path, sizeof path, "%s/mod.conf", dir);
    FILE* fp = fopen(path, "w");
    if (!fp) return 2;
    fputs("[srv]\nhost = h\nuser = u\n", fp);
    fclose(fp);

    /* 1) EACCES：必须返回 NULL（旧实现返回「空存储」） */
    g_fail_path = path;
    g_fail_errno = EACCES;
    errno = 0;
    NspIniStore* s = nsp_ini_open(path);
    CHECK(s == NULL, "EACCES 时 nsp_ini_open 返回 NULL（不当空存储）");
    CHECK(errno == EACCES, "EACCES 时保留 errno 语义");
    if (s) { /* 旧实现路径：空存储 + save 会把整份配置覆盖成只含本次条目 */
        nsp_ini_set(s, "new", "host", "x");
        nsp_ini_save(s);
        nsp_ini_close(s);
    }
    g_fail_path = NULL;
    char body[512];
    read_all(path, body, sizeof body);
    CHECK(strstr(body, "host = h") != NULL && strstr(body, "user = u") != NULL,
          "读失败后原文件逐字节保留（未被覆盖）");

    /* 2) ENOENT：仍是「空存储」，不是读失败 */
    char missing[4096];
    snprintf(missing, sizeof missing, "%s/missing.conf", dir);
    NspIniStore* e = nsp_ini_open(missing);
    CHECK(e != NULL, "ENOENT 仍按空存储返回非 NULL");
    if (e) {
        CHECK(nsp_ini_section_count(e) == 0, "ENOENT 空存储零段");
        nsp_ini_close(e);
    }

    /* 3) 读中途失败（目录当文件 → getline 报 EISDIR）：返回 NULL 而非半份内容 */
    NspIniStore* d = nsp_ini_open(dir);
    CHECK(d == NULL, "读中途失败返回 NULL 而非半份内容");
    if (d) nsp_ini_close(d);

    unlink(path);
    rmdir(dir);
    printf("a26 R12 组：%s\n", g_fail ? "有失败" : "全通过");
    return g_fail ? 1 : 0;
}
"""

# ---- R13 直编驱动：模块侧 ftp_conf 的 bool 词表必须与控制面归一值同口径 ----
R13_DRIVER = r"""
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "ftp_conf.h"
#include "nsp_log.h"

LogLevel g_min_log_level = LOG_INFO;
void log_internal(LogLevel level, const char* format, ...) {
    (void)level;
    (void)format;
}

static int g_fail = 0;
static int g_seq = 0;
#define CHECK(cond, msg) do { \
    if (cond) printf("  PASS %s\n", msg); \
    else { printf("  FAIL %s\n", msg); g_fail++; } \
} while (0)

/* 返回 1 = 解析出一个 server 段（*out 为其 host_key_check）；0 = 整段作废/无 server */
static int load_bool(const char* dir, const char* val, bool* out) {
    char path[4096];
    snprintf(path, sizeof path, "%s/srv_%d.conf", dir, ++g_seq);
    FILE* fp = fopen(path, "w");
    if (!fp) return 0;
    fprintf(fp, "[srv]\nhost = h\nhost_key_check = %s\n", val);
    fclose(fp);
    FtpServerList list = {0};
    int rc = ftp_conf_load(path, &list);
    int ok = 0;
    if (rc == 0 && list.count == 1) {
        *out = list.servers[0].host_key_check;
        ok = 1;
    }
    ftp_conf_free(&list);
    unlink(path);
    return ok;
}

int main(void) {
    char dir[] = "/tmp/a26_r13_XXXXXX";
    if (!mkdtemp(dir)) return 2;
    const char* on_vals[] = {"on", "ON", "true", "TRUE", "1"};
    const char* off_vals[] = {"off", "OFF", "false", "FALSE", "0"};
    char msg[160];
    for (size_t i = 0; i < sizeof(on_vals) / sizeof(on_vals[0]); i++) {
        bool b = false;
        int ok = load_bool(dir, on_vals[i], &b);
        snprintf(msg, sizeof msg, "ftp_conf 接受 %s → true（与控制面归一 on 同口径）",
                 on_vals[i]);
        CHECK(ok && b, msg);
    }
    for (size_t i = 0; i < sizeof(off_vals) / sizeof(off_vals[0]); i++) {
        bool b = true;
        int ok = load_bool(dir, off_vals[i], &b);
        snprintf(msg, sizeof msg, "ftp_conf 接受 %s → false（与控制面归一 off 同口径）",
                 off_vals[i]);
        CHECK(ok && !b, msg);
    }
    const char* bad[] = {"garbage", "2", "yes", ""};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        bool b = false;
        int ok = load_bool(dir, bad[i], &b);
        snprintf(msg, sizeof msg, "ftp_conf 拒绝非法值 %s → 整段作废（控制面同样拒绝）",
                 bad[i][0] ? bad[i] : "(空串)");
        CHECK(!ok, msg);
    }
    rmdir(dir);
    printf("a26 R13 组：%s\n", g_fail ? "有失败" : "全通过");
    return g_fail ? 1 : 0;
}
"""


def _compile_and_run(tmpdir, include, name, driver_src, sources, extra_cflags=(),
                     extra_ldflags=()):
    """写驱动源码 → 直编实际源码 → 跑；返回是否通过（输出直接打印）。"""
    src = os.path.join(tmpdir, name + ".c")
    with open(src, "w", encoding="utf-8") as f:
        f.write(driver_src)
    exe = os.path.join(tmpdir, name)
    cmd = [
        *shlex.split(os.environ.get("CC", "cc")), "-std=c23", "-D_GNU_SOURCE",
        "-Wall", "-Wextra", "-Wno-unused-parameter",
        "-I", include, *extra_cflags,
        src, *sources, *extra_ldflags, "-o", exe,
    ]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print(f"[{name}] C 编译/链接失败:", file=sys.stderr)
        print(r.stderr, file=sys.stderr)
        return False
    try:
        run = subprocess.run([exe], capture_output=True, text=True, timeout=RUN_TIMEOUT)
    except subprocess.TimeoutExpired:
        print(f"[{name}] 超时（>{RUN_TIMEOUT}s）", file=sys.stderr)
        return False
    print(run.stdout, end="")
    if run.returncode != 0:
        print(f"[{name}] 判别测试失败", file=sys.stderr)
        if run.stderr:
            print(run.stderr, file=sys.stderr)
        return False
    return True


def main():
    for path in (DRIVER, SRC, INI_SRC, UTIL_SRC):
        if not os.path.exists(path):
            print(f"缺少源文件 {path}", file=sys.stderr)
            return 1
    include = os.path.join(ROOT, "include")
    with tempfile.TemporaryDirectory(prefix="a26_misc_") as tmpdir:
        exe = os.path.join(tmpdir, "a26_misc_test")
        cmd = [
            *shlex.split(os.environ.get("CC", "cc")), "-std=c23", "-D_GNU_SOURCE",
            "-DNSP_MODULE_BUILD",  # ftp_conf.c 经 nsp_module.h 取 LOG_WRN（模块 ABI）
            "-Wall", "-Wextra", "-Wno-unused-parameter",
            "-I", include,
            "-I", os.path.join(ROOT, "src", "modules", "ftp"),
            DRIVER, SRC, INI_SRC, UTIL_SRC, "-o", exe,
        ]
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            print("C 编译/链接失败:", file=sys.stderr)
            print(r.stderr, file=sys.stderr)
            return 1
        errlines = [ln for ln in r.stderr.splitlines() if "警告" not in ln and "warning" not in ln
                    and "note" not in ln and "注意" not in ln and "|" not in ln and "^" not in ln]
        if errlines:
            print("\n".join(errlines), file=sys.stderr)
        try:
            run = subprocess.run([exe], capture_output=True, text=True, timeout=RUN_TIMEOUT)
        except subprocess.TimeoutExpired:
            print(f"A26 杂项测试超时（>{RUN_TIMEOUT}s）", file=sys.stderr)
            return 1
        # R12：nsp_ini_open 读失败语义（--wrap=fopen 确定性注入 EACCES，root 下同样有效）
        r12_ok = _compile_and_run(
            tmpdir, include, "a26_r12_open", R12_DRIVER, [INI_SRC, UTIL_SRC],
            extra_ldflags=("-Wl,--wrap=fopen", "-Wl,--wrap=fopen64"))
        # R13：模块侧 bool 词表与控制面归一值同口径
        r13_ok = _compile_and_run(
            tmpdir, include, "a26_r13_bool", R13_DRIVER, [SRC, UTIL_SRC],
            extra_cflags=("-DNSP_MODULE_BUILD",
                          "-I", os.path.join(ROOT, "src", "modules", "ftp")))
    print(run.stdout, end="")
    if run.returncode != 0:
        print("A26 杂项判别测试失败", file=sys.stderr)
        return 1
    if not r12_ok:
        print("A26 R12（nsp_ini_open 读失败）判别测试失败", file=sys.stderr)
        return 1
    if not r13_ok:
        print("A26 R13（bool 词表一致性）判别测试失败", file=sys.stderr)
        return 1
    print("A26 杂项判别测试通过 ✔")
    return 0


if __name__ == "__main__":
    sys.exit(main())
