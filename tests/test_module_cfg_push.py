#!/usr/bin/env python3
"""配置下发归属判别测试：模块配置由框架读、按 owner 过滤下发（视图版本 2）。

约定（nsp_module.h / docs/modules.md §6.1.1）：模块**不读文件、不跑 inotify**，
包括它自己的配置 `<modules_dir>/<模块名>/<模块名>.conf`。框架读入后以
`NSP_CFG_REC_MODULE_FILE` / `NSP_CFG_REC_MODULE_LINE` 记录下发，并**按 owner
过滤**——只发给同名模块（模块间配置隔离与规则隔离同等要求）。

判别性（旧实现上必失败）：旧实现 `config_read_view` 只读主文件 + App-rules，
视图里没有任何 MODULE_* 记录，故「标记存在」「逐行下发」「owner 隔离」三条全失败。
判别性验证：`FW_CONFIG_SRC=<旧实现> python3 tests/test_module_cfg_push.py`
（旧实现 = 去掉 `config_read_view` 里的 `view_scan_module_confs` 调用）。

超长行整份作废（R4）：模块配置任一有效行超过 `NSP_CONFIG_LINE_MAX` 时，框架必须
把该模块配置**整份**判为不可用——只下发 `NSP_CFG_REC_MODULE_FILE` 标记、零
`NSP_CFG_REC_MODULE_LINE`。旧实现只丢这一行（`continue`），于是模块拿其余行按
默认 `proto=ftp`/21 注册：用户以为在连 SFTP，实际以明文 FTP 发送账号密码。
第二个探针（本文件内生成）做**差分**：同一份文件分别走 `ftp_conf_load()`（模块
文件形态）与「视图行喂入 `ftp_conf_parse_line`」（下发形态），两边的返回码与
服务器表（段名/host/port/proto）必须逐项一致——旧实现 direct servers=0、view
servers=1（sftp=0/port=21）必失败。正常 `proto=sftp` 段作正对照，防止两条路径
一起坏成「都解析不出」的假绿。

本套件直编 `src/daemon/fw_config.c` + `src/config/config_parser.c` 及其依赖
（不经 Meson），驱动见 `tests/fixtures/module_cfg_push_driver.c`。

前置：本机 cc、pthread。退出码：通过 0，失败 1，缺编译器/源码 77（整套跳过）。
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DRIVER = os.path.join(ROOT, "tests", "fixtures", "module_cfg_push_driver.c")

# 与 Meson 构建同源（只取本测试实际链接到的部分，见 test_fw_config_view.py）
SOURCES = [
    "src/daemon/fw_pkg.c",
    "src/daemon/cfg_watch.c",
    "src/daemon/fw_rules.c",
    "src/config/config_parser.c",
    "src/config/path_vars.c",
    "src/core/path_trie.c",
    "src/core/nsp_util.c",
    "src/core/nsp_comm.c",
    "src/core/common.c",
    "src/core/sys_pkg.c",
    "src/core/uid_map.c",
    "src/core/fast_pid.c",
]
# 可经环境变量覆盖（判别旧实现用）
FW_CONFIG_SRC = os.environ.get("FW_CONFIG_SRC") or os.path.join(ROOT, "src", "daemon", "fw_config.c")
# 旧实现 = config_read_view 不扫描模块配置（去掉 view_scan_module_confs 调用）
CONFIG_PARSER_SRC = os.environ.get("CONFIG_PARSER_SRC") or os.path.join(
    ROOT, "src", "config", "config_parser.c")

CONFIG_DIR_PAT = re.compile(
    r'^#define\s+(?:NSP_CONFIG_DIR|CONFIG_DIR)\s+"/var/fuse-proxy"\s*$', re.M)

# ───────────────────────────────────────────────────────────
# 超长行 → 整份作废 + 两条解析路径的差分（探针在临时目录生成）
# ───────────────────────────────────────────────────────────
OVERLONG_PROBE = r'''
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config_parser.h"
#include "ftp_conf.h"

static int g_fail;

static void check(int ok, const char* what) {
    printf("  %s %s\n", ok ? "PASS" : "FAIL", what);
    if (!ok) g_fail++;
}

/* 某模块标记之后的连续 MODULE_LINE 条数（-1 = 无标记） */
static int module_line_count(const NspCfgRec* recs, int count, const char* mod,
                             const char** file_out) {
    for (int i = 0; i < count; i++) {
        if (recs[i].kind != NSP_CFG_REC_MODULE_FILE || !recs[i].text) continue;
        if (strcmp(recs[i].text, mod) != 0) continue;
        if (file_out) *file_out = recs[i].file;
        int n = 0;
        for (int j = i + 1; j < count; j++) {
            if (recs[j].kind == NSP_CFG_REC_MODULE_FILE) break;
            if (recs[j].kind == NSP_CFG_REC_MODULE_LINE) n++;
        }
        return n;
    }
    return -1;
}

/* 与 ftp_module 的 apply_config 同法：把本模块的视图行喂进模块自己的状态机 */
static int parse_from_view(const NspCfgRec* recs, int count, const char* mod,
                           FtpServerList* out) {
    FtpConfParse st;
    ftp_conf_parse_begin(&st, out, NULL);
    const char* owner = NULL;
    for (int i = 0; i < count; i++) {
        if (recs[i].kind == NSP_CFG_REC_MODULE_FILE) {
            owner = recs[i].text;
            continue;
        }
        if (recs[i].kind != NSP_CFG_REC_MODULE_LINE) continue;
        if (!owner || strcmp(owner, mod) != 0) continue;
        ftp_conf_parse_line(&st, recs[i].text ? recs[i].text : "");
    }
    return ftp_conf_parse_end(&st);
}

static int same_servers(const FtpServerList* a, const FtpServerList* b) {
    if (a->count != b->count) return 0;
    for (int i = 0; i < a->count; i++) {
        const FtpServerCfg* x = &a->servers[i];
        const FtpServerCfg* y = &b->servers[i];
        if (strcmp(x->name, y->name) != 0 || strcmp(x->host, y->host) != 0 ||
            x->port != y->port || x->sftp != y->sftp)
            return 0;
    }
    return 1;
}

static void diff_case(const char* mod, const char* conf, const NspCfgRec* recs, int count,
                      int expect_servers) {
    FtpServerList direct, view;
    int rc_direct = ftp_conf_load(conf, &direct);
    int rc_view = parse_from_view(recs, count, mod, &view);
    printf("    [%s] direct rc=%d servers=%d%s | view rc=%d servers=%d\n", mod, rc_direct,
           direct.count,
           direct.count ? (direct.servers[0].sftp ? " sftp" : " ftp") : "", rc_view,
           view.count);
    check(rc_direct == rc_view, "差分：直接读文件与视图喂入的返回码一致");
    check(same_servers(&direct, &view),
          "差分：两条路径的服务器表逐项一致（段名/host/port/proto）");
    check(direct.count == expect_servers, "直接读文件得到期望的服务器数（正对照）");
    ftp_conf_free(&direct);
    ftp_conf_free(&view);
}

int main(int argc, char** argv) {
    if (argc < 3) return 2;
    config_set_modules_dir(argv[2]);
    NspCfgRec* recs = NULL;
    int count = 0;
    config_read_view(argv[1], &recs, &count);
    if (!recs || count <= 0) {
        printf("FAIL config_read_view 未产出记录\nRESULT FAIL\n");
        return 1;
    }
    char conf[PATH_MAX];
    snprintf(conf, sizeof conf, "%s/modOverlong/modOverlong.conf", argv[2]);
    const char* file = NULL;
    int lines = module_line_count(recs, count, "modOverlong", &file);
    check(lines == 0, "超长行：该模块只下发标记、零 MODULE_LINE（整份作废）");
    check(file && strcmp(file, conf) == 0, "超长行：标记仍下发且 file 是确切路径");
    diff_case("modOverlong", conf, recs, count, 0);

    snprintf(conf, sizeof conf, "%s/modSftp/modSftp.conf", argv[2]);
    diff_case("modSftp", conf, recs, count, 1);
    {
        FtpServerList l;
        ftp_conf_load(conf, &l);
        check(l.count == 1 && l.servers[0].sftp && l.servers[0].port == 22,
              "正对照：正常 proto=sftp 段解析出 1 个后端且 sftp/22");
        ftp_conf_free(&l);
    }
    config_free_view(recs, count);
    printf("%s\n", g_fail == 0 ? "RESULT OK" : "RESULT FAIL");
    return g_fail == 0 ? 0 : 1;
}
'''

def prepare_include(tmpdir, config_dir):
    """复制 include/，把 GNU 配置根常量指向临时 fixture 根（与 fw_config_view 同法）。"""
    dst_inc = os.path.join(tmpdir, "include")
    shutil.copytree(os.path.join(ROOT, "include"), dst_inc)
    hits = 0
    for name in sorted(os.listdir(dst_inc)):
        if not name.endswith(".h"):
            continue
        path = os.path.join(dst_inc, name)
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        patched, n = CONFIG_DIR_PAT.subn(
            lambda m: m.group(0).replace('"/var/fuse-proxy"', f'"{config_dir}"'), text)
        if n:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(patched)
            hits += n
    return dst_inc if hits else None


def compile_binary(tmpdir, inc_dir):
    exe = os.path.join(tmpdir, "module_cfg_push_test")
    cmd = [
        *os.environ.get("CC", "cc").split(), "-std=c23", "-DTARGET_GNU=1", "-D_GNU_SOURCE",
        "-Wall", "-Wno-unused-parameter",
        "-I", inc_dir, "-I", os.path.join(ROOT, "include"),
        "-I", os.path.join(ROOT, "src", "daemon"),
        DRIVER, FW_CONFIG_SRC,
    ] + [CONFIG_PARSER_SRC if s == "src/config/config_parser.c" else os.path.join(ROOT, s)
         for s in SOURCES] + [
        "-o", exe, "-pthread", "-ldl", "-lm",
    ]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print("C 编译/链接失败:", file=sys.stderr)
        print(r.stderr, file=sys.stderr)
        return None
    return exe


def compile_overlong_probe(tmpdir, inc_dir):
    """第二个探针：超长行整份作废 + 文件形态/下发形态差分（直编 ftp_conf.c）。"""
    src = os.path.join(tmpdir, "module_cfg_overlong_probe.c")
    with open(src, "w", encoding="utf-8") as fh:
        fh.write(OVERLONG_PROBE)
    exe = os.path.join(tmpdir, "module_cfg_overlong_probe")
    cmd = [
        *os.environ.get("CC", "cc").split(), "-std=c23", "-DTARGET_GNU=1", "-D_GNU_SOURCE",
        # ftp_conf.c 经 nsp_module.h 取 LOG_WRN（模块 ABI 形态），与 test_a26_misc 同法
        "-DNSP_MODULE_BUILD",
        "-Wall", "-Wno-unused-parameter",
        "-I", inc_dir, "-I", os.path.join(ROOT, "include"),
        "-I", os.path.join(ROOT, "src", "daemon"),
        "-I", os.path.join(ROOT, "src", "modules", "ftp"),
        src, os.path.join(ROOT, "src", "modules", "ftp", "ftp_conf.c"),
    ] + [CONFIG_PARSER_SRC if s == "src/config/config_parser.c" else os.path.join(ROOT, s)
         for s in SOURCES] + [
        "-o", exe, "-pthread", "-ldl", "-lm",
    ]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print("超长行探针编译/链接失败:", file=sys.stderr)
        print(r.stderr, file=sys.stderr)
        return None
    return exe


def main():
    if not os.path.isfile(DRIVER):
        print("缺少驱动 fixture", file=sys.stderr)
        return 1
    if not os.path.isfile(FW_CONFIG_SRC):
        print(f"缺少源码 {FW_CONFIG_SRC}", file=sys.stderr)
        return 77
    if not os.path.isfile(CONFIG_PARSER_SRC):
        print(f"缺少源码 {CONFIG_PARSER_SRC}", file=sys.stderr)
        return 77
    if not shutil.which(os.environ.get("CC", "cc").split()[0]):
        print("无 C 编译器，整套跳过", file=sys.stderr)
        return 77

    with tempfile.TemporaryDirectory(prefix="module_cfg_push_") as tmpdir:
        config_dir = os.path.join(tmpdir, "config")
        modules = os.path.join(config_dir, "modules")
        # modA/modB 各有配置；modC 只有目录（无配置文件）→ 标记仍须下发
        for mod in ("modA", "modB", "modC"):
            os.makedirs(os.path.join(modules, mod), exist_ok=True)
        with open(os.path.join(modules, "modA", "modA.conf"), "w", encoding="utf-8") as fh:
            fh.write("# 注释行\nhost = a.example.com\npass = p#ssw0rd\nHIDE /nsp_from_module_conf\n")
        with open(os.path.join(modules, "modB", "modB.conf"), "w", encoding="utf-8") as fh:
            fh.write("host = b.example.com\n")
        # R4：modOverlong 第 3 行超长（> NSP_CONFIG_LINE_MAX=2048）——框架必须把该
        # 模块配置整份作废（只下发标记、零 MODULE_LINE）；modSftp 是正常 sftp 段的
        # 正对照（两路径都必须解析出 1 个后端、sftp/22）。
        for mod in ("modOverlong", "modSftp"):
            os.makedirs(os.path.join(modules, mod), exist_ok=True)
        with open(os.path.join(modules, "modOverlong", "modOverlong.conf"), "w",
                  encoding="utf-8") as fh:
            fh.write("[over]\nhost = over.example.com\nproto = sftp" + " " * 2300 + "\n")
        with open(os.path.join(modules, "modSftp", "modSftp.conf"), "w",
                  encoding="utf-8") as fh:
            fh.write("[ok]\nhost = ok.example.com\nproto = sftp\n")

        inc_dir = prepare_include(tmpdir, config_dir)
        if inc_dir is None:
            print("未在 include 头中定位 GNU 配置根常量", file=sys.stderr)
            return 1

        rules = os.path.join(config_dir, "injector.conf")
        with open(rules, "w", encoding="utf-8") as fh:
            fh.write("[GLOBAL]\nMONITOR ON\nHIDE /nsp_main_rule\n")

        exe = compile_binary(tmpdir, inc_dir)
        if exe is None:
            return 1

        print("── 模块配置下发（框架读 → 按 owner 过滤 → 模块消费）──")
        r = subprocess.run([exe, rules, modules], capture_output=True, text=True,
                           env=dict(os.environ))
        print(r.stdout, end="")
        if r.stderr:
            print(r.stderr, end="", file=sys.stderr)
        if r.returncode != 0:
            print("配置下发归属测试失败")
            return 1

        probe = compile_overlong_probe(tmpdir, inc_dir)
        if probe is None:
            return 1
        print("── 超长行整份作废 + 文件形态/下发形态差分 ──")
        r = subprocess.run([probe, rules, modules], capture_output=True, text=True,
                           env=dict(os.environ))
        print(r.stdout, end="")
        if r.stderr:
            print(r.stderr, end="", file=sys.stderr)
        if r.returncode != 0:
            print("超长行整份作废/差分测试失败")
            return 1
        print("配置下发归属测试通过 ✔")
        return 0


if __name__ == "__main__":
    sys.exit(main())
