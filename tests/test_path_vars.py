#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""build_real_base_from_target 路径合成单元测试

覆盖路径合成的基础行为（g_fuse_mount_point 已移除——挂载点根
不合成规则由框架 loader.c 的 path_has_uid_layer 拦截兜底）：
- ? 前缀相对 user 存储动态拼接（ALLOW/相对路径）
- /storage/emulated/ 前缀剥离 uid 后动态拼接
- ? 前缀剥离后为空（指向根）拒绝规则插入
- 系统绝对路径（/data、/mnt、/storage 开头）原样使用

前置：GNU 构建产物 build_gnu（含 path_vars/config_parser/common 对象）。
失败时退出码为 1（勿用管道吞掉退出码）。
"""

import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUILD = os.path.join(ROOT, "build_gnu")
GPR = os.path.join(BUILD, "global_replace_ctl.p")

# 与 /tmp 临时验证一致的 C 测试源码
C_SRC = r"""
#include <stdio.h>
#include <string.h>
#include "path_vars.h"
extern char g_real_root[4096];
static int fails = 0;
static void check(const char* tag, const char* target, int uid, int want_rc, const char* want_out) {
    char out[4096] = {0};
    int rc = build_real_base_from_target(target, uid, out, sizeof out, NULL, NULL, "com.test.app");
    int ok = (rc == want_rc) && (want_rc == 1 ? strcmp(out, want_out) == 0 : 1);
    printf("%-38s rc=%d out='%s' want=%d '%s' %s\n", tag, rc, out, want_rc, want_out ? want_out : "-", ok ? "PASS" : "FAIL");
    if (!ok) fails++;
}
int main(void) {
    strcpy(g_real_root, "/data/media");
    check("? relative strip", "?/foo", 0, 1, "/data/media/0/foo");
    check("? relative uid10", "?/bar", 10, 1, "/data/media/10/bar");
    check("storage emulated", "/storage/emulated/0/foo", 7, 1, "/data/media/7/foo");
    check("? root reject", "?/", 0, 0, NULL);
    check("? root only reject", "?", 0, 0, NULL);
    check("sys abs data", "/data/foo/bar", 0, 1, "/data/foo/bar");
    check("sys abs mnt", "/mnt/nsp_global2/foo", 0, 1, "/mnt/nsp_global2/foo");
    check("relative path", "foo/bar", 0, 1, "/data/media/0/foo/bar");
    printf(fails ? "FAILED %d\n" : "ALL PASS\n", fails);
    return fails;
}
"""


def main():
    for obj in ("src_config_path_vars.c.o", "src_config_config_parser.c.o",
                "src_core_common.c.o", "src_core_path_trie.c.o"):
        if not os.path.exists(os.path.join(GPR, obj)):
            print(f"缺少构建对象 {obj}，请先 ninja -C build_gnu", file=sys.stderr)
            return 1
    tmpdir = tempfile.mkdtemp(prefix="pv_test_")
    src = os.path.join(tmpdir, "pv_test.c")
    exe = os.path.join(tmpdir, "pv_test")
    with open(src, "w", encoding="utf-8") as f:
        f.write(C_SRC)
    objs = " ".join(os.path.join(GPR, o) for o in
                    ("src_config_path_vars.c.o", "src_config_config_parser.c.o",
                     "src_core_common.c.o", "src_core_path_trie.c.o"))
    cc = subprocess.run(
        f"cc -o {exe} {src} -I {ROOT}/include -I {ROOT}/src {objs} -pthread",
        shell=True, capture_output=True, text=True)
    if cc.returncode != 0:
        print("C 编译失败:", cc.stderr, file=sys.stderr)
        return 1
    r = subprocess.run([exe], capture_output=True, text=True)
    print(r.stdout, end="")
    if r.returncode != 0:
        print("path_vars 测试失败", file=sys.stderr)
        return 1
    print("path_vars 测试通过 ✔")
    return 0


if __name__ == "__main__":
    sys.exit(main())
