#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""COPY_FILE_RANGE 一律交回内核，不进入 libfuse 高层回退路径
=============================================================
本文件不实现 copy_file_range，libfuse 于是把这类请求交给高层的
fuse_lib_copy_file_range()。该 wrapper 在判断操作是否存在**之前**就先取线程
上下文（fuse.c 的 fuse_fs_copy_file_range 里 fuse_get_context()），上下文缺失
（会话销毁/线程收尾阶段）时按小偏移解空指针，SIGSEGV 落在 libc 的
pthread_getspecific 里——现场崩溃栈就是这条链。

修法不是「在崩溃处加保护」，而是让请求根本到不了高层：libfuse fork 增加
fuse_disable_copy_file_range()，把 session 的 lowlevel 操作表里
copy_file_range 置 NULL；低层 copy_file_range_common() 见操作表为空，直接
回 ENOSYS，内核据此永久改走 read/write 循环（我们长期在用的路径）。

判别方式（静态契约，全部对着源码文本，不跑 FUSE）：
  C1 fork 头文件里有该 API 的声明
  C2 fork 实现里确实把 session 的操作表项置 NULL，且两个入参各自判空
  C3 daemon 在进入任何 loop 之前调用它（调用点下标必须早于 fuse_loop /
     fuse_loop_mt）
  C4 调用点用弱引用守卫：GNU 开发构建链接系统 libfuse（3.18.3）没有该 API，
     缺失时要能照常链接与启动
  C5 daemon 的 vfs_ops 表里没有 copy_file_range（一旦有人「顺手实现」它，
     崩溃点会复活，而 C2 的关闭动作会变成死代码）
  C6 低层确实在操作表为空时回 ENOSYS（内核回退的前提）
  C7 调用点唯一
  C8 文档写着这条策略

退出码：0 通过、1 失败。
"""
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
FUSE_H = os.path.join(ROOT, "subprojects", "libfuse", "include", "fuse.h")
FUSE_C = os.path.join(ROOT, "subprojects", "libfuse", "lib", "fuse.c")
FUSE_LL = os.path.join(ROOT, "subprojects", "libfuse", "lib", "fuse_lowlevel.c")
DAEMON = os.path.join(ROOT, "src", "daemon", "fuse_daemon.c")
ARCH = os.path.join(ROOT, "docs", "architecture.md")

API_SIG = "void fuse_disable_copy_file_range(struct fuse *f);"
WEAK_DECL = ("extern void fuse_disable_copy_file_range(struct fuse *f) "
             "__attribute__((weak));")


def read(path):
    with open(path, encoding="utf-8") as fp:
        return fp.read()


def check(name, ok, detail=""):
    print(f"case={name:<46} ok={1 if ok else 0} {detail}")
    return 0 if ok else 1


def body_of(text, start_marker, span=400):
    start = text.find(start_marker)
    if start < 0:
        return ""
    return text[start:start + span]


def run_contracts():
    failures = 0
    fuse_h = read(FUSE_H)
    fuse_c = read(FUSE_C)
    fuse_ll = read(FUSE_LL)
    daemon = read(DAEMON)
    arch = read(ARCH)

    impl = body_of(fuse_c, "void fuse_disable_copy_file_range(struct fuse *f)", 300)

    failures += check("C1_fork_declares_api", API_SIG in fuse_h)
    failures += check("C2_fork_clears_lowlevel_op",
                      "f->se->op.copy_file_range = NULL;" in impl and
                      "f == NULL || f->se == NULL" in impl,
                      "impl_len=%d" % len(impl))

    call_at = daemon.find("fuse_disable_copy_file_range(f);")
    loop_at = daemon.find("fuse_loop(f)")
    loop_mt_at = daemon.find("fuse_loop_mt(f, lcfg)")
    failures += check("C3_daemon_calls_before_loop",
                      call_at >= 0 and loop_at > call_at and
                      loop_mt_at > call_at,
                      "call=%d loop=%d loop_mt=%d" % (call_at, loop_at, loop_mt_at))

    failures += check("C4_daemon_weak_guarded",
                      WEAK_DECL in daemon and
                      "if (fuse_disable_copy_file_range != NULL)" in daemon)

    table = body_of(daemon, "static struct fuse_operations vfs_ops = {", 3000)
    failures += check("C5_daemon_does_not_implement_it",
                      table != "" and ".copy_file_range" not in table,
                      "table_len=%d" % len(table))

    ll_body = body_of(fuse_ll, "static void copy_file_range_common(", 1200)
    failures += check("C6_lowlevel_replies_enosys",
                      "if (req->se->op.copy_file_range)" in ll_body and
                      "fuse_reply_err(req, ENOSYS);" in ll_body,
                      "ll_len=%d" % len(ll_body))

    failures += check("C7_single_call_site",
                      daemon.count("fuse_disable_copy_file_range(f);") == 1,
                      "count=%d" % daemon.count("fuse_disable_copy_file_range(f);"))

    failures += check("C9_logs_when_applied",
                      "FUSE copy_file_range: 关闭派发" in daemon)
    failures += check("C8_docs_describe_policy",
                      "COPY_FILE_RANGE" in arch and "ENOSYS" in arch)
    return failures


def main():
    failures = run_contracts()
    if failures:
        print(f"\n静态契约失败 {failures} 条")
        return 1
    print("all cases passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
