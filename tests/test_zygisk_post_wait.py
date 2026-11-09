#!/usr/bin/env python3
"""zygisk post-specialize 等待预算回归：`DEFER <ms>` 的解析矩阵 + 三处契约。

预算由 injector 在 pre 的 `DEFER` 应答里下发（proto 4 起带数字），模块据此决定
post 等多久：0 = 不等待、一次 mountinfo 都不读。解析逻辑单独放在
`src/zygisk/post_wait.h`（不依赖 android/log.h），所以本套件在宿主用 `cc` 直编
它跑真函数，不做文本模拟。

判别性：把 `nsp_post_wait_budget` 改回「非零即按上限等」、让裸 `DEFER` 返回上限、
或把超限值原样返回，矩阵里对应的用例立刻失败；把模块的等待改回编译期常量、
或让它回到按步进计数（旧实现把整表扫描的耗时排除在预算之外），静态契约失败。
"""
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]

HARNESS = r'''
#include "post_wait.h"
#include <assert.h>
#include <stdio.h>

int main(void) {
    /* 带预算：数字在 DEFER 之后，允许前导空白 */
    assert(nsp_post_wait_budget("DEFER 150") == 150);
    assert(nsp_post_wait_budget("DEFER 1") == 1);
    assert(nsp_post_wait_budget("DEFER 1000") == 1000);
    assert(nsp_post_wait_budget("DEFER  7") == 7);
    assert(nsp_post_wait_budget("DEFER\t30") == 30);
    /* 先认数字，尾巴不参与判定（未来 injector 追加字段不该让旧模块整段失效） */
    assert(nsp_post_wait_budget("DEFER 150x") == 150);

    /* 超上限截断：多写一个 0 不该把应用冻在 specialize 上几十秒 */
    assert(nsp_post_wait_budget("DEFER 1001") == NSP_POST_WAIT_MAX_MS);
    assert(nsp_post_wait_budget("DEFER 999999999") == NSP_POST_WAIT_MAX_MS);

    /* 不等待：裸 DEFER、0、负数、乱码 */
    assert(nsp_post_wait_budget("DEFER") == 0);
    assert(nsp_post_wait_budget("DEFER ") == 0);
    assert(nsp_post_wait_budget("DEFER 0") == 0);
    assert(nsp_post_wait_budget("DEFER -5") == 0);
    assert(nsp_post_wait_budget("DEFER  ") == 0);
    assert(nsp_post_wait_budget("DEFER abc") == 0);

    /* 非 DEFER 应答一律不等；大小写与错位前缀也不算（模块用同一前缀判 pending） */
    assert(nsp_post_wait_budget("OK") == 0);
    assert(nsp_post_wait_budget("ERR") == 0);
    assert(nsp_post_wait_budget("") == 0);
    assert(nsp_post_wait_budget(NULL) == 0);
    assert(nsp_post_wait_budget("defer 150") == 0);
    assert(nsp_post_wait_budget("DEFE 150") == 0);
    assert(nsp_post_wait_budget("XDEFER 150") == 0);

    /* 绝不返回负数或越界值（调用方拿它做循环上界） */
    assert(NSP_POST_WAIT_MAX_MS > 0 && NSP_POST_WAIT_MAX_MS <= 10000);
    puts("预算解析矩阵通过");
    return 0;
}
'''


def read(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


def grab_define(text, name):
    m = re.search(rf"^#define\s+{name}\s+(\d+)", text, re.M)
    return int(m.group(1)) if m else None


def main():
    cc = shlex.split(os.environ.get("CC", "cc"))
    with tempfile.TemporaryDirectory(prefix="nsp-zygisk-wait-") as tmp:
        src = Path(tmp) / "contract.c"
        src.write_text(HARNESS)
        exe = Path(tmp) / "contract"
        subprocess.run(cc + ["-std=c23", "-O1", "-Wall", "-Wextra", "-Werror",
                             "-I" + str(ROOT / "src/zygisk"), str(src), "-o", str(exe)],
                       check=True)
        subprocess.run([str(exe)], check=True)

    # ── 契约：同一个上限在两处头文件里必须同值 ──
    mod_max = grab_define(read("src/zygisk/post_wait.h"), "NSP_POST_WAIT_MAX_MS")
    cfg_max = grab_define(read("include/config_parser.h"), "NSP_ZYGISK_POST_WAIT_MAX_MS")
    assert mod_max == cfg_max, f"模块上限 {mod_max} 与配置上限 {cfg_max} 不一致"

    # ── 契约：模块侧 ──
    module = read("src/zygisk/zygisk_module.cpp")
    assert re.search(r"^#define\s+NSP_ZYGISK_PROTO\s+4\b", module, re.M), \
        "proto 4 才能收到带毫秒数的 DEFER"
    assert "nsp_post_wait_budget(reply)" in module, "预算必须从应答里解出来"
    assert "wait_storage_proxied(post_wait_ms_" in module, \
        "等待必须用应答下发的预算，不得回到编译期常量"
    assert ".events = 0" in module, \
        "mountinfo 只当事件源：events 置位会把等事件变成忙轮询"
    assert "monotonic_ms()" in module, "预算必须按墙钟算（探测自身的耗时也吃预算）"
    assert "poll(&pfd, 1," in module, "等的是挂载表变化事件，不是步进轮询"

    # ── 契约：injector 侧下发 ──
    ipc = read("src/injector/ipc_server.c")
    assert '"DEFER %d"' in ipc, "proto>=4 的 DEFER 必须带毫秒数"
    assert "IPC_PROTO_POST_WAIT" in ipc, "带数字的应答只能发给认识它的模块"
    assert "g_global_cfg.zygisk_post_wait_ms" in ipc, "预算来自 [GLOBAL] 配置"

    # ── 契约：配置解析与文档 ──
    assert '"ZYGISK_POST_WAIT_MS"' in read("src/config/config_parser.c"), \
        "解析分派缺失"
    assert "ZYGISK_POST_WAIT_MS" in read("docs/config.md"), "配置键未写入文档"

    print("zygisk post 等待预算检查通过：解析矩阵、上限同值、模块按应答预算、"
          "injector 按 proto 下发、配置键有文档")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
