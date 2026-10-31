#!/usr/bin/env python3
"""`do_combined_mount` 合并挂载失败回滚的失败注入回归（确定性用例）。

背景（本用例守护的修复，src/injector/ns_utils.c 的 do_combined_mount 回滚分支）：
  合并挂载在真正 bind 项目 FUSE 之前，会先卸载 target/backup 下的子挂载以及
  target 本身。若随后的 `mount(source, target, MS_BIND|MS_REC)` 失败（应用
  命名空间内源不可见/只读等），旧实现直接 `return err` —— 应用被留在"裸"状态
  （连 /storage/emulated 都没有，直到进程重启或重试成功）。修复后以应用 ns 内
  始终存活的**族根**重新 bind 出原生视图（与 cleanup_app_mounts 同源），失败
  才 loud 报错交由重试队列。

做法：tests/fixtures/ns_combined_rollback_driver.c 把实际源码
src/injector/ns_utils.c 整体 #include（-DNS_UTILS_SRC=），只把 mount/umount2
经 -Wl,--wrap 换成可控返回值；do_combined_mount 全走真实实现。因此不依赖
命名空间、FUSE、特权与调度运气。

覆盖：
  A. 源 bind 失败 + 族根可用 → 第二次 mount 以族根为源回滚、日志「已回滚」、
     返回原始 errno。
  B. 源 bind 失败 + 族根不可用 → 不回滚、loud 报错、返回原始 errno。
  C. 对照：源 bind 成功 → 不触发回滚。
  D. 目标视图未就绪（readiness_ms=0）→ 在任何卸载之前返回 ENOENT。
  E. 后台通道（NSP_READINESS_QUIET，异步扫描/失败重试）：目标缺失属预期未就绪
     ——零 WARN/ERROR、不写 error.log、不宣称"交由重试队列"，只留一条 DEBUG 说明
     （旧实现按普通失败记 WARN，真机表现为每个应用启动都刷一条"挂载失败"）。
  F. 对照：同一缺失走权威尝试（readiness_ms=0，POST/旧通道）→ 仍须 loud。
  G. 源预检：源在应用命名空间里不是 FUSE 挂载（不同 ROM 的 /mnt 传播只带目录、
     不带 FUSE）→ **零卸载、零挂载**返回 ENODEV，目标原样保留（旧实现先把原生
     视图拆掉，再把普通空目录 bind 成 /storage/emulated → 应用存储整个变空）。
  H. 挂载后校验：目标没有变成 FUSE 视图 → 卸载本次挂载 + 族根回滚 + EIO。
  I. 传播隔离：MS_PRIVATE 必须发生在第一次卸载之前（否则共享挂载组上的卸载事件
     会传播到 zygote/其它应用命名空间，真机表现为"整机存储都空了"）。
  S1（静态契约）：异步通道的参数结构（CombinedMountArgs）必须 calloc。该结构随
     功能增长（分段计时 seg 等），异步通道用 malloc 且漏初始化 seg 时，子进程
     SEG_MARK 往垃圾地址写 → SIGSEGV → 完成管道 EOF（read=0）→ 上层按"挂载失败"
     重试，日志只有「异步挂载结果不可得」。malloc 出来的内存是否为零取决于堆复用，
     所以直接盯源码而不是靠运气。

退出码：全部通过 0，任一失败 1。环境变量 NS_UTILS_SRC 可指向另一份源码副本
（用于验证本用例确能捕获旧实现）：指向 HEAD 的 ns_utils.c 时 E3/E4/E5（静默口径）、
G2/G3（源预检）、H1/H2（挂载后校验）、I1（传播隔离）、S1（参数结构零初始化）必失败。
"""
import os
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DRIVER = ROOT / "tests" / "fixtures" / "ns_combined_rollback_driver.c"
NS_UTILS_SRC = os.environ.get("NS_UTILS_SRC") or str(ROOT / "src" / "injector" / "ns_utils.c")


def check_async_args_zero_init(src_path):
    """S1：异步挂载通道的参数结构必须零初始化（calloc）。

    CombinedMountArgs 会随功能增长（[ns计] 的 seg 就是这么加进来的），异步通道
    若仍用 malloc 且漏给新字段赋值，子进程 SEG_MARK 就会往垃圾地址写 → SIGSEGV
    → 完成管道 EOF（read=0）→ 上层按"挂载失败"重试（真机/沙箱都复现过：core 里
    seg 指向已释放的包名字符串）。malloc 内存是否为零取决于堆复用，故直接盯源码。
    """
    text = Path(src_path).read_text(encoding="utf-8", errors="replace")
    hits = [i + 1 for i, ln in enumerate(text.splitlines())
            if "malloc(sizeof(struct CombinedMountArgs))" in ln]
    if hits:
        print(f"❌ S1 异步挂载参数结构未零初始化：{src_path} 第 {hits[0]} 行仍是 "
              f"malloc(sizeof(struct CombinedMountArgs))，必须 calloc(1, …)",
              file=sys.stderr)
        return 1
    print("✅ S1 异步挂载参数结构零初始化（calloc）")
    return 0


def main():
    if not DRIVER.is_file():
        print(f"缺少 fixture 驱动 {DRIVER}", file=sys.stderr)
        return 1
    if not Path(NS_UTILS_SRC).is_file():
        print(f"缺少 ns_utils 源码 {NS_UTILS_SRC}", file=sys.stderr)
        return 1

    cc = shlex.split(os.environ.get("CC", "cc"))
    with tempfile.TemporaryDirectory(prefix="ns_combined_rollback_") as tmp:
        exe = Path(tmp) / "ns_combined_rollback"
        cmd = cc + [
            "-std=c23", "-O1", "-g", "-D_GNU_SOURCE",
            f'-DNS_UTILS_SRC="{NS_UTILS_SRC}"',
            "-I", str(ROOT / "include"),
            "-I", str(ROOT / "src" / "core"),
            "-I", str(ROOT / "src" / "injector"),
            "-ffunction-sections", "-fdata-sections",
            str(DRIVER),
            "-Wl,--gc-sections",
            "-Wl,--wrap=mount", "-Wl,--wrap=umount2", "-Wl,--wrap=statfs",
            "-o", str(exe),
        ]
        build = subprocess.run(cmd, capture_output=True, text=True)
        if build.returncode != 0:
            print("编译失败：\n" + build.stderr, file=sys.stderr)
            return 1
        run = subprocess.run([str(exe)], capture_output=True, text=True)
        sys.stdout.write(run.stdout)
        if run.stderr:
            sys.stderr.write(run.stderr)
        run_rc = run.returncode
    # 静态契约放在驱动跑完之后：NS_UTILS_SRC 指向旧副本时，驱动的判别性用例
    # （E/G/H/I）仍要照常给出结论，别被 S1 提前截断。
    static_rc = check_async_args_zero_init(NS_UTILS_SRC)
    return run_rc or static_rc


if __name__ == "__main__":
    sys.exit(main())
