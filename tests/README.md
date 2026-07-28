# 测试说明

测试流程完全由 Python 脚本驱动（无需编译 C 测试目标）。

## 前置条件

1. 构建 GNU 目标（主线 libfuse3）：

   ```bash
   meson setup build_gnu -Dtarget_os=gnu
   ninja -C build_gnu
   ```

2. 本机需要:
   - `fusermount3`（libfuse3 工具，用于挂载/卸载）
   - Python 3 + `sqlite3` 模块
   - `/dev/fuse` 可访问

## 运行测试

```bash
# 功能测试：基础文件操作 + SQLite + 并发压力
python3 tests/test_functional.py

# 规则边界测试：ALLOW/REDIRECT/HIDE/RO/通配符/优先级/沙盒/热重载
python3 tests/test_rules.py

# 指定 daemon 路径（默认使用 build_gnu/fuse_daemon）
FUSE_DAEMON=/path/to/fuse_daemon python3 tests/test_rules.py
```

## 测试覆盖

### test_functional.py
- 模块 1: 基础文件操作（创建/读取/删除/重命名/大文件/追加/stat）
- 模块 2: SQLite 数据库（建表/事务/回滚/WAL/BLOB/多连接）
- 模块 3: 并发压力（多线程读写、多进程写入、SQLite 并发、混合负载、stat 风暴）

### test_rules.py
- REDIRECT 基本与嵌套
- ALLOW + REDIRECT 组合
- HIDE（精确路径、通配符）
- RO 只读（可读、写拒）
- 最长前缀优先、HIDE 覆盖 REDIRECT
- 沙盒交互（SANDBOX ON/OFF + 各类规则）
- Unicode/特殊字符/深层路径边界
- 规则热重载（inotify）

> 注意：配置中的 REDIRECT 虚拟前缀不含 user_id（如 `/云盘/`），
> 测试通过 `/0/云盘/...` 访问（FUSE 自动剥离 `/0/` 后匹配）。
