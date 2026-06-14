# Fuse-Proxy Patches for libfuse

## 概述

这些补丁将 Google/libfuse(Android 分支)中的 FUSE passthrough 特性移植到
mainline libfuse 3.18.2，使其能在 Android 设备上使用 FUSE passthrough 功能。

## 补丁列表

| 补丁 | 文件 | 说明 |
|------|------|------|
| 0001 | `include/fuse_kernel.h` | 添加 passthrough 内核协议定义 |
| 0002 | `include/fuse_lowlevel.h` | 添加 passthrough 字段、回调和声明 |
| 0003 | `lib/fuse_lowlevel.c` | 实现 passthrough API 函数 |
| 0004 | `include/fuse.h` + `lib/fuse.c` | 在 fuse_context 中暴露 fuse_req_t |
| 0005 | `include/fuse_common.h` | conn_info 添加 fd, file_info 添加 passthrough_fh |

## 应用方法

```bash
cd /path/to/libfuse-source
git am /path/to/Fuse-Proxy/patches/0001-*.patch
git am /path/to/Fuse-Proxy/patches/0002-*.patch
git am /path/to/Fuse-Proxy/patches/0003-*.patch
git am /path/to/Fuse-Proxy/patches/0004-*.patch
git am /path/to/Fuse-Proxy/patches/0005-*.patch
```

或者手动 patch:

```bash
cd /path/to/libfuse-source
patch -p1 < /path/to/Fuse-Proxy/patches/0001-*.patch
patch -p1 < /path/to/Fuse-Proxy/patches/0002-*.patch
patch -p1 < /path/to/Fuse-Proxy/patches/0003-*.patch
patch -p1 < /path/to/Fuse-Proxy/patches/0004-*.patch
patch -p1 < /path/to/Fuse-Proxy/patches/0005-*.patch
```

然后重新编译:

```bash
meson setup build_static_release --buildtype=release \
    --default-library=static \
    -Dprefix=/path/to/install-dir \
    -Denable-native=true
ninja -C build_static_release
ninja -C build_static_release install
```

## 移植的特性

### FUSE Passthrough 支持
- `struct fuse_entry_bpf_out` — backing_action, backing_fd, bpf_action, bpf_fd
- `fuse_passthrough_enable()` — API 版本协商(V0→V1→V2→STABLE)
- `FUSE_PASSTHROUGH_API_*` 枚举
- Android passthrough ioctls (FUSE_DEV_IOC_PASSTHROUGH_OPEN_V0/V1/V2)

### 高层 API 集成
- `struct fuse_conn_info` 增加 `int fd` 字段（暴露 /dev/fuse 设备 fd）
- `struct fuse_context` 增加 `fuse_req_t req` 字段（暴露请求句柄）
- `struct fuse_file_info` 增加 `uint32_t passthrough_fh` 字段
- `fuse_passthrough_enable()` 声明（可在高层 API 中调用）

### Android 内核兼容性
- `FUSE_INIT_EXT` 兼容性修复（某些未修复的 Android 内核同时设置 FUSE_INIT_EXT 和旧的 FUSE_PASSTHROUGH 值）
- `FUSE_PASSTHROUGH` 使用 `(1 << 31)` 匹配实际 Android 内核（而非 upstream 的 `(1ULL << 37)`）
- `FUSE_CANONICAL_PATH` opcode (用于 inotify)
- `fuse_reply_canonical_path()` / `canonical_path` callback
