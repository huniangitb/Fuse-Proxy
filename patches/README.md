# Fuse-Proxy Patches for libfuse

## 概述

这些补丁将 Google/libfuse(Android 分支)中的 FUSE passthrough 特性移植到
mainline libfuse 3.18.2，使其能在 Android 设备上使用 FUSE passthrough 功能。

## 补丁列表

| 补丁 | 文件 | 说明 |
|------|------|------|
| 0001 | `include/fuse_kernel.h` | 添加 passthrough 内核协议定义 |
| 0002 | `include/fuse_lowlevel.h` | 添加 passthrough 字段和回调 |
| 0003 | `lib/fuse_lowlevel.c` | 实现 passthrough API 函数 |

## 应用方法

```bash
cd /path/to/libfuse-source
git am /path/to/Fuse-Proxy/patches/0001-*.patch
git am /path/to/Fuse-Proxy/patches/0002-*.patch
git am /path/to/Fuse-Proxy/patches/0003-*.patch
```

或者手动 patch:

```bash
cd /path/to/libfuse-source
patch -p1 < /path/to/Fuse-Proxy/patches/0001-*.patch
patch -p1 < /path/to/Fuse-Proxy/patches/0002-*.patch
patch -p1 < /path/to/Fuse-Proxy/patches/0003-*.patch
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

### Android 专用特性
- `FUSE_CANONICAL_PATH` opcode (用于 inotify)
- `fuse_reply_canonical_path()` / `canonical_path` callback
