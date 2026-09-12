/* 项目内 libfuse 子模块（subprojects/libfuse）的兼容转接头。
 *
 * 源码统一使用 <fuse3/fuse.h> 系统布局引用；子模块源码树头文件为平铺
 * 布局（include/fuse.h）。此目录将系统布局转发到子模块头文件，仅在
 * 构建优先采用项目内 libfuse 时加入头文件搜索路径（见 meson.build）。
 */
#pragma once
#include <fuse.h>
