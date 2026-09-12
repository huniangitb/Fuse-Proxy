/* 转发到 cmake 子项目 json-c 的伞头（见 compat/fuse3/fuse.h 说明）。
 *
 * 上游 json-c 头文件为平铺布局（json.h 由 cmake 按 json.h.cmakein 生成到
 * 其构建目录）；源码统一使用 <json-c/json.h> 系统布局引用，此转接头将其
 * 转发到平铺 json.h。cmake 依赖透传的 -I（含源码根与生成构建目录）保证
 * json.h 及其内部引用的生成头（json_config.h 等）可解析。
 */
#pragma once
#include <json.h>
