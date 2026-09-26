/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * override_rules.c — 测试用模块：声明式决策（V3）能力回归
 *
 * 演示并回归"模块只声明、框架单点强制"：
 *   /0/ovr/gone/**   → appear_missing：框架在**所有**回调统一 ENOENT
 *                      （V2 时代读类 ENOENT、写类 EACCES，同一声明两种结果）
 *   /0/ovr/ro/**     → read_only：变更操作统一 EROFS，root 豁免由框架持有
 *   /0/ovr/attrs/**  → 属性覆盖：mode 0700 + uid/gid，且**故意带上 S_IFDIR 位**
 *                      用于验证"权限位可覆盖、类型位始终取自真实属性"
 *   其余             → valid=false（框架直通）
 *
 * 编译：gcc -shared -fPIC -O1 -DNSP_MODULE_BUILD -Iinclude override_rules.c -o override_rules.so
 * 第三方模块视角：仅依赖 nsp_module.h（docs/modules.md 契约）。
 */
#define _GNU_SOURCE
#include "nsp_module.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char* ovr_storage(void) {
    const char* s = getenv("NSP_OVR_STORAGE");
    return (s && s[0]) ? s : "/tmp/fuse_overrides_test/storage";
}

/* 覆盖用的目标属主：与测试进程 uid 明显不同，便于断言"确实来自模块声明" */
#define OVR_UID 4242
#define OVR_GID 4343

static int ovr_resolve(const NspQueryCtx* q, NspPathDecision* out) {
    if (!q || !out || !q->path) return -EINVAL;
    /* 只处理 /0/ 用户层下的 /ovr/ 子树（其余直通） */
    if (!(q->path[0] == '/' && q->path[1] == '0' && q->path[2] == '/')) return 0;
    const char* vp = q->path + 3; /* "ovr/..." */
    if (strncmp(vp, "ovr/", 4) != 0) return 0;
    const char* sub = vp + 3; /* "/gone/..." */

    /* sub 是 "/gone/..." 形式（已剥掉 "ovr" 段），真实路径需带回来 */
    snprintf(out->real_path, sizeof out->real_path, "%s/0/ovr%s", ovr_storage(), sub);
    out->valid = true;

    if (strncmp(sub, "/gone", 5) == 0) {
        out->appear_missing = true;
        return 0;
    }
    if (strncmp(sub, "/ro", 3) == 0) {
        out->read_only = true;
        return 0;
    }
    if (strncmp(sub, "/attrs", 6) == 0) {
        /* S_IFDIR 位是故意的：框架只取 07777，类型位仍取自真实属性 */
        out->attr_override = NSP_OV_MODE | NSP_OV_UID | NSP_OV_GID;
        out->mode = S_IFDIR | 0700;
        out->uid = OVR_UID;
        out->gid = OVR_GID;
        return 0;
    }
    out->valid = false; /* /ovr 下未声明的前缀：直通 */
    return 0;
}

static int ovr_probe(const NspQueryCtx* q, NspProbeResult* out) {
    if (!out) return -EINVAL;
    (void)q;
    memset(out, 0, sizeof *out);
    return 0; /* valid=false：不逐条目过滤 */
}

static const NspModuleOps ovr_ops = {
    .resolve = ovr_resolve,
    .probe = ovr_probe,
};

const NspModuleInfo nsp_module_info = {
    .magic = NSP_MODULE_MAGIC,
    .abi_version = NSP_MODULE_ABI_VERSION,
    .type = NSP_MODULE_TYPE_RULES,
    .caps = NSP_CAP_REDIRECT | NSP_CAP_HIDE | NSP_CAP_RO,
    .name = "override_rules",
    .version = "1.0",
    .init = NULL,
    .exit = NULL,
    .ops = &ovr_ops,
};
