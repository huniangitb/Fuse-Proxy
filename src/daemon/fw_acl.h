#ifndef FW_ACL_H
#define FW_ACL_H
/*
 * fw_acl.h — 访问控制（对齐 Android 原生 FUSE 的用户态策略层）
 *
 * 背景（AOSP 事实，见 docs/architecture.md「访问控制」）：
 *   - Android 的 /storage/emulated FUSE **故意不加 default_permissions**
 *     （system/vold/Utils.cpp：「we don't want kernel to do lower filesystem
 *     permission checks before routing to FUSE daemon」），属主/权限由 daemon
 *     合成；挂载层我们与 AOSP 等价。
 *   - AOSP 的唯一门是 FuseDaemon.cpp 的 is_app_accessible_path()，策略外包给
 *     MediaProvider 的 13 个方法（MediaStore owner_package_name + appops +
 *     进程 mount mode）。
 *   - 我们的等价实现即本模块：**唯一判定点**，由 fw_route 统一调用，回调里
 *     不得再写访问判定（与「决策强制单点」同一条纪律）。
 *
 * 拒绝语义照 AOSP 分工，三码不混用：
 *   ENOENT = 「对他包私有目录假装不存在」（/Android/data|obb/<pkg>）
 *   EACCES = 「存在但不许」（写意图 open、setattr、目录写、列举骨架目录）
 *   EPERM  = 「结构层不许」（删/改他应用文件、删/改名顶层目录、非法文件名）
 */
#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

/* ---- 判定结果 ---- */
typedef enum {
    NSP_ACL_ALLOW = 0,
    NSP_ACL_DENY_ENOENT,
    NSP_ACL_DENY_EACCES,
    NSP_ACL_DENY_EPERM,
} NspAclVerdict;

/* ---- 操作种类（决定拒绝码，不决定是否拒绝） ---- */
typedef enum {
    NSP_ACL_OP_GENERIC_READ = 0, /* 读类回调的缺省值：lookup/getattr/read/readlink… */
    NSP_ACL_OP_GENERIC_WRITE,    /* 变更类回调的缺省值 */
    NSP_ACL_OP_OPENDIR,
    NSP_ACL_OP_READDIR,
    NSP_ACL_OP_WRITE_OPEN,  /* open 且 flags 表明写意图 */
    NSP_ACL_OP_CREATE,
    NSP_ACL_OP_MKDIR,
    NSP_ACL_OP_DELETE,      /* unlink */
    NSP_ACL_OP_RMDIR,
    NSP_ACL_OP_RENAME_SRC,
    NSP_ACL_OP_RENAME_DST,
    NSP_ACL_OP_SETATTR,
    NSP_ACL_OP_SETXATTR,
    NSP_ACL_OP_LINK,
    NSP_ACL_OP_SYMLINK,
    NSP_ACL_OP_MKNOD,
    NSP_ACL_OP_ACCESS,      /* 需要配合 mask 字段 */
} NspAclOp;

/* ---- 路径分类（对应 AOSP 的正则，不散落字符串判断） ---- */
typedef enum {
    NSP_PATH_ROOT = 0,       /* 卷根（/storage/emulated，即 v1 的挂载点 "/"） */
    NSP_PATH_USER_ROOT,      /* 用户根（/0 = /sdcard 本体）：**可列举**，与卷根不同 */
    NSP_PATH_SKELETON,       /* /Android/data、/Android/obb、/Android/media 本身 */
    NSP_PATH_OWNED,          /* /Android/data/<pkg>[/...]、/Android/obb/<pkg>[/...] */
    NSP_PATH_ANDROID_MEDIA,  /* /Android/media/<pkg>[/...]（AOSP 明确「不是私有目录」） */
    NSP_PATH_TOPLEVEL,       /* 用户根下的一级条目 /Download、/DCIM… */
    NSP_PATH_NORMAL,         /* 其余 */
} NspPathClass;

/* ---- 调用者身份（数据来源见 fw_acl_identity） ---- */
typedef struct {
    uid_t uid;
    char pkg[128];          /* 解析得到的包名，未知时为 "unknown" */
    bool pkg_known;         /* 包名是否可信（false 时按最保守口径处理） */
    bool is_system;         /* uid < AID_APP_START(10000)：AOSP 直接放行 */
    bool privileged;        /* platform 签名（mount-mode 的现有近似，fw_pkg 提供） */
    bool manage_external;   /* MANAGE_EXTERNAL_STORAGE（appops，fw_pkg_manages_external 提供） */
    bool legacy;            /* legacy storage（appops，fw_pkg_has_legacy_storage 提供） */
    bool cross_app_isolated; /* 跨应用隔离生效（沿用 [GLOBAL] ALLOW_CROSS_APP_DATA，单一出处
                                fw_rules_cross_app_isolated()）：false 时他包 data/obb 按旧行为放行 */
} NspAclIdentity;

/* ---- 判定查询 ---- */
typedef struct {
    uid_t uid;
    const char* path;   /* 应用看到的路径，可带 "/<user_id>" 前缀，如 "/0/Android/data/com.x/y" */
    NspAclOp op;
    int access_mask;    /* 仅 NSP_ACL_OP_ACCESS：R_OK/W_OK/X_OK/F_OK 位或 */
    bool is_dir;        /* 目标是否为目录（未知传 false） */
} NspAclQuery;

/* 纯函数判定（可直编单测，不依赖全局状态）：给定查询与身份，返回裁决。 */
NspAclVerdict fw_acl_decide(const NspAclQuery* q, const NspAclIdentity* id);

/* 路径分类（owner_pkg 仅在 NSP_PATH_OWNED / NSP_PATH_ANDROID_MEDIA 时写入，
   无包名时写空串）。 */
NspPathClass fw_acl_classify(const char* path, char* owner_pkg, size_t size);

/* 判定结果 → 负 errno（ALLOW 返回 0）。 */
int fw_acl_errno(NspAclVerdict v);

/* 生产路径：按 uid/pid 组装身份（包名走 fw_pkg，特权走 packages.list 的 seinfo，
   All files access 与 legacy storage 都走 appops，见 fw_pkg.h）。 */
void fw_acl_identity(uid_t uid, pid_t pid, NspAclIdentity* out);

/* 唯一执行点：fw_route 在完成规则决策后调用，非 0 即拒绝（返回负 errno）。
   拒绝日志按路径限速（首条 + 每 1024 条），绝不在热路径刷屏。 */
int fw_acl_check(uid_t uid, pid_t pid, const char* path, NspAclOp op, bool is_dir, int access_mask);

/* 测试钩子：把后续判定的调用者 uid 强制成给定值（0 = 关闭）。仅 GNU 测试使用，
   生产代码永不调用；用于在宿主单 uid 环境里验证 uid>=10000 的判定分支。 */
void fw_acl_set_test_uid(uid_t uid);
uid_t fw_acl_test_uid(void);

#endif /* FW_ACL_H */
