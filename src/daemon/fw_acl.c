/*
 * fw_acl.c — 访问控制唯一判定点（对齐 Android 原生 FUSE 的 userspace 策略层）
 *
 * 设计纪律：
 *   1. 只有 fw_acl_decide 一份判定表；回调与 fw_route 不得各自写 if。
 *   2. 分类用「路径形态」而不是散落字符串比较：卷根 / 骨架目录 / 他包私有
 *      目录 / Android/media / 顶层条目，集中在本文件。
 *   3. 数据来源（包名、特权、appops）与判定解耦：身份由 fw_acl_identity 组装，
 *      纯函数 fw_acl_decide 只吃 NspAclIdentity，可在宿主直编单测。
 */
#include "fw_acl.h"

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <strings.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "fw_pkg.h"
#include "fw_rules.h" /* fw_rules_cross_app_isolated：隔离开关唯一出处 */
#include "nsp_log.h"

/* AOSP FuseDaemon.cpp: AID_APP_START */
#define NSP_ACL_AID_APP_START 10000u

/* AOSP MediaStore DEFAULT_FOLDER_NAMES（12 项 + Android）。
   顶层目录的结构规则只认这张表——表与 AOSP 同步，不在别处硬编码名字。 */
static const char* const k_default_toplevel[] = {
    "Alarms",    "Android",     "Audiobooks", "DCIM",    "Documents",
    "Download",  "Movies",      "Music",      "Notifications",
    "Pictures",  "Podcasts",    "Recordings", "Ringtones",
};

static bool acl_is_default_toplevel(const char* name, size_t len) {
    for (size_t i = 0; i < sizeof(k_default_toplevel) / sizeof(k_default_toplevel[0]); i++) {
        const char* d = k_default_toplevel[i];
        if (strlen(d) == len && strncasecmp(d, name, len) == 0) return true;
    }
    return false;
}

/* 跳过路径开头的可选 "/<user_id>" 段（v1 挂载点 = /storage/emulated，
   应用看到的是 "/0/..."）。返回指向剩余部分的指针（可能指向结尾 '\0'）。 */
static const char* acl_skip_user_layer(const char* p) {
    while (*p == '/') p++;
    const char* seg = p;
    const char* e = p;
    while (*e && *e != '/') e++;
    if (e == seg) return p; /* 空段 */
    for (const char* c = seg; c < e; c++) {
        if (*c < '0' || *c > '9') return p; /* 非纯数字：不是 user 层 */
    }
    /* 纯数字首段即 <user_id> 层（v1 挂载点 /storage/emulated 下应用只看到
       "/0/..."）；"\0" 或 "/" 结尾时它是卷根本身，剥完指向结尾 → 分类为 ROOT。 */
    const char* q = e;
    while (*q == '/') q++;
    return q;
}

/* 取下一段（不含 '/'），返回下一段起点；*len 为段长。 */
static const char* acl_next_seg(const char* p, const char** seg, size_t* len) {
    while (*p == '/') p++;
    *seg = p;
    size_t n = 0;
    while (p[n] && p[n] != '/') n++;
    *len = n;
    p += n;
    while (*p == '/') p++;
    return p;
}

static bool acl_seg_eq(const char* seg, size_t len, const char* lit) {
    size_t l = strlen(lit);
    return len == l && strncasecmp(seg, lit, len) == 0;
}

NspPathClass fw_acl_classify(const char* path, char* owner_pkg, size_t size) {
    if (owner_pkg && size) owner_pkg[0] = '\0';
    if (!path) return NSP_PATH_NORMAL;
    /* 卷根 "/" 与用户根 "/0" 必须分开：应用天天列举 /sdcard（= "/0"），
       而 AOSP 只禁列举**卷根**（那一层只列出 "0"）。 */
    const char* p = path;
    while (*p == '/') p++;
    if (!*p) return NSP_PATH_ROOT;
    {
        const char* e = p;
        while (*e && *e != '/') e++;
        bool digits = (e > p);
        for (const char* c = p; c < e && digits; c++)
            if (*c < '0' || *c > '9') digits = false;
        if (digits) {
            const char* q = e;
            while (*q == '/') q++;
            if (!*q) return NSP_PATH_USER_ROOT;
            p = q;
        }
    }
    if (!*p) return NSP_PATH_USER_ROOT;

    const char* seg1;
    size_t len1;
    p = acl_next_seg(p, &seg1, &len1);
    if (len1 == 0) return NSP_PATH_ROOT;

    if (!acl_seg_eq(seg1, len1, "Android")) {
        /* 一级条目 → TOPLEVEL；还有后续段 → NORMAL */
        return *p ? NSP_PATH_NORMAL : NSP_PATH_TOPLEVEL;
    }

    const char* seg2;
    size_t len2;
    const char* after2 = acl_next_seg(p, &seg2, &len2);
    if (len2 == 0) return NSP_PATH_NORMAL; /* "/Android" 本身 */

    const bool is_data = acl_seg_eq(seg2, len2, "data");
    const bool is_obb = acl_seg_eq(seg2, len2, "obb");
    const bool is_media = acl_seg_eq(seg2, len2, "media");
    if (!is_data && !is_obb && !is_media) return NSP_PATH_NORMAL;
    if (!*after2) return NSP_PATH_SKELETON; /* /Android/data 等骨架目录本身 */

    const char* seg3;
    size_t len3;
    const char* after3 = acl_next_seg(after2, &seg3, &len3);
    if (len3 == 0) return NSP_PATH_NORMAL;

    if (is_media) {
        if (owner_pkg && size) {
            size_t n = len3 < size - 1 ? len3 : size - 1;
            memcpy(owner_pkg, seg3, n);
            owner_pkg[n] = '\0';
        }
        return NSP_PATH_ANDROID_MEDIA;
    }

    /* .nomedia 不是包名：AOSP 明确把它当普通条目放行 */
    if (acl_seg_eq(seg3, len3, ".nomedia")) return NSP_PATH_NORMAL;

    if (owner_pkg && size) {
        size_t n = len3 < size - 1 ? len3 : size - 1;
        memcpy(owner_pkg, seg3, n);
        owner_pkg[n] = '\0';
    }
    (void)after3;
    return NSP_PATH_OWNED;
}

int fw_acl_errno(NspAclVerdict v) {
    switch (v) {
    case NSP_ACL_ALLOW: return 0;
    case NSP_ACL_DENY_ENOENT: return -ENOENT;
    case NSP_ACL_DENY_EACCES: return -EACCES;
    case NSP_ACL_DENY_EPERM: return -EPERM;
    }
    return -EACCES;
}

/* 包名基础名比较（调用方 cmdline 可能带 ":push" 之类进程后缀，而
   /Android/data 下的目录名恒为包名本身）。与 fw_rules 的 br_pkg_same_base
   同口径，但 ACL 不得反向依赖规则引擎内部实现，故各自持有一份最小实现。 */
static bool acl_pkg_same_base(const char* a, const char* b) {
    if (!a || !b) return false;
    size_t la = strcspn(a, ":");
    size_t lb = strcspn(b, ":");
    return la == lb && la > 0 && strncmp(a, b, la) == 0;
}

/* 该目录属主包是否与调用方同 uid（同 uid 多包 = 同一 app 身份，见
   fw_acl_decide 的 NSP_PATH_OWNED 分支）。packages.list 里查不到该包 → false，
   维持原判定（不额外放行）。 */
static bool acl_owner_shares_uid(const char* owner_pkg, uid_t uid) {
    uid_t owner_uid = 0;
    return owner_pkg && owner_pkg[0] && fw_pkg_uid_for_package(owner_pkg, &owner_uid) &&
           owner_uid == uid;
}

static bool acl_op_is_create_like(NspAclOp op) {
    return op == NSP_ACL_OP_CREATE || op == NSP_ACL_OP_MKDIR || op == NSP_ACL_OP_MKNOD ||
           op == NSP_ACL_OP_SYMLINK || op == NSP_ACL_OP_LINK;
}

static bool acl_op_is_destroy_like(NspAclOp op) {
    return op == NSP_ACL_OP_DELETE || op == NSP_ACL_OP_RMDIR;
}

static bool acl_op_is_rename(NspAclOp op) {
    return op == NSP_ACL_OP_RENAME_SRC || op == NSP_ACL_OP_RENAME_DST;
}

NspAclVerdict fw_acl_decide(const NspAclQuery* q, const NspAclIdentity* id) {
    if (!q || !id || !q->path) return NSP_ACL_ALLOW;

    /* AOSP: uid < AID_APP_START 或 daemon 自身 uid → 全放行 */
    if (id->is_system) return NSP_ACL_ALLOW;

    char owner[128];
    NspPathClass cls = fw_acl_classify(q->path, owner, sizeof(owner));

    switch (cls) {
    case NSP_PATH_ROOT:
        /* 应用不得列举卷根（只能按已知 user id 进入）；lookup/stat 放行。
           AOSP pf_access 对卷根的 X_OK 特判放行、列举拒绝。 */
        if (q->op == NSP_ACL_OP_OPENDIR || q->op == NSP_ACL_OP_READDIR)
            return NSP_ACL_DENY_EACCES;
        if (q->op == NSP_ACL_OP_ACCESS && (q->access_mask & W_OK)) return NSP_ACL_DENY_EACCES;
        return NSP_ACL_ALLOW;

    case NSP_PATH_USER_ROOT:
        /* 用户根（/sdcard 本体）：可列举、可 stat；不可删/改名（AOSP 的顶层结构规则
           从这一层开始生效，具体条目由 TOPLEVEL 分支处理）。 */
        if (q->op == NSP_ACL_OP_RMDIR || q->op == NSP_ACL_OP_RENAME_SRC)
            return NSP_ACL_DENY_EPERM;
        return NSP_ACL_ALLOW;

    case NSP_PATH_SKELETON:
        /* /Android/data、/Android/obb、/Android/media 本身：不可列举、不可增删改名 */
        if (q->op == NSP_ACL_OP_OPENDIR || q->op == NSP_ACL_OP_READDIR)
            return NSP_ACL_DENY_EACCES;
        if (acl_op_is_create_like(q->op) || acl_op_is_destroy_like(q->op) ||
            acl_op_is_rename(q->op))
            return NSP_ACL_DENY_EPERM;
        return NSP_ACL_ALLOW;

    case NSP_PATH_OWNED:
        /* 他包私有目录：看不见（AOSP 一律 ENOENT）。自己包 / 同 uid 包 /
           白名单包（[GLOBAL] ALLOW_CROSS_APP_PKGS）/ 特权签名 / 能力豁免（开关开时）
           放行。 */
        /* 包名解析不出来时一律放行：ACL 是「多一道门」，不能变成单点故障。
           与 fw_rules 的跨应用隔离同口径（current_pkg 为 system/unknown 即不隔离），
           否则解析失败会把应用挡在自己的 data 目录外（真实故障，比越权更难排查）。 */
        if (!id->pkg_known) return NSP_ACL_ALLOW;
        if (owner[0] && acl_pkg_same_base(owner, id->pkg)) return NSP_ACL_ALLOW;
        /* 同一 uid 内的多个包（sharedUserId，或系统同进程宿主如 MediaProvider 与
           DownloadProvider 共用 android.process.media）在 Linux DAC 里本就是同一个
           app 身份：/Android/data/<包> 的属主 uid 等于调用方 uid。只按包名比较会把
           它们误判成跨应用（现场表现：下载器读不到 Downloads 的私有目录，ENOENT）。 */
        if (owner[0] && acl_owner_shares_uid(owner, q->uid)) return NSP_ACL_ALLOW;
        if (id->cross_app_allowed) return NSP_ACL_ALLOW;
        if (id->privileged) return NSP_ACL_ALLOW;
        /* 能力豁免（All files access / legacy storage）默认关：系统授权只是"用户
           给了这个能力"，不等于同意读别的应用的私有目录，故由
           [GLOBAL] ALLOW_CROSS_APP_BY_CAPABILITY 显式开启。 */
        if (id->cross_app_by_capability && (id->manage_external || id->legacy))
            return NSP_ACL_ALLOW;
        /* 隔离开关沿用既有配置口径（默认生效）；关闭时按旧行为放行，
           否则这条 AOSP 默认会让 ALLOW_CROSS_APP_DATA ON 的用户突然失效。 */
        return id->cross_app_isolated ? NSP_ACL_DENY_ENOENT : NSP_ACL_ALLOW;

    case NSP_PATH_ANDROID_MEDIA:
        /* AOSP：Android/media 不是私有目录（读放行）；但该目录本身不可改名 */
        if (acl_op_is_rename(q->op)) return NSP_ACL_DENY_EPERM;
        return NSP_ACL_ALLOW;

    case NSP_PATH_TOPLEVEL:
        /* 顶层条目的结构规则（AOSP isDirAccessAllowedForFuse）：
           - 只能建默认目录；- 任何顶层目录不可删；- 顶层目录不可改名。
           建目录另有一条 AOSP 旁路：isDirAccessAllowedForFuse 在整段结构规则之前
           先问 shouldBypassFuseRestrictions()，命中即放行——原生系统里持有
           All files access 的应用根本不经过 MediaProvider 的 FUSE（vold 给它的是
           lowerfs 直通视图），结构规则对它从来没有生效过。本项目把所有应用都收进
           自己的代理视图，这条旁路必须由这里补回来，否则持有该能力的文件管理器
           建不了顶层目录——比原生更严，且与同一目录下建文件成功自相矛盾（文件
           创建不走这条规则）。 */
        if (q->op == NSP_ACL_OP_MKDIR) {
            if (id->manage_external) return NSP_ACL_ALLOW;
            /* 先剥掉 <user_id> 层再取一级名：回调收到的是 "/0/Download" 这种形态，
               直接取首段会把 "0" 当名字，任何新建都被误拒。 */
            const char* seg = nullptr;
            size_t len = 0;
            (void)acl_next_seg(acl_skip_user_layer(q->path), &seg, &len);
            if (len == 0 || !acl_is_default_toplevel(seg, len)) return NSP_ACL_DENY_EACCES;
            return NSP_ACL_ALLOW;
        }
        if (q->op == NSP_ACL_OP_RMDIR) return NSP_ACL_DENY_EACCES;
        if (q->op == NSP_ACL_OP_DELETE && q->is_dir) return NSP_ACL_DENY_EACCES;
        if (q->op == NSP_ACL_OP_RENAME_SRC) return NSP_ACL_DENY_EPERM;
        return NSP_ACL_ALLOW;

    case NSP_PATH_NORMAL:
    default:
        break;
    }

    /* 普通路径：access(2) 的 X_OK 语义按 AOSP —— FUSE 以 MS_NOEXEC 挂载，
       普通文件不可执行（EACCES），目录可进入。 */
    if (q->op == NSP_ACL_OP_ACCESS) {
        if (q->access_mask == F_OK) return NSP_ACL_ALLOW;
        if ((q->access_mask & X_OK) && !q->is_dir) return NSP_ACL_DENY_EACCES;
    }
    return NSP_ACL_ALLOW;
}

/* ---- 生产身份组装 ---- */

static uid_t g_acl_test_uid; /* 0 = 关闭（测试钩子） */

void fw_acl_set_test_uid(uid_t uid) { g_acl_test_uid = uid; }
uid_t fw_acl_test_uid(void) { return g_acl_test_uid; }

void fw_acl_identity(uid_t uid, pid_t pid, NspAclIdentity* out) {
    if (!out) return;
    memset(out, 0, sizeof(*out));
    out->uid = uid;
    out->is_system = ((unsigned)uid < NSP_ACL_AID_APP_START);
    snprintf(out->pkg, sizeof(out->pkg), "%s", "unknown");
    if (!out->is_system) {
        char pkg[128];
        if (fw_pkg_resolve_exact(uid, (pid_t)pid, pkg, sizeof(pkg))) {
            snprintf(out->pkg, sizeof(out->pkg), "%s", pkg);
            out->pkg_known = true;
        }
        out->privileged = fw_pkg_is_privileged(uid);
        out->cross_app_allowed = fw_rules_cross_app_pkg_allowed(out->pkg);
        out->cross_app_by_capability = fw_rules_cross_app_capability();
        /* 总闸关着就不查 appops（一次子进程查询），免得为一条不生效的豁免付代价 */
        if (out->cross_app_by_capability) {
            out->manage_external = fw_pkg_manages_external(uid);
            out->legacy = fw_pkg_has_legacy_storage(uid);
        }
        out->cross_app_isolated = fw_rules_cross_app_isolated();
    }
}

/* ---- 拒绝日志限速（首条 + 每 1024 条），热路径不刷屏 ---- */

static void acl_log_deny(uid_t uid, const char* pkg, const char* path, NspAclOp op, int err) {
    static atomic_ulong seq;
    unsigned long n = atomic_fetch_add_explicit(&seq, 1, memory_order_relaxed) + 1;
    if (n != 1 && (n & 1023u) != 0) return;
    LOG_DBG("访问控制拒绝（累计 %lu 次）: uid=%u pkg=%s op=%d path=%s errno=%d", n, (unsigned)uid,
            pkg ? pkg : "unknown", (int)op, path ? path : "nullptr", err);
}

/* 这次调用会不会用到「持有 All files access」这个事实：只有顶层目录的创建
   会（见 fw_acl_decide 的 NSP_PATH_TOPLEVEL）。身份组装默认不填这一位——能力
   查询是一次 appops 子进程调用（缓存见 fw_pkg.h），不该让每个 FUSE 回调为它
   付钱——所以在这一条分支上按需补一次。 */
static bool acl_wants_capability(const NspAclQuery* q) {
    return q->op == NSP_ACL_OP_MKDIR && fw_acl_classify(q->path, nullptr, 0) == NSP_PATH_TOPLEVEL;
}

int fw_acl_check(uid_t uid, pid_t pid, const char* path, NspAclOp op, bool is_dir, int access_mask) {
    if (g_acl_test_uid) uid = g_acl_test_uid;
    if ((unsigned)uid < NSP_ACL_AID_APP_START) return 0;
    if (!path) return 0;

    NspAclIdentity id;
    fw_acl_identity(uid, pid, &id);
    NspAclQuery q = {.uid = uid, .path = path, .op = op, .access_mask = access_mask, .is_dir = is_dir};
    if (!id.manage_external && acl_wants_capability(&q)) id.manage_external = fw_pkg_manages_external(uid);
    NspAclVerdict v = fw_acl_decide(&q, &id);
    if (v == NSP_ACL_ALLOW) return 0;
    int err = fw_acl_errno(v);
    acl_log_deny(uid, id.pkg, path, op, err);
    return err;
}
