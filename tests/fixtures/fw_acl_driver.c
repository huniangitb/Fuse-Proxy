/*
 * fw_acl_driver.c — fw_acl.c 的判别性驱动（L0，纯逻辑，不挂载）
 *
 * 直编真实源码 src/daemon/fw_acl.c，只桩掉它依赖的两个外部事实源
 * （uid→包名 / 特权签名 / 跨应用隔离开关），因此本驱动断言的每一条都是
 * fw_acl_decide 的真实分支。
 *
 * 判别性：旧实现没有 fw_acl.c（本模块为新增），故「旧源码上必失败」由
 * 文件不存在保证；另有 A 组断言钉住 AOSP 语义（他包私有目录 ENOENT、
 * 骨架目录不可列举、顶层结构规则、access 的 X_OK）。
 */
#define _GNU_SOURCE 1
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

/* ---- 外部事实源的桩（真实实现在 fw_pkg.c / fw_rules.c）---- */
static char g_stub_pkg[128] = "";
static bool g_stub_priv = false;
static bool g_stub_isolated = true;

bool fw_pkg_resolve_exact(uid_t uid, pid_t pid, char* out, size_t size) {
    (void)uid;
    (void)pid;
    if (!g_stub_pkg[0]) return false;
    snprintf(out, size, "%s", g_stub_pkg);
    return true;
}
bool fw_pkg_is_privileged(uid_t uid) {
    (void)uid;
    return g_stub_priv;
}
bool fw_rules_cross_app_isolated(void) { return g_stub_isolated; }

/* 拒绝日志走 LOG_DBG → log_internal：驱动里吞掉（判定逻辑与日志无关） */
#include "nsp_log.h"
void log_internal(LogLevel level, const char* format, ...) {
    (void)level;
    (void)format;
}

#include "fw_acl.c"

/* ---- 断言设施 ---- */
static int g_fail;
static int g_pass;

static const char* cls_name(NspPathClass c) {
    switch (c) {
    case NSP_PATH_ROOT: return "ROOT";
    case NSP_PATH_USER_ROOT: return "USER_ROOT";
    case NSP_PATH_SKELETON: return "SKELETON";
    case NSP_PATH_OWNED: return "OWNED";
    case NSP_PATH_ANDROID_MEDIA: return "ANDROID_MEDIA";
    case NSP_PATH_TOPLEVEL: return "TOPLEVEL";
    case NSP_PATH_NORMAL: return "NORMAL";
    }
    return "?";
}

static void expect_cls(const char* path, NspPathClass want, const char* want_owner) {
    char owner[128] = "";
    NspPathClass got = fw_acl_classify(path, owner, sizeof(owner));
    bool ok = (got == want) && (want_owner == nullptr || strcmp(owner, want_owner) == 0);
    if (ok) {
        g_pass++;
    } else {
        g_fail++;
        printf("❌ 分类 %s: 期望 %s(owner=%s) 实际 %s(owner=%s)\n", path, cls_name(want),
               want_owner ? want_owner : "-", cls_name(got), owner);
    }
}

static NspAclVerdict mkdecide(const char* path, NspAclOp op, const char* pkg, bool priv,
                              bool isolated, bool known, int mask, bool is_dir) {
    NspAclIdentity id;
    memset(&id, 0, sizeof(id));
    id.uid = 10123;
    id.is_system = false;
    id.pkg_known = known;
    snprintf(id.pkg, sizeof(id.pkg), "%s", pkg ? pkg : "unknown");
    id.privileged = priv;
    id.cross_app_isolated = isolated;
    NspAclQuery q;
    memset(&q, 0, sizeof(q));
    q.uid = id.uid;
    q.path = path;
    q.op = op;
    q.access_mask = mask;
    q.is_dir = is_dir;
    return fw_acl_decide(&q, &id);
}

static void expect_v(const char* what, NspAclVerdict got, NspAclVerdict want) {
    if (got == want) {
        g_pass++;
        return;
    }
    g_fail++;
    printf("❌ %s: 期望 verdict=%d 实际=%d\n", what, (int)want, (int)got);
}

int main(void) {
    /* ---- A. 路径分类（AOSP PATTERN_OWNED_PATH 的等价物）---- */
    expect_cls("/", NSP_PATH_ROOT, "");
    expect_cls("/0", NSP_PATH_USER_ROOT, "");
    expect_cls("/10/", NSP_PATH_USER_ROOT, "");
    expect_cls("/0/Download", NSP_PATH_TOPLEVEL, "");
    expect_cls("/0/Download/x.jpg", NSP_PATH_NORMAL, "");
    expect_cls("/0/Android", NSP_PATH_NORMAL, "");
    expect_cls("/0/Android/data", NSP_PATH_SKELETON, "");
    expect_cls("/0/Android/obb", NSP_PATH_SKELETON, "");
    expect_cls("/0/Android/media", NSP_PATH_SKELETON, "");
    expect_cls("/0/Android/data/com.other.app", NSP_PATH_OWNED, "com.other.app");
    expect_cls("/0/Android/data/com.other.app/files/a.db", NSP_PATH_OWNED, "com.other.app");
    expect_cls("/0/Android/obb/com.other.app", NSP_PATH_OWNED, "com.other.app");
    expect_cls("/0/Android/media/com.other.app", NSP_PATH_ANDROID_MEDIA, "com.other.app");
    expect_cls("/0/Android/data/.nomedia", NSP_PATH_NORMAL, "");

    /* ---- B. 系统身份（uid < 10000）全放行：AOSP 同口径 ---- */
    {
        NspAclIdentity id;
        memset(&id, 0, sizeof(id));
        id.uid = 1000;
        id.is_system = true;
        NspAclQuery q = {.uid = 1000, .path = "/0/Android/data/com.other.app", .op = NSP_ACL_OP_DELETE};
        expect_v("system 身份放行", fw_acl_decide(&q, &id), NSP_ACL_ALLOW);
    }

    /* ---- C. 他包私有目录：ENOENT（看不见），自己包放行 ---- */
    expect_v("他包 data → ENOENT",
             mkdecide("/0/Android/data/com.other.app/files/a.db", NSP_ACL_OP_GENERIC_READ,
                      "com.mine", false, true, true, 0, false),
             NSP_ACL_DENY_ENOENT);
    expect_v("自己包 data → ALLOW",
             mkdecide("/0/Android/data/com.mine/files/a.db", NSP_ACL_OP_GENERIC_READ, "com.mine",
                      false, true, true, 0, false),
             NSP_ACL_ALLOW);
    expect_v("自己包（进程后缀 :push）→ ALLOW",
             mkdecide("/0/Android/data/com.mine/files/a.db", NSP_ACL_OP_GENERIC_READ,
                      "com.mine:push", false, true, true, 0, false),
             NSP_ACL_ALLOW);
    expect_v("特权应用（platform 签名）→ ALLOW",
             mkdecide("/0/Android/data/com.other.app/x", NSP_ACL_OP_GENERIC_READ, "com.priv", true,
                      true, true, 0, false),
             NSP_ACL_ALLOW);
    expect_v("ALLOW_CROSS_APP_DATA ON → ALLOW",
             mkdecide("/0/Android/data/com.other.app/x", NSP_ACL_OP_GENERIC_READ, "com.mine", false,
                      false, true, 0, false),
             NSP_ACL_ALLOW);
    expect_v("包名解析失败 → 放行（不能把应用挡在自己 data 外）",
             mkdecide("/0/Android/data/com.other.app/x", NSP_ACL_OP_GENERIC_READ, "unknown", false,
                      true, false, 0, false),
             NSP_ACL_ALLOW);

    /* ---- D. 骨架目录 /Android/data|obb|media：不可列举、不可增删改名 ---- */
    expect_v("骨架目录 readdir → EACCES",
             mkdecide("/0/Android/data", NSP_ACL_OP_READDIR, "com.mine", false, true, true, 0, true),
             NSP_ACL_DENY_EACCES);
    expect_v("骨架目录 opendir → EACCES",
             mkdecide("/0/Android/obb", NSP_ACL_OP_OPENDIR, "com.mine", false, true, true, 0, true),
             NSP_ACL_DENY_EACCES);
    /* 在 /Android/data 下建**自己的**包目录是允许的（AOSP：安装器就这么建），
       建他包目录则因他包私有目录不可见而 ENOENT。 */
    expect_v("骨架目录下建自己包目录 → ALLOW",
             mkdecide("/0/Android/data/com.mine", NSP_ACL_OP_MKDIR, "com.mine", false, true, true, 0,
                      true),
             NSP_ACL_ALLOW);
    expect_v("骨架目录下建他包目录 → ENOENT",
             mkdecide("/0/Android/data/com.other", NSP_ACL_OP_MKDIR, "com.mine", false, true, true, 0,
                      true),
             NSP_ACL_DENY_ENOENT);
    expect_v("骨架目录 rename → EPERM",
             mkdecide("/0/Android/data", NSP_ACL_OP_RENAME_SRC, "com.mine", false, true, true, 0, true),
             NSP_ACL_DENY_EPERM);
    expect_v("骨架目录 getattr → ALLOW",
             mkdecide("/0/Android/data", NSP_ACL_OP_GENERIC_READ, "com.mine", false, true, true, 0,
                      true),
             NSP_ACL_ALLOW);

    /* ---- E. Android/media：不是私有目录（读放行），但该目录本身不可改名 ---- */
    expect_v("Android/media 读 → ALLOW",
             mkdecide("/0/Android/media/com.other.app/a.mp3", NSP_ACL_OP_GENERIC_READ, "com.mine",
                      false, true, true, 0, false),
             NSP_ACL_ALLOW);
    expect_v("Android/media 写 → ALLOW",
             mkdecide("/0/Android/media/com.other.app/a.mp3", NSP_ACL_OP_WRITE_OPEN, "com.mine",
                      false, true, true, 0, false),
             NSP_ACL_ALLOW);
    expect_v("Android/media 自身 rename → EPERM",
             mkdecide("/0/Android/media", NSP_ACL_OP_RENAME_SRC, "com.mine", false, true, true, 0,
                      true),
             NSP_ACL_DENY_EPERM);

    /* ---- F. 顶层条目结构规则（AOSP isDirAccessAllowedForFuse）---- */
    expect_v("建默认目录（/DCIM）→ ALLOW",
             mkdecide("/0/DCIM", NSP_ACL_OP_MKDIR, "com.mine", false, true, true, 0, true),
             NSP_ACL_ALLOW);
    expect_v("建非默认目录（/MyStuff）→ EACCES",
             mkdecide("/0/MyStuff", NSP_ACL_OP_MKDIR, "com.mine", false, true, true, 0, true),
             NSP_ACL_DENY_EACCES);
    expect_v("删顶层目录 → EACCES",
             mkdecide("/0/Download", NSP_ACL_OP_RMDIR, "com.mine", false, true, true, 0, true),
             NSP_ACL_DENY_EACCES);
    expect_v("顶层目录改名 → EPERM",
             mkdecide("/0/Download", NSP_ACL_OP_RENAME_SRC, "com.mine", false, true, true, 0, true),
             NSP_ACL_DENY_EPERM);
    expect_v("顶层目录内建文件 → ALLOW",
             mkdecide("/0/Download/a.bin", NSP_ACL_OP_CREATE, "com.mine", false, true, true, 0,
                      false),
             NSP_ACL_ALLOW);

    /* ---- G. 卷根：不可列举，可 stat；access 的 W_OK 拒 ---- */
    expect_v("用户根 readdir → ALLOW（/sdcard 本体必须可列举）",
             mkdecide("/0", NSP_ACL_OP_READDIR, "com.mine", false, true, true, 0, true),
             NSP_ACL_ALLOW);
    expect_v("用户根 rename → EPERM",
             mkdecide("/0", NSP_ACL_OP_RENAME_SRC, "com.mine", false, true, true, 0, true),
             NSP_ACL_DENY_EPERM);
    expect_v("卷根 readdir → EACCES",
             mkdecide("/", NSP_ACL_OP_READDIR, "com.mine", false, true, true, 0, true),
             NSP_ACL_DENY_EACCES);
    expect_v("卷根 getattr → ALLOW",
             mkdecide("/0", NSP_ACL_OP_GENERIC_READ, "com.mine", false, true, true, 0, true),
             NSP_ACL_ALLOW);
    expect_v("卷根 access(W_OK) → EACCES",
             mkdecide("/", NSP_ACL_OP_ACCESS, "com.mine", false, true, true, W_OK, true),
             NSP_ACL_DENY_EACCES);
    expect_v("卷根 access(X_OK) → ALLOW",
             mkdecide("/0", NSP_ACL_OP_ACCESS, "com.mine", false, true, true, X_OK, true),
             NSP_ACL_ALLOW);

    /* ---- H. access(2) 语义：MS_NOEXEC 下普通文件不可执行 ---- */
    expect_v("普通文件 access(X_OK) → EACCES",
             mkdecide("/0/Download/a.bin", NSP_ACL_OP_ACCESS, "com.mine", false, true, true, X_OK,
                      false),
             NSP_ACL_DENY_EACCES);
    expect_v("普通目录 access(X_OK) → ALLOW",
             mkdecide("/0/Download", NSP_ACL_OP_ACCESS, "com.mine", false, true, true, X_OK, true),
             NSP_ACL_ALLOW);
    expect_v("普通文件 access(F_OK) → ALLOW",
             mkdecide("/0/Download/a.bin", NSP_ACL_OP_ACCESS, "com.mine", false, true, true, F_OK,
                      false),
             NSP_ACL_ALLOW);

    /* ---- I. errno 映射（三码不混用）---- */
    expect_v("errno ENOENT", (NspAclVerdict)(fw_acl_errno(NSP_ACL_DENY_ENOENT) == -ENOENT ? NSP_ACL_ALLOW : NSP_ACL_DENY_EPERM), NSP_ACL_ALLOW);
    expect_v("errno ALLOW=0", (NspAclVerdict)(fw_acl_errno(NSP_ACL_ALLOW) == 0 ? NSP_ACL_ALLOW : NSP_ACL_DENY_EPERM), NSP_ACL_ALLOW);
    if (fw_acl_errno(NSP_ACL_DENY_EACCES) != -EACCES || fw_acl_errno(NSP_ACL_DENY_EPERM) != -EPERM) {
        g_fail++;
        printf("❌ errno 映射: EACCES/EPERM 不对\n");
    } else {
        g_pass++;
    }

    /* ---- J. 生产入口 fw_acl_check（含身份组装与测试 uid 钩子）---- */
    g_stub_pkg[0] = '\0';
    g_stub_priv = false;
    g_stub_isolated = true;
    fw_acl_set_test_uid(10123);
    snprintf(g_stub_pkg, sizeof(g_stub_pkg), "%s", "com.mine");
    int rc_own = fw_acl_check(10123, 0, "/0/Android/data/com.mine/x", NSP_ACL_OP_GENERIC_READ, false, 0);
    if (rc_own != 0) {
        g_fail++;
        printf("❌ check: 自己包应放行，实际 rc=%d\n", rc_own);
    } else {
        g_pass++;
    }
    int rc_other = fw_acl_check(10123, 0, "/0/Android/data/com.other/y", NSP_ACL_OP_GENERIC_READ, false, 0);
    if (rc_other != -ENOENT) {
        g_fail++;
        printf("❌ check: 他包应 -ENOENT，实际 rc=%d\n", rc_other);
    } else {
        g_pass++;
    }
    fw_acl_set_test_uid(0);

    printf("fw_acl 驱动: %d 通过 / %d 失败\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
