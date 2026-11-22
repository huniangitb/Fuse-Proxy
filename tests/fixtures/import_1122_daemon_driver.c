/* 1122 daemon 实际函数回归；Python 插入原样源码。无挂载，根由 argv 私有化。
 * 路由拒绝、ACL xattr 与错误注入仅是外部边界；mkdir/guard/attrs/FIFO 均真 IO。 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "common.h"
#include "nsp_comm.h"
#include <libgen.h>
#include <stdatomic.h>
#include <stdarg.h>
#include <sys/xattr.h>

static unsigned failures, cases;
static unsigned mkdir_calls, mknod_calls, access_calls, open_calls, openat_calls, mkdirat_calls;
static unsigned fchown_calls, fchmod_calls;
static uid_t fd_owner; static gid_t fd_group;
static bool swap_parent, swap_child;
static char swap_root[PATH_MAX], swap_saved[PATH_MAX], swap_target[PATH_MAX];
static atomic_uint acl_logs;
static int route_rc, node_errno;
static bool acl_present, structure_entry;

#define CHECK(name, cond) do { \
    bool ok = (cond); cases++; if (!ok) failures++; \
    printf("case=%s ok=%d\n", name, ok); \
} while (0)

void log_internal(LogLevel level, const char* format, ...) {
    (void)level;
    if (strstr(format, "丢弃带 ACL 条目的 chmod")) atomic_fetch_add(&acl_logs, 1);
}
void nsp_comm_post(nsp_ch_t ch, const void* data, size_t len) {
    (void)ch; (void)data; (void)len;
}
int __real_access(const char* path, int mode);
int __wrap_access(const char* path, int mode) {
    access_calls++;
    return __real_access(path, mode);
}
int __real_open(const char* path, int flags, ...);
int __wrap_open(const char* path, int flags, ...) {
    open_calls++;
    if ((flags & O_CREAT) || (flags & O_TMPFILE) == O_TMPFILE) {
        va_list ap; va_start(ap, flags); mode_t mode = va_arg(ap, mode_t); va_end(ap);
        return __real_open(path, flags, mode);
    }
    return __real_open(path, flags);
}
int __real_fchown(int fd, uid_t owner, gid_t group);
int __wrap_fchown(int fd, uid_t owner, gid_t group) {
    fchown_calls++; fd_owner = owner; fd_group = group;
    return __real_fchown(fd, owner, group);
}
int __real_fchmod(int fd, mode_t mode);
int __wrap_fchmod(int fd, mode_t mode) {
    fchmod_calls++;
    return __real_fchmod(fd, mode);
}
int __real_openat(int fd, const char* path, int flags, ...);
int __wrap_openat(int fd, const char* path, int flags, ...) {
    openat_calls++;
    int ret;
    if ((flags & O_CREAT) || (flags & O_TMPFILE) == O_TMPFILE) {
        va_list ap; va_start(ap, flags); mode_t mode = va_arg(ap, mode_t); va_end(ap);
        ret = __real_openat(fd, path, flags, mode);
    } else ret = __real_openat(fd, path, flags);
    if (ret >= 0 && swap_parent && strcmp(path, "race_parent") == 0) {
        /* Rename only inside private storage, then replace logical path with a symlink. */
        swap_parent = false;
        if (rename(swap_root, swap_saved) != 0 || symlink(swap_target, swap_root) != 0) exit(2);
    }
    return ret;
}
int __real_mkdirat(int fd, const char* path, mode_t mode);
int __wrap_mkdirat(int fd, const char* path, mode_t mode) {
    mkdirat_calls++;
    int ret = __real_mkdirat(fd, path, mode);
    if (ret == 0 && swap_child && strcmp(path, "Android") == 0) {
        /* Real new directory is retained inside its parent; target never replaced by fake IO. */
        swap_child = false;
        if (renameat(fd, "Android", fd, "saved_child") != 0 ||
            symlinkat(swap_target, fd, "Android") != 0) exit(2);
    }
    return ret;
}
int __real_common_mkdir_within_storage(const char* path, mode_t mode);
int __wrap_common_mkdir_within_storage(const char* path, mode_t mode) {
    mkdir_calls++;
    return __real_common_mkdir_within_storage(path, mode);
}
static void log_fuse_err(const char* op, const char* path, int error) {
    (void)op; (void)path; (void)error;
}
static bool fw_acl_is_structure_entry(const char* path) {
    (void)path;
    return structure_entry;
}
static int import_mknod(const char* path, mode_t mode, dev_t dev) {
    mknod_calls++;
    if (node_errno) { errno = node_errno; return -1; }
    return mknod(path, mode, dev);
}
static ssize_t import_lgetxattr(const char* path, const char* name, void* value, size_t size) {
    (void)path; (void)name; (void)value; (void)size;
    return acl_present ? 32 : -1;
}
struct fuse_file_info { int unused; };
/* Gate boundary: test a denied fw_route result, not a duplicate ACL implementation. */
#define VFS_OP_MUTATE 1
#define NSP_ACL_OP_MKNOD 1
#define NSP_ACL_OP_SETATTR 2
#define VFS_SETUP_CORE_OP(path, op, acl) \
    if (route_rc) return route_rc; \
    const char* p = (path); (void)(op); (void)(acl)
#define VFS_RETURN(value) return (value)

/* ACTUAL_FUNCTIONS */

static bool is_dir(const char* path) {
    struct stat st;
    return lstat(path, &st) == 0 && S_ISDIR(st.st_mode);
}
static bool is_fifo(const char* path) {
    struct stat st;
    return lstat(path, &st) == 0 && S_ISFIFO(st.st_mode);
}
static void path_at(char* out, size_t size, const char* relative) {
    int n = snprintf(out, size, "%s/%s", g_real_root, relative);
    if (n < 0 || (size_t)n >= size) { fprintf(stderr, "fixture path overflow\n"); exit(2); }
}
static void test_child_path(void) {
    char parent[PATH_MAX], out[PATH_MAX];
    path_at(parent, sizeof parent, "0/sandbox");
    mkdir_calls = access_calls = 0;
    CHECK("child_path_valid", common_storage_child_path(parent, "Android", out, sizeof out) == 0 &&
          strstr(out, "/0/sandbox/Android") != NULL);
    const char* invalid[] = {"", ".", "..", "a/b", "/Android"};
    for (size_t i = 0; i < sizeof invalid / sizeof invalid[0]; i++) {
        strcpy(out, "sentinel");
        CHECK("child_component_rejected", common_storage_child_path(parent, invalid[i], out, sizeof out) == -1 && !out[0]);
    }
    strcpy(out, "sentinel");
    CHECK("child_parent_root_rejected", common_storage_child_path(g_real_root, "Android", out, sizeof out) == -1 && !out[0]);
    strcpy(out, "sentinel");
    CHECK("child_parent_outside_rejected", common_storage_child_path("/outside/storage/0", "Android", out, sizeof out) == -1 && !out[0]);
    int n = snprintf(parent, sizeof parent, "%sx/0", g_real_root);
    if (n < 0 || (size_t)n >= sizeof parent) exit(2);
    strcpy(out, "sentinel");
    CHECK("child_parent_prefix_sibling_rejected", common_storage_child_path(parent, "Android", out, sizeof out) == -1 && !out[0]);
    path_at(parent, sizeof parent, "0/sandbox");
    char tiny[4] = "old"; errno = 0;
    CHECK("child_overflow_clears_output", common_storage_child_path(parent, "Android", tiny, sizeof tiny) == -1 &&
          errno == ENAMETOOLONG && !tiny[0]);
    size_t fit = strlen(parent) + 1 + strlen("Android") + 1;
    CHECK("child_exact_fit", common_storage_child_path(parent, "Android", out, fit) == 0 && strlen(out) + 1 == fit);
    errno = 0;
    CHECK("child_one_short", common_storage_child_path(parent, "Android", out, fit - 1) == -1 && errno == ENAMETOOLONG && !out[0]);
    path_at(parent, sizeof parent, "999/sandbox/");
    CHECK("child_valid999_without_fs_and_trailing_slash", common_storage_child_path(parent, "Android", out, sizeof out) == 0 &&
          strstr(out, "/999/sandbox/Android") != NULL && strstr(out, "//Android") == NULL);
    path_at(parent, sizeof parent, "abc/sandbox");
    CHECK("child_nonnumeric_user_rejected", common_storage_child_path(parent, "Android", out, sizeof out) == -1 && !out[0]);
    path_at(parent, sizeof parent, "4294967296/sandbox");
    CHECK("child_overflow_user_rejected", common_storage_child_path(parent, "Android", out, sizeof out) == -1 && !out[0]);
    path_at(parent, sizeof parent, "0/sandbox");
    const char* dot_parents[] = {"0/../sandbox", "0/./sandbox"};
    for (size_t i = 0; i < sizeof dot_parents / sizeof dot_parents[0]; i++) {
        path_at(parent, sizeof parent, dot_parents[i]);
        CHECK("child_parent_dot_component_rejected", common_storage_child_path(parent, "Android", out, sizeof out) == -1 && !out[0]);
    }
    path_at(parent, sizeof parent, "0/sandbox");
    CHECK("child_null_rejected", common_storage_child_path(parent, NULL, out, sizeof out) == -1 && !out[0]);
    CHECK("child_parent_null_rejected", common_storage_child_path(NULL, "Android", out, sizeof out) == -1 && !out[0]);
    char long_parent[PATH_MAX + 1];
    memset(long_parent, 'x', PATH_MAX); long_parent[PATH_MAX] = 0; errno = 0;
    CHECK("child_parent_long_rejected", common_storage_child_path(long_parent, "Android", out, sizeof out) == -1 && errno == ENAMETOOLONG && !out[0]);
    char long_child[NAME_MAX + 2];
    memset(long_child, 'x', NAME_MAX + 1); long_child[NAME_MAX + 1] = 0; errno = 0;
    CHECK("child_name_long_rejected", common_storage_child_path(parent, long_child, out, sizeof out) == -1 && errno == ENAMETOOLONG && !out[0]);
    CHECK("child_helper_zero_fs_calls", mkdir_calls == 0 && access_calls == 0);
}
static void test_sandbox(void) {
    char root[PATH_MAX], android[PATH_MAX], missing[PATH_MAX];
    path_at(root, sizeof root, "0/sandbox");
    path_at(android, sizeof android, "0/sandbox/Android");
    br_ensure_sandbox_dir(root);
    CHECK("sandbox_root_and_android", is_dir(root) && is_dir(android));
    if (is_dir(android)) rmdir(android);
    br_ensure_sandbox_dir(root);
    CHECK("same_thread_android_delete_repair", is_dir(android));
    if (is_dir(android)) rmdir(android);
    if (is_dir(root)) rmdir(root);
    br_ensure_sandbox_dir(root);
    CHECK("same_thread_root_delete_repair", is_dir(root) && is_dir(android));
    /* Real dirname setter models A/B/A config changes; not the full publication/slot engine. */
    char cfg_a[PATH_MAX], cfg_b[PATH_MAX], cfg_child[PATH_MAX];
    if (common_sandbox_path(0, "com.example.app", cfg_a, sizeof cfg_a) != 0) exit(2);
    br_ensure_sandbox_dir(cfg_a);
    if (common_storage_child_path(cfg_a, "Android", cfg_child, sizeof cfg_child) != 0) exit(2);
    CHECK("sandbox_config_dirname_a", is_dir(cfg_child));
    common_set_sandbox_dirname("changed-sandbox");
    if (common_sandbox_path(0, "com.example.app", cfg_b, sizeof cfg_b) != 0) exit(2);
    br_ensure_sandbox_dir(cfg_b);
    if (common_storage_child_path(cfg_b, "Android", cfg_child, sizeof cfg_child) != 0) exit(2);
    CHECK("sandbox_config_dirname_b", strcmp(cfg_a, cfg_b) != 0 && is_dir(cfg_child));
    common_set_sandbox_dirname("sandbox");
    if (common_storage_child_path(cfg_a, "Android", cfg_child, sizeof cfg_child) != 0) exit(2);
    if (is_dir(cfg_child)) rmdir(cfg_child);
    if (is_dir(cfg_a)) rmdir(cfg_a);
    br_ensure_sandbox_dir(cfg_a);
    CHECK("sandbox_config_dirname_a_return_repairs", is_dir(cfg_a) && is_dir(cfg_child));
    path_at(missing, sizeof missing, "999/sandbox");
    br_ensure_sandbox_dir(missing);
    path_at(missing, sizeof missing, "999");
    CHECK("sandbox_missing_user_not_created", access(missing, F_OK) != 0);
    char overflow[PATH_MAX + 16];
    memset(overflow, 'x', sizeof overflow - 1); overflow[0] = '/'; overflow[sizeof overflow - 1] = 0;
    mkdir_calls = access_calls = 0;
    br_ensure_sandbox_dir(overflow);
    CHECK("android_overflow_no_fs_attempt", mkdir_calls == 0 && access_calls == 0);
    const char* containers[] = {"data", "obb", "media"};
    for (size_t i = 0; i < 3; i++) {
        char view[128], name[128], mirror[PATH_MAX];
        snprintf(view, sizeof view, "/Android/%s", containers[i]);
        snprintf(name, sizeof name, "container_%s_passthrough", containers[i]);
        CHECK(name, br_path_android_passthrough(view, "com.example.app"));
        snprintf(view, sizeof view, "/Android/%s/com.example.app/sub", containers[i]);
        snprintf(name, sizeof name, "own_%s_passthrough", containers[i]);
        CHECK(name, br_path_android_passthrough(view, "com.example.app"));
        snprintf(name, sizeof name, "0/sandbox/Android/%s", containers[i]);
        path_at(mirror, sizeof mirror, name);
        CHECK("container_not_materialized_in_mirror", access(mirror, F_OK) != 0);
    }
    CHECK("android_root_not_passthrough", !br_path_android_passthrough("/Android", "com.example.app"));
    CHECK("new_android_child_not_passthrough", !br_path_android_passthrough("/Android/socket", "com.example.app"));
    CHECK("near_container_not_passthrough", !br_path_android_passthrough("/Android/database", "com.example.app"));
}
/* Exact fresh-review topology: pre-existing sandbox root points outside storage.
 * Only argv-owned temporary targets are used; no production paths or mounts. */
static void test_sandbox_symlinks(const char* tmp) {
    char root[PATH_MAX], parent[PATH_MAX], outside[PATH_MAX], child[PATH_MAX];
    int n = snprintf(outside, sizeof outside, "%s/outside_storage", tmp);
    if (n < 0 || (size_t)n >= sizeof outside || mkdir(outside, 0700) != 0) exit(2);
    if (common_sandbox_path(0, "com.symlink.root", root, sizeof root) != 0) exit(2);
    strcpy(parent, root);
    if (common_mkdir_within_storage(dirname(parent), 0775) != 0 || symlink(outside, root) != 0) exit(2);
    struct stat before, after;
    if (lstat(outside, &before) != 0) exit(2);
    br_ensure_sandbox_dir(root);
    n = snprintf(child, sizeof child, "%s/Android", outside);
    if (n < 0 || (size_t)n >= sizeof child) exit(2);
    CHECK("sandbox_root_symlink_no_outside_android", lstat(child, &after) == -1 && errno == ENOENT);
    CHECK("sandbox_root_symlink_target_attrs_unchanged", lstat(outside, &after) == 0 &&
          after.st_mode == before.st_mode && after.st_uid == before.st_uid && after.st_gid == before.st_gid);

    n = snprintf(outside, sizeof outside, "%s/outside_ancestor", tmp);
    if (n < 0 || (size_t)n >= sizeof outside || mkdir(outside, 0700) != 0) exit(2);
    n = snprintf(child, sizeof child, "%s/sandbox", outside);
    if (n < 0 || (size_t)n >= sizeof child || mkdir(child, 0700) != 0) exit(2);
    path_at(parent, sizeof parent, "0/Android/data/com.symlink.ancestor");
    if (symlink(outside, parent) != 0 || common_sandbox_path(0, "com.symlink.ancestor", root, sizeof root) != 0) exit(2);
    br_ensure_sandbox_dir(root);
    n = snprintf(child, sizeof child, "%s/sandbox/Android", outside);
    if (n < 0 || (size_t)n >= sizeof child) exit(2);
    CHECK("sandbox_ancestor_symlink_no_outside_android", lstat(child, &after) == -1 && errno == ENOENT);

    n = snprintf(outside, sizeof outside, "%s/outside_child", tmp);
    if (n < 0 || (size_t)n >= sizeof outside || mkdir(outside, 0700) != 0 || lstat(outside, &before) != 0) exit(2);
    if (common_sandbox_path(0, "com.symlink.child", root, sizeof root) != 0 ||
        common_mkdir_within_storage(root, 0775) != 0 ||
        common_storage_child_path(root, "Android", child, sizeof child) != 0 || symlink(outside, child) != 0) exit(2);
    br_ensure_sandbox_dir(root);
    CHECK("sandbox_child_live_symlink_target_attrs_unchanged", lstat(outside, &after) == 0 &&
          after.st_mode == before.st_mode && after.st_uid == before.st_uid && after.st_gid == before.st_gid);
    /* Explicit fixture symlink path, not computed production deletion. */
    if (unlink(child) != 0) exit(2);
    n = snprintf(outside, sizeof outside, "%s/outside_child_missing", tmp);
    if (n < 0 || (size_t)n >= sizeof outside || symlink(outside, child) != 0) exit(2);
    br_ensure_sandbox_dir(root);
    CHECK("sandbox_child_broken_symlink_no_target_created", lstat(outside, &after) == -1 && errno == ENOENT);
}
static void test_storage_child_api(const char* tmp) {
    char root[PATH_MAX], child[PATH_MAX], outside[PATH_MAX]; struct stat pst = {0}, st = {0}, before = {0};
    path_at(root, sizeof root, "777/missing");
    mkdirat_calls = 0;
    CHECK("safe_child_missing_user_rejected", common_mkdir_storage_child(root, "Android", 0775) == -1 && mkdirat_calls == 0);
    path_at(child, sizeof child, "777");
    CHECK("safe_child_missing_user_not_created", access(child, F_OK) != 0);
    path_at(root, sizeof root, "0/missing_api_parent"); mkdirat_calls = 0;
    CHECK("safe_child_missing_parent_not_created", common_mkdir_storage_child(root, "Android", 0775) == -1 &&
          mkdirat_calls == 0 && access(root, F_OK) != 0);
    size_t prefix = strlen(g_real_root);
    if (prefix + 3 >= sizeof root) exit(2);
    memcpy(root, g_real_root, prefix); memcpy(root + prefix, "/0/", 3);
    for (size_t i = prefix + 3; i < PATH_MAX - 4; i++) root[i] = (i % 200) ? 'x' : '/';
    root[PATH_MAX - 4] = 0; open_calls = openat_calls = mkdirat_calls = 0; errno = 0;
    CHECK("safe_child_valid_prefix_overflow_zero_io", common_mkdir_storage_child(root, "Android", 0775) == -1 &&
          errno == ENAMETOOLONG && open_calls == 0 && openat_calls == 0 && mkdirat_calls == 0);

    const char* linked_pkgs[] = {"com.symlink.root", "com.symlink.ancestor", "com.symlink.child"};
    for (size_t i = 0; i < sizeof linked_pkgs / sizeof linked_pkgs[0]; i++) {
        if (common_sandbox_path(0, linked_pkgs[i], root, sizeof root) != 0) exit(2);
        fchown_calls = fchmod_calls = 0;
        CHECK("safe_child_linked_parent_or_broken_child_rejected", common_mkdir_storage_child(root, "Android", 0775) == -1 &&
              fchown_calls == 0 && fchmod_calls == 0);
    }
    if (common_sandbox_path(0, "com.symlink.child", root, sizeof root) != 0 ||
        common_storage_child_path(root, "Android", child, sizeof child) != 0 || unlink(child) != 0) exit(2);
    int n = snprintf(outside, sizeof outside, "%s/outside_child", tmp);
    if (n < 0 || (size_t)n >= sizeof outside || symlink(outside, child) != 0) exit(2);
    fchown_calls = fchmod_calls = 0;
    CHECK("safe_child_live_child_symlink_rejected", common_mkdir_storage_child(root, "Android", 0775) == -1 &&
          fchown_calls == 0 && fchmod_calls == 0);

    for (unsigned sg = 0; sg < 2; sg++) {
        const char* pkg = sg ? "com.api.setgid" : "com.api.no_setgid";
        if (common_sandbox_path(0, pkg, root, sizeof root) != 0 || common_mkdir_within_storage(root, 0775) != 0 ||
            chmod(root, sg ? 02775 : 0775) != 0 || lstat(root, &pst) != 0 ||
            common_storage_child_path(root, "Android", child, sizeof child) != 0) exit(2);
        fchown_calls = fchmod_calls = 0;
        int rc = common_mkdir_storage_child(root, "Android", 0750);
        CHECK("safe_child_private_mode_and_setgid", rc == 0 && lstat(child, &st) == 0 &&
              (st.st_mode & 07777) == (sg ? 02750 : 0750));
        CHECK("safe_child_owner_group_fd_inherit", rc == 0 && st.st_uid == pst.st_uid && st.st_gid == pst.st_gid &&
              fchown_calls == 1 && fchmod_calls == 1 && fd_owner == pst.st_uid && fd_group == pst.st_gid);
        if (getuid() != 0) CHECK("safe_child_nonzero_owner", pst.st_uid != 0 && st.st_uid != 0);
        if (chmod(child, 0701) != 0 || lstat(child, &before) != 0) exit(2);
        fchown_calls = fchmod_calls = 0;
        CHECK("safe_child_existing_dir_attrs_preserved", common_mkdir_storage_child(root, "Android", 0775) == 0 &&
              lstat(child, &st) == 0 && st.st_mode == before.st_mode && st.st_uid == before.st_uid && st.st_gid == before.st_gid &&
              fchown_calls == 0 && fchmod_calls == 0);
    }

    path_at(root, sizeof root, "0/race_parent"); path_at(swap_saved, sizeof swap_saved, "0/race_parent_saved");
    strcpy(swap_root, root); n = snprintf(swap_target, sizeof swap_target, "%s/outside_parent_swap", tmp);
    if (n < 0 || (size_t)n >= sizeof swap_target || mkdir(swap_target, 0700) != 0 ||
        common_mkdir_within_storage(root, 0775) != 0) exit(2);
    swap_parent = true;
    int rc = common_mkdir_storage_child(root, "Android", 0775);
    n = snprintf(outside, sizeof outside, "%s/Android", swap_target);
    if (n < 0 || (size_t)n >= sizeof outside || common_storage_child_path(swap_saved, "Android", child, sizeof child) != 0) exit(2);
    CHECK("safe_child_open_parent_fd_not_relocated_by_path_swap", rc == 0 && !swap_parent && is_dir(child) && access(outside, F_OK) != 0);

    path_at(root, sizeof root, "0/race_child");
    n = snprintf(swap_target, sizeof swap_target, "%s/outside_child_swap", tmp);
    if (n < 0 || (size_t)n >= sizeof swap_target || mkdir(swap_target, 0700) != 0 || lstat(swap_target, &before) != 0 ||
        common_mkdir_within_storage(root, 0775) != 0) exit(2);
    swap_child = true; fchown_calls = fchmod_calls = 0;
    rc = common_mkdir_storage_child(root, "Android", 0775);
    CHECK("safe_child_post_mkdir_symlink_swap_rejected", rc == -1 && !swap_child);
    CHECK("safe_child_post_mkdir_symlink_target_attrs_untouched", lstat(swap_target, &st) == 0 &&
          st.st_mode == before.st_mode && st.st_uid == before.st_uid && st.st_gid == before.st_gid && fchown_calls == 0 && fchmod_calls == 0);
    /* fd anchoring does not atomically bind mkdirat's inode to later openchild, nor prevent arbitrary rename out of tree. */
}
static void test_mknod(void) {
    char path[PATH_MAX], parent[PATH_MAX];
    path_at(path, sizeof path, "0/nodes/deep/pipe");
    mkdir_calls = mknod_calls = 0;
    int rc = vfs_mknod(path, S_IFIFO | 0600, 0);
    CHECK("mknod_missing_parent_retried", rc == 0 && is_fifo(path) && mknod_calls == 2 && mkdir_calls == 1);
    struct stat st;
    CHECK("mknod_keeps_actual_attrs", lstat(path, &st) == 0 && (st.st_mode & 0660) == 0660);
    unsigned before = mkdir_calls;
    rc = vfs_mknod(path, S_IFIFO | 0600, 0);
    CHECK("mknod_eexist_not_retried", rc == -EEXIST && mkdir_calls == before);
    path_at(path, sizeof path, "999/nodes/pipe");
    path_at(parent, sizeof parent, "999");
    mkdir_calls = mknod_calls = 0;
    rc = vfs_mknod(path, S_IFIFO | 0600, 0);
    CHECK("mknod_missing_user_guard", rc == -ENOENT && !is_dir(parent) && mknod_calls == 1 && mkdir_calls == 1);
    path_at(path, sizeof path, "0/nonenoent/pipe");
    path_at(parent, sizeof parent, "0/nonenoent");
    node_errno = EIO; mkdir_calls = mknod_calls = 0;
    rc = vfs_mknod(path, S_IFIFO | 0600, 0);
    CHECK("mknod_nonenoent_no_parent_io", rc == -EIO && !is_dir(parent) && mknod_calls == 1 && mkdir_calls == 0);
    node_errno = 0;
    const int denied[] = {-EACCES, -EROFS, -EPERM};
    for (size_t i = 0; i < sizeof denied / sizeof denied[0]; i++) {
        route_rc = denied[i]; mkdir_calls = mknod_calls = 0;
        rc = vfs_mknod(path, S_IFIFO | 0600, 0);
        CHECK("mknod_route_short_circuit", rc == route_rc && mknod_calls == 0 && mkdir_calls == 0 && !is_dir(parent));
    }
    route_rc = 0;
    path_at(parent, sizeof parent, "0/blocker");
    int fd = open(parent, O_CREAT | O_EXCL | O_WRONLY, 0600);
    if (fd >= 0) close(fd);
    path_at(path, sizeof path, "0/blocker/pipe");
    mkdir_calls = mknod_calls = 0;
    rc = vfs_mknod(path, S_IFIFO | 0600, 0);
    CHECK("mknod_enotdir_real_no_retry", rc == -ENOTDIR && mknod_calls == 1 && mkdir_calls == 0);
}
static const char* chmod_path;
static void* chmod_worker(void* arg) {
    (void)arg;
    for (unsigned i = 0; i < 256; i++)
        if (vfs_chmod(chmod_path, 0700, NULL) != 0) atomic_fetch_add(&acl_logs, 100000);
    return NULL;
}
static void test_chmod(void) {
    char path[PATH_MAX]; path_at(path, sizeof path, "0/chmod_file");
    int fd = open(path, O_CREAT | O_EXCL | O_WRONLY, 0640);
    if (fd >= 0) close(fd);
    struct stat before, after;
    if (lstat(path, &before) != 0) { CHECK("chmod_fixture", false); return; }
    acl_present = true; atomic_store(&acl_logs, 0);
    CHECK("acl_chmod_returns_success", vfs_chmod(path, 0700, NULL) == 0);
    CHECK("acl_log_first", atomic_load(&acl_logs) == 1);
    for (unsigned i = 2; i < 1024; i++) (void)vfs_chmod(path, 0700, NULL);
    CHECK("acl_log_suppressed_before_1024", atomic_load(&acl_logs) == 1);
    (void)vfs_chmod(path, 0700, NULL);
    CHECK("acl_log_1024", atomic_load(&acl_logs) == 2);
    chmod_path = path; pthread_t threads[4];
    for (size_t i = 0; i < 4; i++) {
        if (pthread_create(&threads[i], NULL, chmod_worker, NULL) != 0) exit(2);
    }
    for (size_t i = 0; i < 4; i++) pthread_join(threads[i], NULL);
    CHECK("acl_log_concurrent_2048", atomic_load(&acl_logs) == 3);
    CHECK("acl_chmod_keeps_mode", lstat(path, &after) == 0 && after.st_mode == before.st_mode);
    acl_present = false;
    CHECK("nonacl_chmod_changes_mode", vfs_chmod(path, 0700, NULL) == 0 && lstat(path, &after) == 0 && (after.st_mode & 0777) == 0700);
    structure_entry = true;
    CHECK("structure_chmod_unchanged", vfs_chmod(path, 0600, NULL) == 0 && lstat(path, &after) == 0 && (after.st_mode & 0777) == 0700);
    structure_entry = false; route_rc = -EACCES;
    CHECK("chmod_route_short_circuit", vfs_chmod(path, 0600, NULL) == -EACCES && lstat(path, &after) == 0 && (after.st_mode & 0777) == 0700);
    route_rc = 0;
}
int main(int argc, char** argv) {
    if (argc != 2) return 2;
    int n = snprintf(g_real_root, sizeof g_real_root, "%s/storage", argv[1]);
    if (n < 0 || (size_t)n >= sizeof g_real_root) return 2;
    if (mkdir(g_real_root, 0700) != 0) return 2;
    char user[PATH_MAX]; path_at(user, sizeof user, "0");
    if (mkdir(user, 0775) != 0) return 2;
    test_child_path(); test_sandbox(); test_sandbox_symlinks(argv[1]); test_storage_child_api(argv[1]); test_mknod(); test_chmod();
    printf("cases=%u failures=%u\n", cases, failures);
    return failures ? 1 : 0;
}
