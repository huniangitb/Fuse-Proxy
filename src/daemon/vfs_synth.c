/* FUSE 视图的虚拟条目：路径段判定与合成条目属性。

   这两组判定原先内嵌在 fuse_daemon.c 里，分别被 readdir 列举、getattr/access/
   opendir 兜底依赖：口径漂移会让「列表里看得见、stat 却失败」这类缺陷复现，
   故独立成模块，由 tests/test_vfs_synth.py 直编守住。 */
#include "vfs_synth.h"

#include <limits.h>
#include <string.h>

/* 剥掉开头的 /<数字> 用户层（/0/Android → /Android）；无用户层原样返回。 */
const char* sub_path_strip_user_layer(const char* sub_path) {
    if (!sub_path || sub_path[0] != '/') return sub_path;
    const char* d = sub_path + 1;
    while (*d >= '0' && *d <= '9') d++;
    if (d == (sub_path + 1) || *d != '/') return sub_path;
    return d;
}

/* 路径末段是否为 name（忽略尾部 '/'）："/Android"、"/0/Android/" 均命中 */
bool sub_path_tail_is(const char* sub_path, const char* name) {
    if (!sub_path) return false;
    size_t len = strlen(sub_path);
    while (len > 1 && sub_path[len - 1] == '/') len--;
    const char* base = sub_path + len;
    while (base > sub_path && base[-1] != '/') base--;
    size_t bl = (size_t)(sub_path + len - base);
    return bl == strlen(name) && memcmp(base, name, bl) == 0;
}

/* 是否是 /Android 目录本身（含带用户层的 /<uid>/Android） */
bool sub_path_is_android_dir(const char* sub_path) {
    return sub_path_tail_is(sub_path_strip_user_layer(sub_path), "Android");
}

/* 是否是 /Android/data 或 /Android/obb 目录本身（含带用户层的形态） */
bool sub_path_is_android_container(const char* sub_path) {
    const char* p = sub_path_strip_user_layer(sub_path);
    if (!sub_path_tail_is(p, "data") && !sub_path_tail_is(p, "obb")) return false;
    char parent[PATH_MAX];
    strncpy(parent, p, sizeof(parent) - 1);
    parent[sizeof(parent) - 1] = '\0';
    char* last = strrchr(parent, '/');
    if (!last) return false;
    *last = '\0';
    return sub_path_is_android_dir(parent);
}

bool is_android_skel_dir(const char* sub_path) {
    const char* p = sub_path_strip_user_layer(sub_path);
    if (strcmp(p, "/Android") == 0 || strcmp(p, "/Android/") == 0) return true;
    if (strcmp(p, "/Android/data") == 0 || strcmp(p, "/Android/data/") == 0) return true;
    if (strcmp(p, "/Android/obb") == 0 || strcmp(p, "/Android/obb/") == 0) return true;
    return false;
}

bool is_virtual_own_pkg_dir(const char* sub_path, const char* pkg) {
    if (!sub_path || !pkg || pkg[0] == '\0') return false;
    if (!sub_path_tail_is(sub_path, pkg)) return false;
    const char* p = sub_path_strip_user_layer(sub_path);
    size_t len = strlen(p);
    while (len > 1 && p[len - 1] == '/') len--; /* 尾斜杠不参与父路径定位 */
    const char* base = p + len;
    while (base > p && base[-1] != '/') base--;
    if (base == p) return false;
    const size_t parent_len = (size_t)(base - p - 1);
    if (parent_len == 0 || parent_len >= PATH_MAX) return false;
    char parent[PATH_MAX];
    memcpy(parent, p, parent_len);
    parent[parent_len] = '\0';
    return sub_path_is_android_container(parent);
}

void nsp_synth_stat_fill(struct stat* st, ino_t ino, mode_t type_mode,
                         const struct stat* real_child, const struct stat* parent) {
    memset(st, 0, sizeof(*st));
    st->st_ino = ino;
    st->st_mode = type_mode;
    const bool want_dir = S_ISDIR(type_mode);
    st->st_nlink = want_dir ? 2 : 1;
    st->st_size = want_dir ? 4096 : 0;

    const struct stat* src = real_child ? real_child : parent;
    if (!src) return;
    st->st_atime = src->st_atime;
    st->st_mtime = src->st_mtime;
    st->st_ctime = src->st_ctime;
    st->st_uid = src->st_uid;
    st->st_gid = src->st_gid;
    if (!want_dir) return;
    if (S_ISDIR(src->st_mode)) {
        /* 同名真实子项就是目录：连权限位与链接数/大小一起沿用 */
        st->st_mode = S_IFDIR | (src->st_mode & 07777);
        st->st_nlink = src->st_nlink;
        st->st_size = src->st_size;
    } else {
        /* 父目录属性只借权限位：合成目录链的 nlink/size 不复用父目录的值 */
        st->st_mode = S_IFDIR | (src->st_mode & 07777);
    }
}

/* 最近的存在祖先：从父目录逐级上溯（调用方传入的路径本身不参与——它正是
   lstat 失败的那个）。尾部 '/' 先剥掉，避免 "/a/b/" 只切出 "/a/b" 又原地失败。
   逐级只按 '/' 切，不做路径规范化：入参来自框架的 real_path，已是规范形态。 */
bool nsp_stat_nearest_ancestor(const char* real_path, struct stat* out) {
    if (!real_path || !out) return false;
    size_t len = strlen(real_path);
    if (len == 0 || len >= PATH_MAX) return false;
    char path[PATH_MAX];
    memcpy(path, real_path, len + 1);
    while (len > 1 && path[len - 1] == '/') path[--len] = '\0';
    if (len == 1) return false; /* 入参就是根："自己的父目录" 没有意义 */
    for (;;) {
        char* slash = strrchr(path, '/');
        if (!slash) return false;
        if (slash == path)
            path[1] = '\0';
        else
            *slash = '\0';
        if (lstat(path, out) == 0) return true;
        if (strcmp(path, "/") == 0) return false;
    }
}
