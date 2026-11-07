/* FUSE 视图的虚拟条目：路径段判定与合成条目属性。

   这两组判定原先内嵌在 fuse_daemon.c 里，分别被 readdir 列举、getattr/access/
   opendir 兜底依赖：口径漂移会让「列表里看得见、stat 却失败」这类缺陷复现，
   故独立成模块，由 tests/test_vfs_synth.py 直编守住。 */
#include "vfs_synth.h"

#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

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

/* 剥用户层后是否恰好等于 want（尾部单个 '/' 可接受，否则必须是结尾） */
static bool path_is_stripped(const char* sub_path, const char* want) {
    const char* p = sub_path_strip_user_layer(sub_path);
    if (!p) return false;
    size_t len = strlen(want);
    if (strncmp(p, want, len) != 0) return false;
    return p[len] == '\0' || (p[len] == '/' && p[len + 1] == '\0');
}

bool sub_path_is_storage_android_dir(const char* sub_path) {
    return path_is_stripped(sub_path, "/Android");
}

bool sub_path_is_android_container(const char* sub_path) {
    return path_is_stripped(sub_path, "/Android/data") ||
           path_is_stripped(sub_path, "/Android/obb");
}

bool is_android_skel_dir(const char* sub_path) {
    return sub_path_is_storage_android_dir(sub_path) ||
           sub_path_is_android_container(sub_path);
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

/* ==================== 合成列举登记 ====================
   own_pkg 目录的放行条件是「readdir 真的发出过这一条」，而不是「路径形状像」。
   登记只服务这一个判定：条目上限固定、过期即视为未登记，没有命中也不改变任何
   真实条目。 */

#define NSP_LISTED_SLOTS 32
#define NSP_LISTED_PKG_MAX 128
/* 列举到逐条 stat 的自然间隔：文件管理器列完立刻逐条 stat，实际在几十毫秒内；
   窗口放宽到 30s 只是让「刚列过」这一事实多留一会儿，不会把从未列举的路径放行。 */
#define NSP_LISTED_TTL_MS 30000u

struct nsp_listed_slot {
    uid_t uid;
    unsigned char kind; /* 1 = /Android/data, 2 = /Android/obb */
    char pkg[NSP_LISTED_PKG_MAX];
    uint64_t stamp_ms;
};

static struct nsp_listed_slot g_listed[NSP_LISTED_SLOTS];
static size_t g_listed_cursor;
static pthread_mutex_t g_listed_mu = PTHREAD_MUTEX_INITIALIZER;
static uint64_t (*g_listed_clock)(void); /* 测试注入，生产为 NULL */

static uint64_t listed_now_ms(void) {
    if (g_listed_clock) return g_listed_clock();
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000);
}

/* sub_path 落在 /Android/data|obb 时返回容器种类，末段名字写入 name（容器自身为
   空串）；嵌套同名目录、无关路径返回 0。 */
static int listed_container_of(const char* sub_path, char* name, size_t name_cap) {
    if (!sub_path) return 0;
    const char* p = sub_path_strip_user_layer(sub_path);
    if (!p || p[0] != '/') return 0;
    static const char kData[] = "/Android/data";
    static const char kObb[] = "/Android/obb";
    const size_t dl = sizeof kData - 1, ol = sizeof kObb - 1;
    size_t len = strlen(p);
    while (len > 1 && p[len - 1] == '/') len--;
    int kind;
    size_t base; /* 容器在 p 中的长度 */
    if (len == dl && memcmp(p, kData, dl) == 0) {
        kind = 1;
        base = dl;
    } else if (len == ol && memcmp(p, kObb, ol) == 0) {
        kind = 2;
        base = ol;
    } else {
        size_t cut = len;
        while (cut > 1 && p[cut - 1] != '/') cut--;
        if (cut <= 1) return 0;
        size_t plen = cut - 1; /* 去掉分隔 '/' */
        if (plen == dl && memcmp(p, kData, dl) == 0)
            kind = 1;
        else if (plen == ol && memcmp(p, kObb, ol) == 0)
            kind = 2;
        else
            return 0;
        size_t nlen = len - cut;
        if (!name) return kind;
        if (nlen + 1 > name_cap) return 0;
        memcpy(name, p + cut, nlen);
        name[nlen] = '\0';
        return kind;
    }
    if (name && name_cap > 0) name[0] = '\0';
    (void)base;
    return kind;
}

void nsp_listed_mark_own_pkg(uid_t uid, const char* sub_path, const char* pkg) {
    if (!pkg || pkg[0] == '\0') return;
    int kind = listed_container_of(sub_path, nullptr, 0);
    if (kind == 0) return;
    size_t plen = strlen(pkg);
    if (plen >= NSP_LISTED_PKG_MAX) return; /* 超长包名：不登记 = 不放行 */
    uint64_t now = listed_now_ms();
    pthread_mutex_lock(&g_listed_mu);
    struct nsp_listed_slot* slot = nullptr;
    for (size_t i = 0; i < NSP_LISTED_SLOTS; i++) {
        struct nsp_listed_slot* s = &g_listed[i];
        if (s->kind == (unsigned char)kind && s->uid == uid && strcmp(s->pkg, pkg) == 0) {
            slot = s;
            break;
        }
    }
    if (!slot) {
        slot = &g_listed[g_listed_cursor];
        g_listed_cursor = (g_listed_cursor + 1) % NSP_LISTED_SLOTS;
        slot->uid = uid;
        slot->kind = (unsigned char)kind;
        memcpy(slot->pkg, pkg, plen + 1);
    }
    slot->stamp_ms = now;
    pthread_mutex_unlock(&g_listed_mu);
}

bool nsp_listed_own_pkg(uid_t uid, const char* sub_path, const char* pkg) {
    if (!pkg || pkg[0] == '\0') return false;
    char name[NSP_LISTED_PKG_MAX];
    int kind = listed_container_of(sub_path, name, sizeof name);
    if (kind == 0 || strcmp(name, pkg) != 0) return false;
    uint64_t now = listed_now_ms();
    bool hit = false;
    pthread_mutex_lock(&g_listed_mu);
    for (size_t i = 0; i < NSP_LISTED_SLOTS; i++) {
        struct nsp_listed_slot* s = &g_listed[i];
        if (s->kind != (unsigned char)kind || s->uid != uid || strcmp(s->pkg, pkg) != 0) continue;
        /* 过期条目留着等下次覆盖：这里只当没命中 */
        if (now < s->stamp_ms || now - s->stamp_ms > NSP_LISTED_TTL_MS) continue;
        hit = true;
        break;
    }
    pthread_mutex_unlock(&g_listed_mu);
    return hit;
}

void nsp_listed_clear(void) {
    pthread_mutex_lock(&g_listed_mu);
    memset(g_listed, 0, sizeof g_listed);
    g_listed_cursor = 0;
    pthread_mutex_unlock(&g_listed_mu);
}

void nsp_listed_set_clock_for_test(uint64_t (*fn)(void)) {
    g_listed_clock = fn;
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
