#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
/* 后端文件句柄标记：open/create 命中后端时置位（本地 fd 不置位），
   read/write/release/fsync 据此区分本地 fd 与模块句柄。
   用 bit40（非 bit63）：Android tagged-pointer 检测对 fh 的 top byte
   （bit 56-63）非零会 SIGABRT（"Pointer tag truncated"）；bit40 置位
   不触发该检测，且远高于普通 fd 范围 */
#define NSP_FH_BACKEND_FLAG (1ULL << 40)
#include <fuse3/fuse.h>
#include <fuse3/fuse_lowlevel.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/statvfs.h>
#include <sys/xattr.h>
#include <sys/prctl.h>
#include <pthread.h>
#include <libgen.h>
#include <sys/syscall.h>
#include <ctype.h>
#include "common.h"
#include "crash_dump.h"
#include "module_loader.h"
#include <fuse3/fuse_log.h>
#ifdef TARGET_ANDROID
#include <fuse3/fuse_kernel.h>
#include <sys/ioctl.h>
#endif

bool g_passthrough_enabled = false;
bool g_preserve_perms = false;
bool g_disable_sandbox = false; /* 新增：禁用沙盒功能标志 */

static int g_ready_fd = -1;
static int g_global_root_fd = -1;
#ifdef TARGET_ANDROID
static int g_bpf_fd = -1;           /* BPF program fd, -1 = disabled */
#endif
static bool g_passthrough_disabled = false; /* --no-passthrough 显式禁用 */
static bool g_is_media_fuse = false; /* --media-fuse: 媒体模块专属 FUSE */
static char g_modules_dir_arg[PATH_MAX] = {0}; /* --modules-dir: 热插拔模块目录覆盖 */

#define MAX_PENDING_CLOSE 64
static int g_pending_close_fds[MAX_PENDING_CLOSE];
static int g_pending_close_count = 0;
static pthread_mutex_t g_pending_close_mutex = PTHREAD_MUTEX_INITIALIZER;

#ifdef TARGET_ANDROID
static void vfs_defer_close(int fd) {
    if (fd < 0) return;
    pthread_mutex_lock(&g_pending_close_mutex);
    if (g_pending_close_count < MAX_PENDING_CLOSE) {
        g_pending_close_fds[g_pending_close_count++] = fd;
    } else {
        close(fd);
    }
    pthread_mutex_unlock(&g_pending_close_mutex);
}
#endif

static void vfs_flush_pending_closes(void) {
    pthread_mutex_lock(&g_pending_close_mutex);
    for (int i = 0; i < g_pending_close_count; i++) {
        close(g_pending_close_fds[i]);
    }
    g_pending_close_count = 0;
    pthread_mutex_unlock(&g_pending_close_mutex);
}

typedef enum { MODE_REDIRECT, MODE_OVERLAY } DaemonMode;
static DaemonMode g_mode = MODE_REDIRECT;

static char g_lower_dir[PATH_MAX] = {0}; 
static char g_upper_dir[PATH_MAX] = {0};

static int recursive_rmdir(const char *path);
static int recursive_copy_dir(const char *src, const char *dst, uid_t uid, gid_t gid);

static void log_fuse_err(const char* op, const char* path, int err_code) {
    int err = err_code < 0 ? -err_code : err_code;
    if (err != 0 && err != ENOENT && err != EEXIST && err != EROFS) {
        char current_pkg[128] = "unknown";
        struct fuse_context* ctx = fuse_get_context();
        if (ctx) {
            module_dispatch_get_pkg(ctx->uid, ctx->pid, current_pkg, sizeof(current_pkg));
        }
        fprintf(stderr, "[FUSE_ERR] 应用: %s (PID: %d, UID: %d) | 操作: %s | 路径: %s | 错误码: %d (%s)\n",
                current_pkg, ctx ? ctx->pid : 0, ctx ? ctx->uid : 0, op, path ? path : "nullptr", err, strerror(err));
        fflush(stderr);
        LOG_ERR("[FUSE_ERR] %s %s: %s", op, path ? path : "nullptr", strerror(err));
    }
}

/* 框架最小路径解析（无规则模块时的直通回退）：剥离 /0/ user_id 前缀 + 非法字符清理 */
static int fw_parse_path(const char* path, int* user_id_out, char* sub_path_out, size_t sz) {
    if (!path) return -ENOENT;
    const char* sub = path;
    if (path[0] == '/' && isdigit((unsigned char)path[1])) {
        if (user_id_out) *user_id_out = atoi(path + 1);
        const char* slash = strchr(path + 1, '/');
        sub = slash ? slash : "/";
    }
    if (path_contains_invalid_chars(sub)) {
        path_sanitize(sub_path_out, sz, sub);
        if (sub_path_out[0] == '\0') return -ENOENT;
    } else {
        strncpy(sub_path_out, sub, sz - 1);
        sub_path_out[sz - 1] = '\0';
    }
    return 0;
}

/* 框架默认存储路径（无规则模块 / 模块未命中时的直通回退） */
static void fw_default_real_path(int user_id, const char* sub_path, char* out, size_t sz) {
    if (user_id >= 0) {
        if (g_real_root[0])
            snprintf(out, sz, "%s/%d%s", g_real_root, user_id, sub_path);
        else
            snprintf(out, sz, STORAGE_BASE "/%d%s", user_id, sub_path);
    } else {
        if (g_real_root[0])
            snprintf(out, sz, "%s%s", g_real_root, sub_path);
        else
            snprintf(out, sz, STORAGE_BASE "%s", sub_path);
    }
}

/* 虚拟目录判空（原 vfs_is_virtual_dir_empty 的分派器版）：
   - 虚拟祖先 → 视为非空（拒绝删除）
   - 否则扫描真实目录，跳过规则隐藏/重定向子项（与 readdir 过滤一致） */
static bool fw_virtual_dir_empty(const char* sub_path, const char* real_path, const char* current_pkg,
                                 int path_user_id, uid_t uid) {
    if (uid != 0) {
        struct fuse_context* c = fuse_get_context();
        NspQueryCtx q0 = { .uid = uid, .pid = c ? c->pid : 0, .gid = c ? c->gid : 0, .path = sub_path };
        NspProbeResult r0; memset(&r0, 0, sizeof r0);
        if (module_dispatch_probe(&q0, &r0) == NSP_DISPATCH_OK && r0.valid && r0.is_virtual_ancestor)
            return false;
    }
    struct stat st;
    if (lstat(real_path, &st) == -1) return true;
    DIR* dp = opendir(real_path);
    if (!dp) return false;
    bool skip_sandbox = (path_user_id < 0) || g_disable_sandbox;
    bool hide_others = (!skip_sandbox && current_pkg[0] && strcmp(current_pkg, "system") != 0 &&
                        strcmp(current_pkg, "unknown") != 0);
    bool is_root = (strcmp(sub_path, "/") == 0 || sub_path[0] == '\0');
    struct dirent* de;
    bool empty = true;
    while ((de = readdir(dp)) != nullptr) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;
        if (path_contains_invalid_chars(de->d_name)) continue;
        char item_sub_path[2048];
        if (is_root) snprintf(item_sub_path, 2047, "/%s", de->d_name);
        else snprintf(item_sub_path, 2047, "%s/%s", sub_path, de->d_name);
        if (uid != 0) {
            /* 轻量探测；user_id 目录条目豁免 redirect_target（与 readdir 一致） */
            bool uid_dir = (item_sub_path[0] == '/' && isdigit((unsigned char)item_sub_path[1]) &&
                            (item_sub_path[2] == '\0' || item_sub_path[2] == '/'));
            struct fuse_context* c = fuse_get_context();
            NspQueryCtx iq = { .uid = uid, .pid = c ? c->pid : 0, .gid = c ? c->gid : 0, .path = item_sub_path };
            NspProbeResult ir; memset(&ir, 0, sizeof ir);
            if (module_dispatch_probe(&iq, &ir) == NSP_DISPATCH_OK && ir.valid) {
                if (ir.hidden || (!uid_dir && ir.is_redirect_target)) continue;
            }
        }
        if (hide_others && (strcmp(sub_path, "/Android/data") == 0 || strcmp(sub_path, "/Android/data/") == 0 ||
                            strcmp(sub_path, "/Android/obb") == 0 || strcmp(sub_path, "/Android/obb/") == 0)) {
            if (strcmp(de->d_name, current_pkg) != 0) continue;
        }
        empty = false;
        break;
    }
    closedir(dp);
    return empty;
}

static bool is_android_skel_dir(const char* sub_path) {
    if (strcmp(sub_path, "/Android") == 0 || strcmp(sub_path, "/Android/") == 0) return true;
    if (strcmp(sub_path, "/Android/data") == 0 || strcmp(sub_path, "/Android/data/") == 0) return true;
    if (strcmp(sub_path, "/Android/obb") == 0 || strcmp(sub_path, "/Android/obb/") == 0) return true;
    return false;
}

/* 分派器模式：FUSE 回调入口统一经 module_dispatch_resolve 决策。
   - 有规则模块命中：用模块返回的 sub_path/real_path/ro/虚拟目录等
   - 无模块/未命中：框架直通回退（fw_parse_path + fw_default_real_path）
   - hidden 命中 → 返回 err_code；rr 各标志在回调体中以 rr.xxx 直接使用 */
#define VFS_SETUP_CORE(path_val, err_code) \
    struct fuse_context* ctx = fuse_get_context(); \
    if (!ctx) return err_code; \
    NspQueryCtx nsp_q = { .uid = ctx->uid, .pid = ctx->pid, .gid = ctx->gid, .path = path_val }; \
    NspResolveResult rr; memset(&rr, 0, sizeof rr); \
    bool nsp_ok = (module_dispatch_resolve(&nsp_q, &rr) == NSP_DISPATCH_OK && rr.valid); \
    char current_pkg[128] = "unknown"; \
    int path_user_id = -1; \
    char sub_path[PATH_MAX]; sub_path[0] = '\0'; \
    char p[PATH_MAX]; p[0] = '\0'; \
    bool is_redir = false; \
    if (nsp_ok) { \
        if (rr.hidden) return err_code; \
        strncpy(current_pkg, rr.pkg[0] ? rr.pkg : "unknown", 127); current_pkg[127] = '\0'; \
        path_user_id = rr.user_id; \
        strncpy(sub_path, rr.sub_path, sizeof sub_path - 1); sub_path[sizeof sub_path - 1] = '\0'; \
        strncpy(p, rr.real_path, sizeof p - 1); p[sizeof p - 1] = '\0'; \
        is_redir = rr.is_redir; \
    } else { \
        if (fw_parse_path(path_val, &path_user_id, sub_path, sizeof sub_path) != 0) return err_code; \
        fw_default_real_path(path_user_id, sub_path, p, sizeof p); \
    } \
    (void)is_redir; /* 部分回调不使用 is_redir，抑制未使用警告 */

#define VFS_SETUP_LOG(path_val, err_code, op) \
    VFS_SETUP_CORE(path_val, err_code) \
    vfs_log_io(current_pkg, ctx->uid, op, sub_path, (nsp_ok && is_redir) ? rr.real_path : NULL, nsp_ok ? rr.monitor_on : false);

#define VFS_RETURN(val) do { return val; } while(0)

/* 框架版 I/O 监控日志：由框架记录目标应用操作的【原始路径】；
   target_path 为模块 resolve 可选返回的【目标路径】（REDIRECT 命中时
   非空，否则 NULL），附加到日志尾部。monitor 开关来自模块配置。 */
static void vfs_log_io(const char* pkg, uid_t uid, const char* op, const char* orig_path,
                       const char* target_path, bool monitor_on) {
    if (monitor_on) {
        if (target_path && target_path[0]) {
            log_internal(LOG_IO, "[%s(%u)] [%s] %s -> %s", pkg, uid, op, orig_path, target_path);
        } else {
            log_internal(LOG_IO, "[%s(%u)] [%s] %s", pkg, uid, op, orig_path);
        }
    }
    if (target_path && target_path[0] && g_min_log_level == LOG_DEBUG) {
        log_internal(LOG_DEBUG, "[MAP] %s: '%s' -> '%s'", op, orig_path, target_path);
    }
}

static void vfs_log_io_err(const char* pkg, const char* op, const char* sub_path, const char* fmt, ...) {
    char msg[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(msg, sizeof(msg), fmt, args);
    va_end(args);
    log_internal(LOG_IO, "[%s] [ERR] %s %s %s", pkg, op, sub_path, msg);
}

/* readdir 去重哈希（原 vfs_core 提供，框架保留） */
#define HASH_BUCKETS 1024
typedef struct HashNode { char* name; struct HashNode* next; } HashNode;
typedef struct { HashNode* buckets[HASH_BUCKETS]; } DirHashTable;

static void vfs_hash_init(DirHashTable* ht) { memset(ht->buckets, 0, sizeof(ht->buckets)); }

static unsigned long hash_djb2(const char *str) {
    unsigned long hash = 5381;
    int c;
    while ((c = *str++)) hash = ((hash << 5) + hash) + c;
    return hash;
}

static bool vfs_hash_insert(DirHashTable* ht, const char* name) {
    unsigned long h = hash_djb2(name) % HASH_BUCKETS;
    HashNode* node = ht->buckets[h];
    while (node) { if (strcmp(node->name, name) == 0) return false; node = node->next; }
    HashNode* new_node = malloc(sizeof(HashNode));
    if (new_node) {
        new_node->name = strdup(name);
        if (!new_node->name) { free(new_node); return false; }
        new_node->next = ht->buckets[h];
        ht->buckets[h] = new_node;
        return true;
    }
    return false;
}

static void vfs_hash_free(DirHashTable* ht) {
    for (int i = 0; i < HASH_BUCKETS; i++) {
        HashNode* node = ht->buckets[i];
        while (node) {
            HashNode* temp = node;
            node = node->next;
            free(temp->name);
            free(temp);
        }
    }
}

/* 为合成目录 stat 生成非零 inode（原 vfs_core.h static inline） */
static inline ino_t synthetic_inode(const char *path) {
    if (!path) return 1;
    unsigned long h = 5381;
    int c;
    while ((c = (unsigned char)*path++)) h = ((h << 5) + h) + c;
    return (ino_t)(h | 1);
}

static int vfs_getattr(const char *path, struct stat *st, struct fuse_file_info *fi) {
    vfs_flush_pending_closes();
    (void)fi; VFS_SETUP_CORE(path, -ENOENT);
    if (st == nullptr) VFS_RETURN(-EINVAL);
    /* 后端分派：路径命中 BACKEND 模块时由模块方法提供元数据（模块不实现 FUSE） */
    const NspModuleOps* bops = NULL;
    if (rr.is_ftp && module_backend_lookup(sub_path, &bops) == 0 && bops->backend_getattr) {
        memset(st, 0, sizeof *st);
        int brc = bops->backend_getattr(sub_path, st);
        module_backend_put(bops);
        if (brc != 0) VFS_RETURN(brc < 0 ? brc : -EIO);
        if (!g_preserve_perms) { st->st_uid = ctx->uid; st->st_gid = ctx->gid; }
        VFS_RETURN(0);
    }
    if (lstat(p, st) == -1) {
        int err = errno;
        if ((err == ENOENT || err == EACCES) && (is_android_skel_dir(sub_path) || rr.is_virtual_ancestor || rr.is_redirect_target)) {
            memset(st, 0, sizeof(struct stat)); st->st_ino = synthetic_inode(sub_path); st->st_mode = S_IFDIR | 0755; st->st_nlink = 2; st->st_uid = ctx->uid; st->st_gid = ctx->gid;
            VFS_RETURN(0);
        }
        log_fuse_err("GETATTR", path, err);
        if (err == EIO) { vfs_log_io_err(current_pkg, "GETATTR", sub_path, "EIO real='%s'", p); VFS_RETURN(-EIO); }
        if (err != ENOENT && g_min_log_level == LOG_DEBUG) vfs_log_io_err(current_pkg, "GETATTR", sub_path, "errno=%d real='%s'", err, p);
        VFS_RETURN(-err);
    }
    bool is_data_or_obb = (strncmp(sub_path, "/Android/data", 13) == 0 ||
                           strncmp(sub_path, "/Android/obb", 12) == 0);
    if (!g_preserve_perms && !is_data_or_obb) { 
        st->st_uid = ctx->uid; 
        st->st_gid = ctx->gid; 
    } else if (is_redir && S_ISDIR(st->st_mode)) {
        st->st_mode = (st->st_mode & ~07777) | 0777;
    }
    if (is_android_skel_dir(sub_path)) {
        st->st_mode = (st->st_mode & ~07777) | S_IFDIR | 0755;
        st->st_uid = ctx->uid;
        st->st_gid = ctx->gid;
    }
    VFS_RETURN(0);
}

static int vfs_access(const char *path, int mask) {
    vfs_flush_pending_closes();
    VFS_SETUP_CORE(path, -ENOENT);
    /* 后端路径：访问检查由后端语义决定，框架默认放行 */
    const NspModuleOps* bops = NULL;
    if (rr.is_ftp && module_backend_lookup(sub_path, &bops) == 0) { module_backend_put(bops); VFS_RETURN(0); }
    if (access(p, mask) == -1) {
        int err = errno; 
        if ((err == ENOENT || err == EACCES) && (is_android_skel_dir(sub_path) || rr.is_virtual_ancestor || rr.is_redirect_target)) {
            VFS_RETURN(0);
        }
        log_fuse_err("ACCESS", path, err);
        if (err == EIO) VFS_RETURN(-EIO);
        vfs_log_io_err(current_pkg, "ACCESS", sub_path, "errno=%d", err); VFS_RETURN(-err);
    }
    VFS_RETURN(0);
}

static int vfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi, enum fuse_readdir_flags flags) {
    vfs_flush_pending_closes();
    (void)offset; (void)flags; (void)fi; VFS_SETUP_CORE(path, -ENOENT);
    vfs_log_io(current_pkg, ctx->uid, "READDIR", sub_path, (nsp_ok && is_redir) ? rr.real_path : NULL, nsp_ok ? rr.monitor_on : false);
    LOG_DBG_PERF("[READDIR_ENTRY] path=%s real=%s", path, p);

    /* 后端分派：readdir 由模块方法返回条目，框架负责 filler */
    const NspModuleOps* bops = NULL;
    if (rr.is_ftp && module_backend_lookup(sub_path, &bops) == 0 && bops->backend_readdir) {
        NspDirEntry entries[1024];
        memset(entries, 0, sizeof entries);   /* 清零防御：防后端未填充字段残留栈垃圾 */
        int n = bops->backend_readdir(sub_path, entries, 1024);
        module_backend_put(bops);
        if (n < 0) VFS_RETURN(n);
        /* POSIX readdir 恒含 . / ..（与本地文件系统 readdir 路径一致） */
        struct stat dirst; memset(&dirst, 0, sizeof dirst);
        dirst.st_mode = S_IFDIR | 0755;
        if (!g_preserve_perms) { dirst.st_uid = ctx->uid; dirst.st_gid = ctx->gid; }
        filler(buf, ".", &dirst, 0, 0);
        filler(buf, "..", &dirst, 0, 0);
        for (int i = 0; i < n; i++) {
            struct stat st; memset(&st, 0, sizeof st);
            st.st_mode = entries[i].is_dir ? (S_IFDIR | 0755) : (S_IFREG | 0644);
            if (!g_preserve_perms) { st.st_uid = ctx->uid; st.st_gid = ctx->gid; }
            if (filler(buf, entries[i].name, &st, 0, 0) != 0) break;
        }
        VFS_RETURN(0);
    }

    /* 根据 g_disable_sandbox 强制跳过沙盒屏蔽逻辑 */
    bool skip_sandbox = (path_user_id < 0) || g_disable_sandbox;
    
    DirHashTable ht; vfs_hash_init(&ht);
    DIR *dp = opendir(p);
    char item_sub_path[2048], item_real_path[2048];
    bool is_root = (strcmp(sub_path, "/") == 0 || sub_path[0] == '\0');
    bool is_android_dir = (!skip_sandbox && (strcmp(sub_path, "/Android") == 0 || strcmp(sub_path, "/Android/") == 0));
    bool hide_others = (!skip_sandbox && current_pkg[0] && strcmp(current_pkg, "system") != 0 && strcmp(current_pkg, "unknown") != 0);
    bool force_android_skel = hide_others;
    bool has_data = false, has_obb = false, has_android = false, has_pkg = false;
    
    if (!dp) {
        int err = errno;
        if (!is_android_skel_dir(sub_path) && !(err == ENOENT && (rr.is_virtual_ancestor || rr.is_redirect_target))) {
            log_fuse_err("READDIR", path, err);
        }
    } else {
        struct dirent *de;
        while ((de = readdir(dp)) != nullptr) {
            if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;
            if (is_root) snprintf(item_sub_path, 2047, "/%s", de->d_name); else snprintf(item_sub_path, 2047, "%s/%s", sub_path, de->d_name);
            if (path_contains_invalid_chars(de->d_name)) continue;
            /* 子项轻量探测（probe）：只判 hidden/redirect_target，不构建真实路径、
               不触发 sandbox 目录创建（无模块时直通不过滤）。
               user_id 目录条目（/0、/1...）旧语义用原始串判 redirect_target 恒 false
               （Trie 无数字前缀规则）；剥离 /0/ 后会误判为根目录 sandbox 重定向目标，
               故豁免其 redirect_target 检查（仅 hidden 生效） */
            if (ctx->uid != 0) {
                bool uid_dir = (item_sub_path[0] == '/' && isdigit((unsigned char)item_sub_path[1]) &&
                                (item_sub_path[2] == '\0' || item_sub_path[2] == '/'));
                NspQueryCtx iq = { .uid = ctx->uid, .pid = ctx->pid, .gid = ctx->gid, .path = item_sub_path };
                NspProbeResult ir; memset(&ir, 0, sizeof ir);
                if (module_dispatch_probe(&iq, &ir) == NSP_DISPATCH_OK && ir.valid) {
                    if (ir.hidden || (!uid_dir && ir.is_redirect_target)) continue;
                }
            }
            if (is_root && strcmp(de->d_name, "Android") == 0) has_android = true;
            if (is_android_dir) {
                if (strcmp(de->d_name, "data") == 0) has_data = true;
                else if (strcmp(de->d_name, "obb") == 0) has_obb = true;
            }
            if (hide_others && (strcmp(sub_path, "/Android/data") == 0 || strcmp(sub_path, "/Android/data/") == 0 || strcmp(sub_path, "/Android/obb") == 0 || strcmp(sub_path, "/Android/obb/") == 0)) {
                if (strcmp(de->d_name, current_pkg) != 0) continue;
                has_pkg = true;
            }
            if (vfs_hash_insert(&ht, de->d_name)) {
                struct stat st; memset(&st, 0, sizeof(st));
                snprintf(item_real_path, 2047, "%s/%s", p, de->d_name);
                if (lstat(item_real_path, &st) == 0) {
                    if (!g_preserve_perms) { st.st_uid = ctx->uid; st.st_gid = ctx->gid; }
                    if (filler(buf, de->d_name, &st, 0, 0) != 0) {
                        closedir(dp);
                        vfs_hash_free(&ht);
                        VFS_RETURN(0);
                    }
                } else {
                    if (filler(buf, de->d_name, nullptr, 0, 0) != 0) {
                        closedir(dp);
                        vfs_hash_free(&ht);
                        VFS_RETURN(0);
                    }
                }
            }
        }
        closedir(dp);
    }
    
    if (is_root && force_android_skel && !has_android) {
        /* 经 ht 去重：ALLOW /Android 会使 vfs_is_redirect_target 在物理循环里跳过真实
           Android（:191），has_android 因此为 false；但 vfs_fill_virtual_dirs 会经 ht
           合成虚拟 Android。此处若不经 ht 直接 filler，将与后者各填一份 → 出现两个 Android。
           与 :246 hide_others 合成 current_pkg 的做法对齐：先 vfs_hash_insert 再 filler。 */
        if (vfs_hash_insert(&ht, "Android")) {
            struct stat st_dir; memset(&st_dir, 0, sizeof(st_dir)); st_dir.st_ino = synthetic_inode("Android"); st_dir.st_mode = S_IFDIR | 0755; st_dir.st_uid = ctx->uid; st_dir.st_gid = ctx->gid;
            if (filler(buf, "Android", &st_dir, 0, 0) != 0) {
                vfs_hash_free(&ht);
                VFS_RETURN(0);
            }
        }
    }
    if (is_android_dir) {
        if (!has_data) {
            struct stat st_dir; memset(&st_dir, 0, sizeof(st_dir)); st_dir.st_ino = synthetic_inode("data"); st_dir.st_mode = S_IFDIR | 0755; st_dir.st_uid = ctx->uid; st_dir.st_gid = ctx->gid;
            if (filler(buf, "data", &st_dir, 0, 0) != 0) {
                vfs_hash_free(&ht);
                VFS_RETURN(0);
            }
        }
        if (!has_obb) {
            struct stat st_dir; memset(&st_dir, 0, sizeof(st_dir)); st_dir.st_ino = synthetic_inode("obb"); st_dir.st_mode = S_IFDIR | 0755; st_dir.st_uid = ctx->uid; st_dir.st_gid = ctx->gid;
            if (filler(buf, "obb", &st_dir, 0, 0) != 0) {
                vfs_hash_free(&ht);
                VFS_RETURN(0);
            }
        }
    }
    if (hide_others && !has_pkg && (strcmp(sub_path, "/Android/data") == 0 || strcmp(sub_path, "/Android/data/") == 0 || strcmp(sub_path, "/Android/obb") == 0 || strcmp(sub_path, "/Android/obb/") == 0)) {
        struct stat st_dir; memset(&st_dir, 0, sizeof(st_dir)); st_dir.st_ino = synthetic_inode(current_pkg); st_dir.st_mode = S_IFDIR | 0755; st_dir.st_uid = ctx->uid; st_dir.st_gid = ctx->gid;
        if (vfs_hash_insert(&ht, current_pkg)) {
            if (filler(buf, current_pkg, &st_dir, 0, 0) != 0) {
                vfs_hash_free(&ht);
                VFS_RETURN(0);
            }
        }
    }
    /* 虚拟目录补充：模块 readdir_extra 返回条目数组，框架 ht 去重 + filler */
    {
        NspDirEntry virt[MAX_MODULES * 8];
        NspQueryCtx vq = { .uid = ctx->uid, .pid = ctx->pid, .gid = ctx->gid, .path = sub_path };
        int vn = module_dispatch_readdir(&vq, sub_path, path_user_id, current_pkg, is_root, virt, MAX_MODULES * 8);
        for (int vi = 0; vi < vn; vi++) {
            if (virt[vi].name[0] == '\0') continue;
            if (vfs_hash_insert(&ht, virt[vi].name)) {
                struct stat st_dir; memset(&st_dir, 0, sizeof(st_dir));
                st_dir.st_ino = synthetic_inode(virt[vi].name);
                st_dir.st_mode = S_IFDIR | 0755;
                st_dir.st_uid = ctx->uid;
                st_dir.st_gid = ctx->gid;
                if (filler(buf, virt[vi].name, &st_dir, 0, 0) != 0) {
                    vfs_hash_free(&ht);
                    VFS_RETURN(0);
                }
            }
        }
    }
    if (filler(buf, ".", nullptr, 0, 0) != 0) {
        vfs_hash_free(&ht);
        VFS_RETURN(0);
    }
    if (filler(buf, "..", nullptr, 0, 0) != 0) {
        vfs_hash_free(&ht);
        VFS_RETURN(0);
    }
    vfs_hash_free(&ht);
    VFS_RETURN(0);
}

static void inherit_parent_attributes(const char* real_path, mode_t base_mode) {
    char parent[PATH_MAX]; strncpy(parent, real_path, PATH_MAX - 1); parent[PATH_MAX - 1] = '\0';
    char* last = strrchr(parent, '/');
    if (last) {
        if (last == parent) strcpy(parent, "/"); else *last = '\0';
        struct stat st;
        if (lstat(parent, &st) == 0) {
            if (lchown(real_path, st.st_uid, st.st_gid) != 0) { }
            mode_t final_mode = st.st_mode & 07777;
            if (!S_ISDIR(base_mode)) { final_mode &= ~0111; final_mode &= ~06000; }
            chmod(real_path, final_mode);
#ifdef TARGET_ANDROID
            char context[256]; ssize_t ctx_len = lgetxattr(parent, "security.selinux", context, sizeof(context));
            if (ctx_len > 0) lsetxattr(real_path, "security.selinux", context, (size_t)ctx_len, 0);
            else if (strstr(real_path, STORAGE_BASE) == real_path) lsetxattr(real_path, "security.selinux", "u:object_r:media_rw_data_file:s0", 35, 0);
#endif
        }
    }
}

static int vfs_open(const char *path, struct fuse_file_info *fi) {
    FTP_DBG("vfs_open: 入口 path=%s\n", path);
    vfs_flush_pending_closes();
    VFS_SETUP_CORE(path, -ENOENT);
    vfs_log_io(current_pkg, ctx->uid, "OPEN", sub_path, (nsp_ok && is_redir) ? rr.real_path : NULL, nsp_ok ? rr.monitor_on : false);
    if (g_strip_o_direct && (fi->flags & O_DIRECT)) fi->flags &= ~O_DIRECT;
    if (ctx->uid != 0 && rr.ro) {
        int accmode = fi->flags & O_ACCMODE;
        if (accmode == O_WRONLY || accmode == O_RDWR || (fi->flags & O_CREAT) || (fi->flags & O_TRUNC) || (fi->flags & O_APPEND)) {
            log_fuse_err("OPEN_RO_DENIED", path, EROFS);
            VFS_RETURN(-EROFS);
        }
    }
    /* 后端分派：open 由模块方法打开，fi->fh 存后端句柄（read/write 经 match 复用） */
    const NspModuleOps* bops = NULL;
    if (rr.is_ftp && module_backend_lookup(sub_path, &bops) == 0 && bops->backend_open) {
        uint64_t h = 0;
        int brc = bops->backend_open(sub_path, fi->flags, &h);
        module_backend_put(bops);
        if (brc != 0) VFS_RETURN(brc < 0 ? brc : -EIO);
        /* FTP 路径：句柄为模块小整数 ID（非 fd），不设 FD 透传等本地
           文件系统才可用的优化（passthrough 仅对下方本地 open 的 fd）；
           设 direct_io 绕过内核 page cache——FUSE 内核在 close 后可能
           失效 page cache，但 dentry 缓存仍命中第二次 open 导致 read
           返回空（复用缓存的 fh 但 page cache 已空） */
        fi->fh = h | NSP_FH_BACKEND_FLAG;
        fi->direct_io = 1;
        FTP_DBG("vfs_open: 后端命中 sub=%s fh=%llu flags=%o direct_io=1\n", sub_path, (unsigned long long)fi->fh, fi->flags);
        VFS_RETURN(0);
    }
    int fd = open(p, fi->flags | O_CLOEXEC, is_redir ? 0666 : 0);
    if (fd == -1) { 
        int err = errno; 
        log_fuse_err("OPEN", path, err);
        if (err != ENOENT) vfs_log_io_err(current_pkg, "OPEN", sub_path, "errno=%d real='%s'", err, p); 
        VFS_RETURN(-err); 
    }
    fi->fh = fd;
#ifdef TARGET_ANDROID
    if (g_passthrough_enabled) {
        fuse_req_t req = fuse_get_context()->req;
        int backing_id = fuse_passthrough_enable(req, (unsigned int)fd);
        if (backing_id > 0) {
            fi->passthrough_fh = (uint32_t)backing_id;
            LOG_DBG_PERF("FUSE Passthrough: ✅ %s -> passthrough_fh=%d (backing_id=%d)",
                    sub_path, fi->passthrough_fh, backing_id);
        } else {
            LOG_DBG_PERF("FUSE Passthrough: ❌ %s -> %s (errno=%d)",
                    sub_path, strerror(errno), errno);
        }
    }
#endif
    VFS_RETURN(0);
}

static int vfs_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
    VFS_SETUP_CORE(path, -EACCES);
    vfs_log_io(current_pkg, ctx->uid, "CREATE", sub_path, (nsp_ok && is_redir) ? rr.real_path : NULL, nsp_ok ? rr.monitor_on : false);
    if (ctx->uid != 0 && rr.ro) {
        log_fuse_err("CREATE_RO_DENIED", path, EROFS);
        VFS_RETURN(-EROFS);
    }
    if (g_strip_o_direct && (fi->flags & O_DIRECT)) fi->flags &= ~O_DIRECT;
    /* 后端分派：create 由模块方法创建，fi->fh 存后端句柄 */
    const NspModuleOps* bops = NULL;
    if (rr.is_ftp && module_backend_lookup(sub_path, &bops) == 0 && bops->backend_create) {
        uint64_t h = 0;
        int brc = bops->backend_create(sub_path, mode, &h);
        module_backend_put(bops);
        if (brc != 0) VFS_RETURN(brc < 0 ? brc : -EIO);
        fi->fh = h | NSP_FH_BACKEND_FLAG;
        VFS_RETURN(0);
    }
    int fd = open(p, fi->flags | O_CREAT | O_EXCL | O_CLOEXEC, is_redir ? 0666 : mode);
    if (fd == -1) {
        if (errno == ENOENT) {
            char *p_dup = strdup(p), *p_dir = dirname(p_dup);
            if (mkdir_recursive_p(p_dir, 0775) == 0) fd = open(p, fi->flags | O_CREAT | O_EXCL | O_CLOEXEC, is_redir ? 0666 : mode);
            free(p_dup);
        }
        if (fd == -1) {
            int err = errno;
            log_fuse_err("CREATE", path, err);
            if (err != EEXIST) vfs_log_io_err(current_pkg, "CREATE", sub_path, "errno=%d", err);
            VFS_RETURN(-err);
        }
    }
    inherit_parent_attributes(p, S_IFREG);
    fi->fh = fd;
#ifdef TARGET_ANDROID
    if (g_passthrough_enabled) {
        fuse_req_t req = fuse_get_context()->req;
        int backing_id = fuse_passthrough_enable(req, (unsigned int)fd);
        if (backing_id > 0) {
            fi->passthrough_fh = (uint32_t)backing_id;
            LOG_DBG_PERF("FUSE Passthrough: ✅ %s -> passthrough_fh=%d (backing_id=%d)",
                    sub_path, fi->passthrough_fh, backing_id);
        } else {
            LOG_DBG_PERF("FUSE Passthrough: ❌ %s -> %s (errno=%d)",
                    sub_path, strerror(errno), errno);
        }
    }
#endif
    VFS_RETURN(0);
}

static int vfs_mkdir(const char *path, mode_t mode) {
    VFS_SETUP_CORE(path, -EACCES);
    vfs_log_io(current_pkg, ctx->uid, "MKDIR", sub_path, (nsp_ok && is_redir) ? rr.real_path : NULL, nsp_ok ? rr.monitor_on : false);
    if (ctx->uid != 0 && rr.ro) {
        log_fuse_err("MKDIR_RO_DENIED", path, EROFS);
        VFS_RETURN(-EROFS);
    }
    /* 后端分派：mkdir 由模块方法创建（rr.is_ftp 短路，避免非 FTP 路径付出
       无条件 rwlock + backend_match 扫描） */
    const NspModuleOps* bops = NULL;
    if (rr.is_ftp && module_backend_lookup(sub_path, &bops) == 0 && bops && bops->backend_mkdir) {
        int brc = bops->backend_mkdir(sub_path, mode);
        module_backend_put(bops);
        if (brc != 0) VFS_RETURN(brc < 0 ? brc : -EIO);
        VFS_RETURN(0);
    }
    /* fallback：lookup 成功但未走后端分支时释放引用，防止 backend_refs 泄漏
       导致模块无法热卸载（loader 等待 backend_refs == 0） */
    if (bops) module_backend_put(bops);
    int ret = mkdir(p, is_redir ? 0775 : mode);
    if (ret == -1) {
        if (errno == ENOENT) {
            char *p_dup = strdup(p), *parent = dirname(p_dup);
            if (mkdir_recursive_p(parent, 0775) == 0) ret = mkdir(p, is_redir ? 0775 : mode);
            free(p_dup);
        }
        if (ret == -1) { 
            int err = errno;
            log_fuse_err("MKDIR", path, err);
            if (err != EEXIST) vfs_log_io_err(current_pkg, "MKDIR", sub_path, "errno=%d", err); 
            VFS_RETURN(-err); 
        }
    }
    inherit_parent_attributes(p, S_IFDIR);
    VFS_RETURN(0);
}

static int vfs_unlink(const char *path) {
    VFS_SETUP_CORE(path, -EACCES);
    vfs_log_io(current_pkg, ctx->uid, "UNLINK", sub_path, (nsp_ok && is_redir) ? rr.real_path : NULL, nsp_ok ? rr.monitor_on : false);
    if (ctx->uid != 0 && rr.ro) {
        log_fuse_err("UNLINK_RO_DENIED", path, EROFS);
        VFS_RETURN(-EROFS);
    }
    /* 后端分派：unlink 由模块方法删除 */
    const NspModuleOps* bops = NULL;
    if (rr.is_ftp && module_backend_lookup(sub_path, &bops) == 0 && bops->backend_unlink) {
        int brc = bops->backend_unlink(sub_path);
        module_backend_put(bops);
        if (brc != 0) VFS_RETURN(brc < 0 ? brc : -EIO);
        VFS_RETURN(0);
    }
    int ret = unlink(p);
    if (ret == -1) {
        int err = errno;
        log_fuse_err("UNLINK", path, err);
        VFS_RETURN(-err);
    }
    VFS_RETURN(0);
}

static int vfs_rmdir(const char *path) {
    VFS_SETUP_CORE(path, -EACCES);
    vfs_log_io(current_pkg, ctx->uid, "RMDIR", sub_path, (nsp_ok && is_redir) ? rr.real_path : NULL, nsp_ok ? rr.monitor_on : false);
    if (ctx->uid != 0 && rr.ro) {
        log_fuse_err("RMDIR_RO_DENIED", path, EROFS);
        VFS_RETURN(-EROFS);
    }
    if (rr.is_virtual_ancestor || rr.is_redirect_target) {
        if (!fw_virtual_dir_empty(sub_path, p, current_pkg, path_user_id, ctx->uid)) {
            log_fuse_err("RMDIR_NOT_EMPTY", path, ENOTEMPTY);
            VFS_RETURN(-ENOTEMPTY);
        }
        int ret = rmdir(p);
        if (ret == -1 && errno != ENOENT) {
            int err = errno;
            log_fuse_err("RMDIR", path, err);
            VFS_RETURN(-err);
        }
        VFS_RETURN(0);
    }
    /* 后端分派：rmdir 由模块方法删除 */
    const NspModuleOps* bops = NULL;
    if (rr.is_ftp && module_backend_lookup(sub_path, &bops) == 0 && bops->backend_rmdir) {
        int brc = bops->backend_rmdir(sub_path);
        module_backend_put(bops);
        if (brc != 0) VFS_RETURN(brc < 0 ? brc : -EIO);
        VFS_RETURN(0);
    }
    int ret = rmdir(p);
    if (ret == -1) {
        int err = errno;
        if (err == ENOTEMPTY) {
            int r = recursive_rmdir(p);
            if (r == 0) VFS_RETURN(0);
            log_fuse_err("RMDIR", path, -r);
            VFS_RETURN(r);
        }
        log_fuse_err("RMDIR", path, err);
        VFS_RETURN(-err);
    }
    VFS_RETURN(0);
}

static int vfs_read(const char *path, char *buf, size_t size, off_t off, struct fuse_file_info *fi) {
    FTP_DBG("vfs_read: 入口 path=%s fh=%llu off=%lld size=%zu\n", path, (unsigned long long)(fi ? fi->fh : 0), (long long)off, size);
    if ((fi->fh & NSP_FH_BACKEND_FLAG) && module_backend_active()) {
        /* 后端句柄（本地 fd 无标记）：轻量解析（仅剥离 /0/）定位后端模块 */
        int uid = -1; char sub[PATH_MAX];
        if (fw_parse_path(path, &uid, sub, sizeof sub) == 0) {
            const NspModuleOps* bops = NULL;
            FTP_DBG("vfs_read: fh=%llu sub=%s\n", (unsigned long long)fi->fh, sub);
            if (module_backend_lookup(sub, &bops) == 0 && bops->backend_read) {
                size_t got = 0;
                int rc = bops->backend_read(fi->fh & ~NSP_FH_BACKEND_FLAG, buf, size, off, &got);
                module_backend_put(bops);
                FTP_DBG("vfs_read: 后端返回 rc=%d got=%zu\n", rc, got);
                return rc == 0 ? (int)got : (rc < 0 ? rc : -EIO);
            }
            FTP_DBG("vfs_read: 后端未命中 sub=%s\n", sub);
        }
        /* 后端句柄但未命中后端（模块卸载/路径不匹配）：返回错误，不把
           后端句柄当 fd 用（pread 后端 ID 会 EBADF 或崩溃） */
        return -EIO;
    }
    ssize_t ret = pread(fi->fh, buf, size, off);
    if (ret == -1) {
        int err = errno;
        log_fuse_err("READ", path, err);
        return -err;
    }
    return (int)ret;
}

static int vfs_write(const char *path, const char *buf, size_t size, off_t off, struct fuse_file_info *fi) {
    if (module_backend_active()) {
        int uid = -1; char sub[PATH_MAX];
        if (fw_parse_path(path, &uid, sub, sizeof sub) == 0) {
            const NspModuleOps* bops = NULL;
            if (module_backend_lookup(sub, &bops) == 0 && bops->backend_write) {
                size_t wrote = 0;
                int rc = bops->backend_write(fi->fh & ~NSP_FH_BACKEND_FLAG, buf, size, off, &wrote);
                module_backend_put(bops);
                return rc == 0 ? (int)wrote : (rc < 0 ? rc : -EIO);
            }
        }
        return -EIO;   /* 后端句柄未命中后端，不 pwrite */
    }
    ssize_t ret = pwrite(fi->fh, buf, size, off);
    if (ret == -1) {
        int err = errno;
        log_fuse_err("WRITE", path, err);
        return -err;
    }
    return (int)ret;
}

static int vfs_release(const char *path, struct fuse_file_info *fi) {
    FTP_DBG("vfs_release: 入口 path=%s fh=%llu\n", path, (unsigned long long)(fi ? fi->fh : 0));
    if ((fi->fh & NSP_FH_BACKEND_FLAG) && module_backend_active()) {
        /* 后端句柄（本地 fd 无标记）：避免完整 resolve 在 HIDE/解析失败时提前返回而泄漏
           已打开的 fd；未命中后端则兜底 close */
        int uid = -1; char sub[PATH_MAX];
        if (fw_parse_path(path, &uid, sub, sizeof sub) == 0) {
            const NspModuleOps* bops = NULL;
            if (module_backend_lookup(sub, &bops) == 0 && bops->backend_release) {
                int rc = bops->backend_release(fi->fh & ~NSP_FH_BACKEND_FLAG);
                module_backend_put(bops);
                /* 句柄已在 FLUSH 中释放（上传+释放提前完成）：-EINVAL 视为成功 */
                return (rc == -EINVAL) ? 0 : (rc < 0 ? rc : 0);
            }
        }
        return 0;   /* 后端句柄未命中后端：不 close（非 fd），避免崩溃 */
    }
    close(fi->fh);
    return 0;
}

static int vfs_fsync(const char *path, int datasync, struct fuse_file_info *fi) {
    if ((fi->fh & NSP_FH_BACKEND_FLAG) && module_backend_active()) {
        int uid = -1; char sub[PATH_MAX];
        if (fw_parse_path(path, &uid, sub, sizeof sub) == 0) {
            const NspModuleOps* bops = NULL;
            if (module_backend_lookup(sub, &bops) == 0) { module_backend_put(bops); return 0; }
        }
    }
    if (!fi || fi->fh <= 0) return 0;
    int ret = (datasync ? fdatasync(fi->fh) : fsync(fi->fh));
    if (ret == -1) {
        if (errno == EBADF || errno == EINVAL) return 0;
        log_fuse_err("FSYNC", path, errno);
        return -errno;
    }
    return 0;
}

static int vfs_flush(const char *path, struct fuse_file_info *fi) {
    /* close() 同步等待 FLUSH 返回——写模式 STOR 上传必须在此完成！
       release 是异步回调，close() 返回后立即读取会读到未上传完成的
       旧数据/0 字节（32MB 大文件写后立即读必现）；backend_release
       在此完成上传并释放句柄（读模式则停线程+释放） */
    if ((fi->fh & NSP_FH_BACKEND_FLAG) && module_backend_active()) {
        int uid = -1; char sub[PATH_MAX];
        if (fw_parse_path(path, &uid, sub, sizeof sub) == 0) {
            const NspModuleOps* bops = NULL;
            if (module_backend_lookup(sub, &bops) == 0 && bops->backend_release) {
                int rc = bops->backend_release(fi->fh & ~NSP_FH_BACKEND_FLAG);
                module_backend_put(bops);
                if (rc == 0) {
                    /* 上传完成：使路径缓存失效（attr_timeout=1.0 下旧大小/
                       不存在缓存会让立即读取 getattr 命中旧值；libfuse3
                       仅有 fuse_invalidate_path，同时失效 attr+entry） */
                    struct fuse_context* ctx = fuse_get_context();
                    if (ctx && ctx->fuse) fuse_invalidate_path(ctx->fuse, path);
                }
                /* 句柄已释放（重复 FLUSH/RELEASE）：视为成功 */
                return (rc == -EINVAL) ? 0 : (rc < 0 ? rc : 0);
            }
        }
        return 0;
    }
    fsync(fi->fh);
    return 0;
}

static int vfs_readlink(const char *path, char *buf, size_t size) {
    VFS_SETUP_CORE(path, -ENOENT);
    vfs_log_io(current_pkg, ctx->uid, "READLINK", sub_path, (nsp_ok && is_redir) ? rr.real_path : NULL, nsp_ok ? rr.monitor_on : false);
    ssize_t res = readlink(p, buf, size - 1);
    if (res == -1) {
        log_fuse_err("READLINK", path, errno);
        VFS_RETURN(-errno);
    }
    buf[res] = '\0';
    VFS_RETURN(0);
}

static int vfs_opendir(const char *path, struct fuse_file_info *fi) {
    VFS_SETUP_CORE(path, -ENOENT);
    vfs_log_io(current_pkg, ctx->uid, "OPENDIR", sub_path, (nsp_ok && is_redir) ? rr.real_path : NULL, nsp_ok ? rr.monitor_on : false);
    /* 后端分派：目录由后端模块管理时直接放行（readdir 条目由模块方法提供，
       本地 real_path 不存在，不可 opendir） */
    const NspModuleOps* bops = NULL;
    if (rr.is_ftp && module_backend_lookup(sub_path, &bops) == 0) {
        fi->fh = 0;
        VFS_RETURN(0);
    }
    DIR* dp = opendir(p);
    if (dp) {
        closedir(dp);
        fi->fh = 0;
        VFS_RETURN(0);
    }
    int err = errno;
    if ((err == ENOENT || err == EACCES) && (is_android_skel_dir(sub_path) || rr.is_virtual_ancestor || rr.is_redirect_target)) {
        VFS_RETURN(0);
    }
    log_fuse_err("OPENDIR", path, err);
    VFS_RETURN(-err);
}

static int vfs_symlink(const char *target, const char *linkpath) {
    VFS_SETUP_CORE(linkpath, -EACCES);
    vfs_log_io(current_pkg, ctx->uid, "SYMLINK", sub_path, (nsp_ok && is_redir) ? rr.real_path : NULL, nsp_ok ? rr.monitor_on : false);
    if (ctx->uid != 0 && rr.ro) {
        log_fuse_err("SYMLINK_RO_DENIED", linkpath, EROFS);
        VFS_RETURN(-EROFS);
    }
    if (symlink(target, p) == -1) {
        if (errno == ENOENT) {
            char *p_dup = strdup(p), *p_dir = dirname(p_dup);
            if (mkdir_recursive_p(p_dir, 0775) == 0 && symlink(target, p) == 0) {
                free(p_dup);
                inherit_parent_attributes(p, S_IFLNK);
                VFS_RETURN(0);
            }
            free(p_dup);
        }
        log_fuse_err("SYMLINK", linkpath, errno);
        VFS_RETURN(-errno);
    }
    inherit_parent_attributes(p, S_IFLNK);
    VFS_RETURN(0);
}

static int recursive_rmdir(const char *path) {
    DIR *d = opendir(path);
    if (!d) return -errno;
    struct dirent *p;
    int r = 0;
    while (!r && (p = readdir(d))) {
        if (!strcmp(p->d_name, ".") || !strcmp(p->d_name, "..")) continue;
        char buf[PATH_MAX];
        snprintf(buf, sizeof(buf), "%s/%s", path, p->d_name);
        struct stat statbuf;
        if (!lstat(buf, &statbuf)) {
            if (S_ISDIR(statbuf.st_mode)) r = recursive_rmdir(buf);
            else r = unlink(buf);
        }
    }
    closedir(d);
    if (!r) r = rmdir(path);
    return r;
}

static int recursive_copy_dir(const char *src, const char *dst, uid_t uid, gid_t gid) {
    struct stat st;
    if (lstat(src, &st) != 0) return -errno;
    if (mkdir(dst, st.st_mode & 07777) != 0 && errno != EEXIST) return -errno;
    lchown(dst, st.st_uid, st.st_gid);
    DIR *d = opendir(src);
    if (!d) return -errno;
    struct dirent *p;
    int r = 0;
    while (!r && (p = readdir(d))) {
        if (!strcmp(p->d_name, ".") || !strcmp(p->d_name, "..")) continue;
        char s_path[PATH_MAX], d_path[PATH_MAX];
        snprintf(s_path, sizeof(s_path), "%s/%s", src, p->d_name);
        snprintf(d_path, sizeof(d_path), "%s/%s", dst, p->d_name);
        struct stat s_st;
        if (!lstat(s_path, &s_st)) {
            if (S_ISDIR(s_st.st_mode)) {
                r = recursive_copy_dir(s_path, d_path, uid, gid);
            } else if (S_ISREG(s_st.st_mode)) {
                int fd_src = open(s_path, O_RDONLY | O_CLOEXEC);
                if (fd_src >= 0) {
                    int fd_dst = open(d_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, s_st.st_mode & 0777);
                    if (fd_dst >= 0) {
                        char buf[16384]; 
                        ssize_t r_len;
                        bool copy_ok = true;
                        while ((r_len = read(fd_src, buf, sizeof(buf))) > 0) {
                            ssize_t w_off = 0;
                            while (w_off < r_len) {
                                ssize_t w_len = write(fd_dst, buf + w_off, r_len - w_off);
                                if (w_len < 0) {
                                    if (errno == EINTR) continue;
                                    copy_ok = false; break;
                                }
                                w_off += w_len;
                            }
                            if (!copy_ok) break;
                        }
                        if (r_len < 0) copy_ok = false;
                        if (copy_ok) {
                            struct timespec ts[2] = {s_st.st_atim, s_st.st_mtim}; 
                            futimens(fd_dst, ts);
                            fchown(fd_dst, s_st.st_uid, s_st.st_gid);
                            fchmod(fd_dst, s_st.st_mode & 07777);
#ifdef TARGET_ANDROID
                            char context[256];
                            ssize_t ctx_len = lgetxattr(s_path, "security.selinux", context, sizeof(context));
                            if (ctx_len > 0) lsetxattr(d_path, "security.selinux", context, (size_t)ctx_len, 0);
#endif
                        } else {
                            r = -EIO;
                        }
                        close(fd_dst);
                        if (!copy_ok) unlink(d_path);
                    } else {
                        r = -errno;
                    }
                    close(fd_src);
                } else {
                    r = -errno;
                }
            }
        }
    }
    closedir(d);
    return r;
}

static int vfs_rename_copy_file(const char* src, const char* dst, struct stat* st) {
    int fd_src = open(src, O_RDONLY | O_CLOEXEC);
    if (fd_src < 0) return -errno;
    int fd_dst = open(dst, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, st->st_mode & 0777);
    if (fd_dst < 0) {
        int err = errno;
        close(fd_src);
        return -err;
    }
    char *buf = malloc(65536);
    if (!buf) {
        close(fd_src); close(fd_dst);
        return -ENOMEM;
    }
    ssize_t r_len;
    int copy_err = 0;
    while ((r_len = read(fd_src, buf, 65536)) > 0) {
        ssize_t w_off = 0;
        while (w_off < r_len) {
            ssize_t w_len = write(fd_dst, buf + w_off, (size_t)(r_len - w_off));
            if (w_len < 0) {
                if (errno == EINTR) continue;
                copy_err = -errno;
                break;
            }
            w_off += w_len;
        }
        if (copy_err < 0) break;
    }
    if (r_len < 0 && copy_err == 0) copy_err = -errno;
    free(buf);
    if (copy_err == 0) {
        struct timespec ts[2] = {st->st_atim, st->st_mtim}; 
        futimens(fd_dst, ts); 
        fchown(fd_dst, st->st_uid, st->st_gid); 
        fchmod(fd_dst, st->st_mode & 07777);
#ifdef TARGET_ANDROID
        char context[256];
        ssize_t ctx_len = lgetxattr(src, "security.selinux", context, sizeof(context));
        if (ctx_len > 0) lsetxattr(dst, "security.selinux", context, (size_t)ctx_len, 0);
#endif
    }
    close(fd_src);
    close(fd_dst);
    if (copy_err < 0) {
        unlink(dst);
        return copy_err;
    }
    return 0;
}

static int vfs_rename(const char *from, const char *to, unsigned int flags) {
    struct fuse_context* ctx = fuse_get_context();
    if (!ctx) return -EACCES;
    /* from/to 各走一次分派器决策（无模块时直通回退） */
    NspQueryCtx q1 = { .uid = ctx->uid, .pid = ctx->pid, .gid = ctx->gid, .path = from };
    NspQueryCtx q2 = { .uid = ctx->uid, .pid = ctx->pid, .gid = ctx->gid, .path = to };
    NspResolveResult r1, r2;
    memset(&r1, 0, sizeof r1); memset(&r2, 0, sizeof r2);
    bool ok1 = (module_dispatch_resolve(&q1, &r1) == NSP_DISPATCH_OK && r1.valid);
    bool ok2 = (module_dispatch_resolve(&q2, &r2) == NSP_DISPATCH_OK && r2.valid);
    if ((ok1 && r1.hidden) || (ok2 && r2.hidden)) return -ENOENT;
    char sub_from[PATH_MAX], sub_to[PATH_MAX], p_from[PATH_MAX], p_to[PATH_MAX];
    int u_from = -1, u_to = -1;
    bool redir_from = false, redir_to = false;
    char pkg_from[128] = "unknown", pkg_to[128] = "unknown";
    if (ok1) {
        strncpy(pkg_from, r1.pkg[0] ? r1.pkg : "unknown", 127); pkg_from[127] = '\0';
        u_from = r1.user_id;
        strncpy(sub_from, r1.sub_path, sizeof sub_from - 1); sub_from[sizeof sub_from - 1] = '\0';
        strncpy(p_from, r1.real_path, sizeof p_from - 1); p_from[sizeof p_from - 1] = '\0';
        redir_from = r1.is_redir;
    } else {
        if (fw_parse_path(from, &u_from, sub_from, sizeof sub_from) != 0) return -ENOENT;
        fw_default_real_path(u_from, sub_from, p_from, sizeof p_from);
    }
    if (ok2) {
        strncpy(pkg_to, r2.pkg[0] ? r2.pkg : "unknown", 127); pkg_to[127] = '\0';
        u_to = r2.user_id;
        strncpy(sub_to, r2.sub_path, sizeof sub_to - 1); sub_to[sizeof sub_to - 1] = '\0';
        strncpy(p_to, r2.real_path, sizeof p_to - 1); p_to[sizeof p_to - 1] = '\0';
        redir_to = r2.is_redir;
    } else {
        if (fw_parse_path(to, &u_to, sub_to, sizeof sub_to) != 0) return -ENOENT;
        fw_default_real_path(u_to, sub_to, p_to, sizeof p_to);
    }
    if (ctx->uid != 0 && ((ok1 && r1.ro) || (ok2 && r2.ro))) {
        log_fuse_err("RENAME_RO_DENIED", from, EROFS);
        return -EROFS;
    }
    vfs_log_io(pkg_from, ctx->uid, "RENAME_FROM", sub_from, (ok1 && redir_from) ? r1.real_path : NULL, ok1 ? r1.monitor_on : false);
    vfs_log_io(pkg_to, ctx->uid, "RENAME_TO", sub_to, (ok2 && redir_to) ? r2.real_path : NULL, ok2 ? r2.monitor_on : false);
    /* 后端分派：from/to 命中后端时由模块方法重命名（两端须同一后端模块） */
    const NspModuleOps* bf_ops = NULL;
    const NspModuleOps* bt_ops = NULL;
    bool bf_hit = (ok1 && r1.is_ftp && module_backend_lookup(sub_from, &bf_ops) == 0);
    bool bt_hit = (ok2 && r2.is_ftp && module_backend_lookup(sub_to, &bt_ops) == 0);
    if (bf_hit || bt_hit) {
        if (bf_hit && bt_hit && bf_ops == bt_ops && bf_ops->backend_rename) {
            int brc = bf_ops->backend_rename(sub_from, sub_to);
            module_backend_put(bf_ops);
            return brc < 0 ? brc : 0;
        }
        return -EXDEV;   /* 跨后端/后端↔本地重命名不支持 */
    }
#ifdef SYS_renameat2
    if (flags && syscall(SYS_renameat2, AT_FDCWD, p_from, AT_FDCWD, p_to, flags) == 0) return 0;
#endif
    char *p_to_dup = strdup(p_to), *p_to_dir = dirname(p_to_dup);
    int mkdir_res = mkdir_recursive_p(p_to_dir, 0775);
    free(p_to_dup);
    if (mkdir_res != 0) {
        LOG_ERR("重命名创建目标父目录失败: %s (errno=%d)", p_to_dir, errno);
        return -errno;
    }
    if (rename(p_from, p_to) == 0) return 0;
    int err = errno;
    if (err == EXDEV) { 
        struct stat st;
        if (lstat(p_from, &st) == 0) {
            if (S_ISREG(st.st_mode)) {
                int copy_res = vfs_rename_copy_file(p_from, p_to, &st);
                if (copy_res == 0) {
                    unlink(p_from);
                    return 0;
                }
                LOG_ERR("跨设备复制文件失败: %s -> %s (err=%d)", p_from, p_to, copy_res);
                return copy_res;
            } else if (S_ISDIR(st.st_mode)) {
                int copy_res = recursive_copy_dir(p_from, p_to, ctx->uid, ctx->gid);
                if (copy_res == 0) {
                    if (recursive_rmdir(p_from) == 0) return 0;
                    else {
                        recursive_rmdir(p_to); 
                        return -errno;
                    }
                } else {
                    recursive_rmdir(p_to); 
                    LOG_ERR("跨设备复制文件夹失败: %s -> %s (err=%d)", p_from, p_to, copy_res);
                    return copy_res;
                }
            }
        } else {
            return -errno;
        }
    }
    log_fuse_err("RENAME", from, err);
    return -err;
}

static int vfs_chmod(const char *path, mode_t mode, struct fuse_file_info *fi) {
    (void)fi; VFS_SETUP_CORE(path, -EACCES);
    if (ctx->uid != 0 && rr.ro) {
        log_fuse_err("CHMOD_RO_DENIED", path, EROFS);
        VFS_RETURN(-EROFS);
    }
    int ret = chmod(p, mode);
    if (ret == -1) {
        int err = errno;
        log_fuse_err("CHMOD", path, err);
        VFS_RETURN(-err);
    }
    VFS_RETURN(0);
}

static int vfs_chown(const char *path, uid_t uid, gid_t gid, struct fuse_file_info *fi) {
    (void)fi; VFS_SETUP_CORE(path, -EACCES);
    if (ctx->uid != 0 && rr.ro) {
        log_fuse_err("CHOWN_RO_DENIED", path, EROFS);
        VFS_RETURN(-EROFS);
    }
    int ret = lchown(p, uid, gid);
    if (ret == -1) {
        int err = errno;
        log_fuse_err("CHOWN", path, err);
        VFS_RETURN(-err);
    }
    VFS_RETURN(0);
}

static int vfs_truncate(const char *path, off_t size, struct fuse_file_info *fi) {
    (void)fi; VFS_SETUP_CORE(path, -EACCES);
    if (ctx->uid != 0 && rr.ro) {
        log_fuse_err("TRUNCATE_RO_DENIED", path, EROFS);
        VFS_RETURN(-EROFS);
    }
    /* 后端分派：truncate 由模块方法截断 */
    const NspModuleOps* bops = NULL;
    if (rr.is_ftp && module_backend_lookup(sub_path, &bops) == 0 && bops->backend_truncate) {
        int brc = bops->backend_truncate(sub_path, size);
        module_backend_put(bops);
        if (brc != 0) VFS_RETURN(brc < 0 ? brc : -EIO);
        VFS_RETURN(0);
    }
    int ret = truncate(p, size);
    if (ret == -1) {
        int err = errno;
        log_fuse_err("TRUNCATE", path, err);
        VFS_RETURN(-err);
    }
    VFS_RETURN(0);
}

static int vfs_utimens(const char *path, const struct timespec ts[2], struct fuse_file_info *fi) {
    (void)fi; VFS_SETUP_CORE(path, -EACCES);
    if (ctx->uid != 0 && rr.ro) {
        log_fuse_err("UTIMENS_RO_DENIED", path, EROFS);
        VFS_RETURN(-EROFS);
    }
    int ret = utimensat(AT_FDCWD, p, ts, AT_SYMLINK_NOFOLLOW);
    if (ret == -1) {
        int err = errno;
        log_fuse_err("UTIMENS", path, err);
        VFS_RETURN(-err);
    }
    VFS_RETURN(0);
}

static int vfs_statfs(const char *path, struct statvfs *st) {
    (void)path;
    int ret = statvfs(STORAGE_BASE, st);
    if (ret == -1) return -errno;
    return 0;
}

static int vfs_getxattr(const char *path, const char *name, char *value, size_t size) {
    VFS_SETUP_CORE(path, -ENOENT);
    ssize_t res = lgetxattr(p, name, value, size);
    if (res == -1) {
        if (errno == ENODATA || errno == EOPNOTSUPP) {
#ifdef TARGET_ANDROID
            if (strcmp(name, "security.selinux") == 0) {
                const char* default_ctx = "u:object_r:media_rw_data_file:s0";
                size_t len = strlen(default_ctx) + 1;
                if (size == 0) { VFS_RETURN((int)len); }
                if (size < len) { VFS_RETURN(-ERANGE); }
                strcpy(value, default_ctx);
                VFS_RETURN((int)len);
            }
#endif
            VFS_RETURN(-errno);
        }
        int err = errno;
        log_fuse_err("GETXATTR", path, err);
        VFS_RETURN(-err);
    }
    VFS_RETURN((int)res);
}

static int vfs_listxattr(const char *path, char *list, size_t size) {
    VFS_SETUP_CORE(path, -ENOENT);
    ssize_t res = llistxattr(p, list, size);
    if (res == -1) {
        int err = errno;
        log_fuse_err("LISTXATTR", path, err);
        VFS_RETURN(-err);
    }
    VFS_RETURN((int)res);
}

static int vfs_setxattr(const char *path, const char *name, const char *value, size_t size, int flags) {
    VFS_SETUP_CORE(path, -ENOENT);
    if (ctx->uid != 0 && rr.ro) {
        log_fuse_err("SETXATTR_RO_DENIED", path, EROFS);
        VFS_RETURN(-EROFS);
    }
    int ret = lsetxattr(p, name, value, size, flags);
    if (ret == -1) {
        int err = errno;
        log_fuse_err("SETXATTR", path, err);
        VFS_RETURN(-err);
    }
    VFS_RETURN(0);
}

static int vfs_removexattr(const char *path, const char *name) {
    VFS_SETUP_CORE(path, -ENOENT);
    if (ctx->uid != 0 && rr.ro) {
        log_fuse_err("REMOVEXATTR_RO_DENIED", path, EROFS);
        VFS_RETURN(-EROFS);
    }
    int ret = lremovexattr(p, name);
    if (ret == -1) {
        int err = errno;
        log_fuse_err("REMOVEXATTR", path, err);
        VFS_RETURN(-err);
    }
    VFS_RETURN(0);
}

static void vfs_destroy(void *private_data) {
    (void)private_data; LOG_DBG("FUSE 守护进程正在退出，清理资源...");
    log_close();
    if (g_global_root_fd >= 0) close(g_global_root_fd);
#ifdef TARGET_ANDROID
    if (g_bpf_fd >= 0) close(g_bpf_fd);
#endif
    char msg[256]; snprintf(msg, sizeof(msg), "FUSE_EXIT %d", getpid()); send_ipc_message(msg);
}

static void* vfs_init(struct fuse_conn_info *conn, struct fuse_config *cfg) {
    cfg->use_ino = 1; cfg->entry_timeout = 1.0; cfg->attr_timeout = 1.0; cfg->negative_timeout = 0.5;
    signal(SIGPIPE, SIG_IGN);
    g_passthrough_enabled = false;
    
#ifdef TARGET_ANDROID
    if (g_passthrough_disabled) {
        LOG("FUSE Passthrough: 已被 --no-passthrough 参数禁用");
        goto skip_passthrough;
    }
    
    if (conn->capable & FUSE_CAP_PASSTHROUGH)
        LOG_DBG("FUSE Passthrough: 内核能力标志包含passthrough (capable=0x%x)", conn->capable);
    else
        LOG_DBG("FUSE Passthrough: 内核能力标志未包含passthrough, 尝试直接ioctl探测");
        
    int backing_id = -1;
    int saved_errno = 0;
    bool ioctl_exists = false;  
    int test_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (test_fd < 0) {
        LOG_ERR("FUSE Passthrough: ❌ 无法打开/dev/null测试fd: %s", strerror(errno));
        goto ioctl_probe_done;
    }
    
    backing_id = (int)ioctl(conn->fd, FUSE_DEV_IOC_PASSTHROUGH_OPEN_V2, &test_fd);
    if (backing_id > 0) {
        ioctl_exists = true;
    } else {
        saved_errno = errno;
        if (saved_errno == EPERM) {
            ioctl_exists = true;
        } else if (saved_errno == ENOTTY) {
            struct fuse_passthrough_out_v0 out = { .fd = (uint32_t)test_fd, .len = 0, .vec = NULL };
            errno = 0;
            backing_id = (int)ioctl(conn->fd, FUSE_DEV_IOC_PASSTHROUGH_OPEN_V1, &out);
            if (backing_id > 0) {
                ioctl_exists = true;
            } else {
                saved_errno = errno;
                if (saved_errno == EPERM) {
                    ioctl_exists = true;
                } else if (saved_errno == ENOTTY) {
                    errno = 0;
                    backing_id = (int)ioctl(conn->fd, FUSE_DEV_IOC_PASSTHROUGH_OPEN_V0, &out);
                    if (backing_id > 0) {
                        ioctl_exists = true;
                    } else {
                        saved_errno = errno;
                        if (saved_errno == EPERM) {
                            ioctl_exists = true;
                        }
                    }
                }
            }
        }
    }
    
    if (ioctl_exists) {
        g_passthrough_enabled = true;
        if (backing_id > 0) {
            LOG("FUSE Passthrough: ✅ 协商成功! backing_id=%d, 文件I/O将走直通加速", backing_id);
            int close_ret = ioctl(conn->fd, FUSE_DEV_IOC_BACKING_CLOSE, &backing_id);
            if (close_ret < 0)
                LOG_DBG("FUSE Passthrough: 关闭测试backing_id=%d: %s", backing_id, strerror(errno));
        } else {
            LOG_DBG("FUSE Passthrough: ioctl 已确认, 通过INIT请求启用...");
        }
        conn->want |= FUSE_CAP_PASSTHROUGH;
        LOG_DBG("FUSE Passthrough: ✅ 检测到内核支持, 已请求启用 (want=0x%x)", conn->want);
    } else {
        int err = saved_errno;
        switch (err) {
        case ENOTTY:
            LOG_ERR("FUSE Passthrough: ❌ 内核FUSE模块不支持任何已知的PASSTHROUGH ioctl");
            break;
        case EPERM:
            LOG_ERR("FUSE Passthrough: ❌ 缺少运行所需权限 (EPERM)");
            break;
        default:
            LOG_ERR("FUSE Passthrough: ❌ 协商失败 errno=%d (%s)", err, strerror(err));
            break;
        }
    }
    close(test_fd);

ioctl_probe_done:
skip_passthrough:
#else
    LOG("主线FUSE: passthrough 不可用，走标准用户态路径");
#endif
    if (g_passthrough_enabled) {
        LOG("FUSE Passthrough: 🟢 启用成功");
    } else {
        LOG_WRN("FUSE Passthrough: 所有文件I/O将走标准FUSE用户态路径 (性能较低)");
    }
    char msg[512]; snprintf(msg, 511, "FUSE_ALIVE Global %d", getpid()); send_ipc_message(msg);
    if (g_ready_fd >= 0) { write(g_ready_fd, "1", 1); close(g_ready_fd); g_ready_fd = -1; }
    return nullptr;
}

#ifdef TARGET_ANDROID
static bool is_fuse_bpf_supported(void) {
    FILE *fp = fopen("/sys/fs/fuse/features/fuse_bpf", "r");
    if (!fp) { LOG_DBG("FUSE BPF: 特性文件不可读"); return false; }
    char line[64]; bool ok = false;
    if (fgets(line, sizeof(line), fp)) {
        size_t len = strlen(line);
        if (len && line[len-1] == '\n') line[--len] = '\0';
        ok = (strcmp(line, "supported") == 0);
    }
    fclose(fp);
    LOG_DBG("FUSE BPF: %s -> %s", "/sys/fs/fuse/features/fuse_bpf",
        ok ? "supported" : "not supported");
    return ok;
}

#ifndef __NR_bpf
#if defined(__aarch64__)
#define __NR_bpf 280
#else
#define __NR_bpf 321  
#endif
#endif
#include <linux/bpf.h>

static int open_bpf_prog(void) {
    static const char *bpf_paths[] = {
        "/sys/fs/bpf/prog_fuseMedia_fuse_media",
        "/sys/fs/bpf/prog_fuse_media",
        NULL
    };
    for (int i = 0; bpf_paths[i]; i++) {
        union bpf_attr attr = {};
        attr.pathname = (uint64_t)(uintptr_t)bpf_paths[i];
        attr.bpf_fd = 0;
        int fd = (int)syscall(__NR_bpf, BPF_OBJ_GET, &attr, sizeof(attr));
        if (fd >= 0) {
            LOG_DBG("FUSE BPF: 已获取程序 %s (fd=%d)", bpf_paths[i], fd);
            return fd;
        }
        LOG_DBG("FUSE BPF: %s: %s", bpf_paths[i], strerror(errno));
    }
    LOG_WRN("FUSE BPF: 无法获取 BPF 程序, 将以标准 FUSE 模式运行");
    return -1;
}
#endif

#ifdef TARGET_ANDROID
static int vfs_bpf_setup(const char *path, struct fuse_entry_param *e) {
    if (g_bpf_fd < 0) return -ENOSYS;
    if (!path || !e) return -EINVAL;

    char real[PATH_MAX];

    if (!g_is_media_fuse) {
        const char *suffix;
        if ((suffix = strstr(path, "/Android/data")) == NULL &&
            (suffix = strstr(path, "/Android/obb")) == NULL)
            return -ENOENT;
    }

    snprintf(real, sizeof(real), "%s%s", g_real_root, path);
    if (!S_ISDIR(e->attr.st_mode))
        return -ENOTDIR;

    int bfd = open(real, O_CLOEXEC | O_DIRECTORY | O_RDONLY);
    if (bfd < 0) {
        LOG_DBG("FUSE BPF: open(%s) = %s", real, strerror(errno));
        return -errno;
    }

    e->backing_action = FUSE_ACTION_REPLACE;
    e->backing_fd = (uint64_t)bfd;
    e->bpf_action = FUSE_ACTION_REPLACE;
    e->bpf_fd = (uint64_t)g_bpf_fd;
    LOG_DBG_PERF("FUSE BPF: backing %s (fd=%d, bpf=%d, media=%d)",
            real, bfd, g_bpf_fd, g_is_media_fuse);

    vfs_defer_close(bfd);
    return 0;
}
#endif

static struct fuse_operations vfs_ops = {
    .init = vfs_init, .destroy = vfs_destroy, .getattr = vfs_getattr, .access = vfs_access,
    .readlink = vfs_readlink, .symlink = vfs_symlink, .opendir = vfs_opendir, .readdir = vfs_readdir,
    .open = vfs_open, .create = vfs_create, .read = vfs_read, .write = vfs_write,
    .release = vfs_release, .fsync = vfs_fsync, .flush = vfs_flush,
    .mkdir = vfs_mkdir, .unlink = vfs_unlink, .rmdir = vfs_rmdir,
    .rename = vfs_rename, .chmod = vfs_chmod, .chown = vfs_chown, .truncate = vfs_truncate,
    .utimens = vfs_utimens, .statfs = vfs_statfs, .getxattr = vfs_getxattr, .listxattr = vfs_listxattr,
    .setxattr = vfs_setxattr, .removexattr = vfs_removexattr,
#ifdef TARGET_ANDROID
    .bpf_setup = vfs_bpf_setup,
#endif
};

int main(int argc, char *argv[]) {
    char rules_path[PATH_MAX] = {0};
    char* fuse_argv[argc + 1]; 
    int fuse_argc = 0; 
    if (argc > 0) fuse_argv[fuse_argc++] = argv[0];
    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "--mode=", 7) == 0) {
            if (strcmp(argv[i] + 7, "overlay") == 0) g_mode = MODE_OVERLAY; else g_mode = MODE_REDIRECT;
        } else if (strncmp(argv[i], "--root=", 7) == 0) { 
            strncpy(g_real_root, argv[i] + 7, PATH_MAX - 1);
        } else if (strncmp(argv[i], "--rules=", 8) == 0) { 
            strncpy(rules_path, argv[i] + 8, PATH_MAX - 1);
        } else if (strncmp(argv[i], "--lower=", 8) == 0) { 
            strncpy(g_lower_dir, argv[i] + 8, PATH_MAX - 1);
        } else if (strncmp(argv[i], "--upper=", 8) == 0) { 
            strncpy(g_upper_dir, argv[i] + 8, PATH_MAX - 1);
        } else if (strncmp(argv[i], "--ready-fd=", 11) == 0) { 
            g_ready_fd = atoi(argv[i] + 11);
        } else if (strncmp(argv[i], "--global-root-fd=", 17) == 0) { 
            g_global_root_fd = atoi(argv[i] + 17);
        } else if (strcmp(argv[i], "--preserve-perms") == 0) { 
            g_preserve_perms = true;
        } else if (strcmp(argv[i], "--strip-o-direct") == 0) { 
            g_strip_o_direct = true;
#ifdef TARGET_ANDROID
        } else if (strcmp(argv[i], "--no-bpf") == 0) {
            g_bpf_fd = -2; 
#endif
        } else if (strcmp(argv[i], "--no-passthrough") == 0) {
            g_passthrough_disabled = true;
        } else if (strcmp(argv[i], "--media-fuse") == 0) {
            g_is_media_fuse = true;
        } else if (strncmp(argv[i], "--modules-dir=", 14) == 0) {
            strncpy(g_modules_dir_arg, argv[i] + 14, PATH_MAX - 1);
        } else if (strcmp(argv[i], "--disable-sandbox") == 0) {
            /* 解析并应用禁用沙盒指令 */
            g_disable_sandbox = true;
        } else if (strcmp(argv[i], "debug") == 0 || strcmp(argv[i], "--debug") == 0) { 
            g_min_log_level = LOG_DEBUG; fuse_argv[fuse_argc++] = "-d"; 
        } else if (strcmp(argv[i], "info") == 0) {
            g_min_log_level = LOG_INFO;
        } else if (strcmp(argv[i], "warn") == 0 || strcmp(argv[i], "warning") == 0) {
            g_min_log_level = LOG_WARN;
        } else if (strcmp(argv[i], "error") == 0) {
            g_min_log_level = LOG_ERROR;
        } else { 
            fuse_argv[fuse_argc++] = argv[i]; 
        }
    }
    fuse_argv[fuse_argc] = nullptr; 
    prctl(PR_SET_NAME, "fuse_daemon", 0, 0, 0);
    log_init("fuse_daemon");
    install_crash_handlers();
    /* 热插拔模块系统：扫描模块目录并启动监控线程（规则模块能力在此注册） */
    uint32_t mod_flags = g_disable_sandbox ? NSP_FLAG_DISABLE_SANDBOX : 0;
    module_system_init(rules_path, g_modules_dir_arg[0] ? g_modules_dir_arg : NULL, mod_flags);
    
    if (g_disable_sandbox) {
        LOG("沙盒特性已强制禁用");
    }

#ifdef TARGET_ANDROID
    if (g_bpf_fd != -2) {
        g_bpf_fd = -1;
        if (is_fuse_bpf_supported()) {
            int fd = open_bpf_prog();
            if (fd >= 0) {
                g_bpf_fd = fd;
                LOG("FUSE BPF: 已启用 (bpf_fd=%d)", g_bpf_fd);
            }
        }
    } else {
        LOG("FUSE BPF: 已被 --no-bpf 参数禁用");
        g_bpf_fd = -1;
    }
#endif
    return fuse_main(fuse_argc, fuse_argv, &vfs_ops, nullptr);
}