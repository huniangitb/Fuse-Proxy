#ifndef VFS_CORE_H
#define VFS_CORE_H

#include "common.h"
#include "config_parser.h"
#include "uid_map.h"
#include <fuse3/fuse.h>

#define HASH_BUCKETS 1024

typedef struct HashNode { char* name; struct HashNode* next; } HashNode;
typedef struct { HashNode* buckets[HASH_BUCKETS]; } DirHashTable;

/* 单次操作内对同一 sub_path 的 Trie 查询结果缓存：
   合并 app + global 两棵 Trie 的静态规则命中（hidden/ro/redir），
   避免 sanitize(hidden)/to_real_path(redir)/is_path_ro(ro) 对同一路径重复遍历。
   redir 存 trie_lookup 已拼接好的完整目标串（可能含 '?' 前缀，运行时再展开）。 */
typedef struct {
    bool valid;      /* 是否已 resolve；false 时消费方各自回退计算 */
    bool hidden;     /* app_hidden || global_hidden */
    bool ro;         /* app_ro || global_ro */
    bool has_redir;  /* 命中 redirect（app 优先，无则 global） */
    char redir[PATH_MAX];
} TrieMatch;

/* 对 sub_path 在 app trie 与 global trie 各查一次，合并填充 out。 */
void vfs_trie_resolve(AppConfig* cfg, const char* sub_path, TrieMatch* out);

extern bool g_passthrough_enabled;
extern bool g_preserve_perms;
extern bool g_disable_sandbox;  /* 新增：全局禁用当前 FUSE 实例的沙盒特性 */

extern char g_rules_path[PATH_MAX];
extern UidMapEntry *g_uid_maps;
extern int g_uid_map_count;

void vfs_core_init(const char* rules_path);
AppConfig* vfs_get_app_cfg(uid_t uid, pid_t tid, char* current_pkg_out);
/* tm_out 可选：非 NULL 时在 sub_path 定型后填充 Trie 命中结果，供 to_real_path/is_path_ro 复用；
   NULL 时退化为原行为（各函数内部自查）。 */
int vfs_sanitize_and_check_hidden(AppConfig* cfg, const char* path, int* path_user_id_out, char* sub_path_out, size_t sub_path_size, const char* current_pkg, uid_t uid, TrieMatch* tm_out);
int vfs_to_real_path(AppConfig* cfg, const char* sub_path, char* out_buf, size_t size, int user_id, bool* is_redir_out, const char* current_pkg, const TrieMatch* tm);
bool vfs_is_virtual_ancestor(AppConfig* cfg, const char* sub_path);
bool vfs_is_redirect_target(AppConfig* cfg, const char* sub_path);
bool vfs_is_path_ro(AppConfig* cfg, const char* sub_path, const char* current_pkg, const TrieMatch* tm);
bool vfs_is_virtual_dir_empty(AppConfig* cfg, const char* sub_path, const char* real_path, const char* current_pkg);
bool vfs_is_other_app_pkg(const char* sub_path, const char* current_pkg);

void vfs_log_io(AppConfig* cfg, const char* pkg, uid_t uid, const char* op, const char* sub_path, const char* real_path, bool is_redir);
void vfs_log_io_err(const char* pkg, const char* op, const char* sub_path, const char* fmt, ...);

void vfs_hash_init(DirHashTable* ht);
bool vfs_hash_insert(DirHashTable* ht, const char* name);
void vfs_hash_free(DirHashTable* ht);

/* 核心修复：添加安全长度 max_len 限制声明 */
bool vfs_get_virtual_child(const char* parent, const char* desc, char* name, size_t max_len);
bool vfs_fill_virtual_dirs(AppConfig* cfg, const char* sub_path, int path_user_id, void* buf, fuse_fill_dir_t filler, uid_t uid, gid_t gid, DirHashTable* ht, bool is_root, const char* current_pkg);

/* 为合成目录 stat 生成非零 inode，防止 FUSE 内核模块拒绝 inode=0 返回 EINVAL */
static inline ino_t synthetic_inode(const char *path) {
    if (!path) return 1;
    unsigned long h = 5381;
    int c;
    while ((c = (unsigned char)*path++))
        h = ((h << 5) + h) + c;
    return (ino_t)(h | 1);
}

#endif