#ifndef VFS_CORE_H
#define VFS_CORE_H

#include "common.h"
#include "config_parser.h"
#include <fuse3/fuse.h>

#define HASH_BUCKETS 1024
typedef struct HashNode { char* name; struct HashNode* next; } HashNode;
typedef struct { HashNode* buckets[HASH_BUCKETS]; } DirHashTable;

extern bool g_passthrough_enabled;
extern bool g_preserve_perms;
extern char g_rules_path[PATH_MAX];

void vfs_core_init(const char* rules_path);
AppConfig* vfs_get_app_cfg(uid_t uid, pid_t tid, char* current_pkg_out);

int vfs_sanitize_and_check_hidden(AppConfig* cfg, const char* path, int* path_user_id_out, char* sub_path_out, size_t sub_path_size, const char* current_pkg, uid_t uid);
int vfs_to_real_path(AppConfig* cfg, const char* sub_path, char* out_buf, size_t size, int user_id, bool* is_redir_out, const char* current_pkg);

bool vfs_is_virtual_ancestor(AppConfig* cfg, const char* sub_path);
bool vfs_is_redirect_target(AppConfig* cfg, const char* sub_path);
bool vfs_is_path_ro(AppConfig* cfg, const char* sub_path);
bool vfs_is_virtual_dir_empty(AppConfig* cfg, const char* sub_path, const char* real_path, const char* current_pkg);
bool vfs_is_other_app_pkg(const char* sub_path, const char* current_pkg);

void vfs_log_io(AppConfig* cfg, const char* pkg, uid_t uid, const char* op, const char* sub_path, const char* real_path, bool is_redir);
void vfs_log_io_err(const char* pkg, const char* op, const char* sub_path, const char* fmt, ...);

void vfs_hash_init(DirHashTable* ht);
bool vfs_hash_insert(DirHashTable* ht, const char* name);
void vfs_hash_free(DirHashTable* ht);

bool vfs_get_virtual_child(const char* parent, const char* desc, char* name);
void vfs_fill_virtual_dirs(AppConfig* cfg, const char* sub_path, int path_user_id, void* buf, fuse_fill_dir_t filler, uid_t uid, gid_t gid, DirHashTable* ht, bool is_root);

#endif