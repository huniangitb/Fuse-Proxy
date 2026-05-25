#ifndef INJECT_TARGET_H
#define INJECT_TARGET_H

#include <sys/types.h>

int is_isolated_uid(uid_t uid);
int is_process_safe_to_inject(const char* cmdline);
int is_target_app(const char* cmdline, uid_t uid, pid_t pid, int from_ipc);
uid_t get_app_uid(int pid);
void update_uid_map(uid_t uid, const char* pkg);
void get_target_storage_path(uid_t uid, char* path, size_t size);

void add_tracked(int pid);
int is_tracked(int pid);
void audit_tracked_apps(void);
void force_recover_tracked_mounts(void);
void handle_list_injected(int client_fd);

#endif