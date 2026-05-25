#define _GNU_SOURCE
#include <sched.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "common.h"
#include "ns_utils.h"

static int run_in_mnt_ns(int target_pid, int (*func)(void*), void* args, int* child_err) {
    pid_t child = fork();
    if (child < 0) return -1;
    
    if (child == 0) {
        char ns_path[64];
        snprintf(ns_path, sizeof(ns_path), "/proc/%d/ns/mnt", target_pid);
        int fd = open(ns_path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) _exit(10);
        if (setns(fd, CLONE_NEWNS) != 0) { close(fd); _exit(11); }
        close(fd);

        int ret = func(args);
        _exit(ret == 0 ? 0 : (ret > 0 ? ret : 1));
    }

    int status;
    waitpid(child, &status, 0);
    if (WIFEXITED(status)) {
        int code = WEXITSTATUS(status);
        if (code == 0) return 0;
        if (child_err) *child_err = code;
        return -1;
    }
    return -1;
}

struct MountArgs { const char *src; const char *target; };

static int do_bind_mount(void* raw_args) {
    struct MountArgs* args = (struct MountArgs*)raw_args;
    if (access(args->src, F_OK) != 0) return errno;
    struct stat st;
    if (stat(args->target, &st) != 0) mkdir(args->target, 0755);

    if (mount(args->src, args->target, NULL, MS_BIND | MS_REC, NULL) != 0)
        return errno;
    return 0;
}

static int do_umount_recursive(void* raw_args) {
    const char* target = (const char*)raw_args;
    umount2(target, MNT_DETACH);
    return 0;
}

static int do_umount_and_rmdir(void* raw_args) {
    const char* target = (const char*)raw_args;
    umount2(target, MNT_DETACH);
    rmdir(target);
    return 0;
}

static int do_make_shared(void* raw_args) {
    const char* target = (const char*)raw_args;
    if (mount(NULL, target, NULL, MS_SHARED, NULL) != 0) return errno;
    return 0;
}

static int do_move_mount(void* raw_args) {
    struct MountArgs* args = (struct MountArgs*)raw_args;
    char parent[PATH_MAX];
    strncpy(parent, args->target, PATH_MAX - 1);
    parent[PATH_MAX - 1] = '\0';
    char* last = strrchr(parent, '/');
    if (last && last != parent) {
        *last = '\0';
        mkdir(parent, 0755);
    }
    mkdir(args->target, 0755);
    if (mount(args->src, args->target, NULL, MS_MOVE, NULL) != 0)
        return errno;
    return 0;
}

int ns_bind_mount(int pid, const char* source, const char* target) {
    struct MountArgs args = { source, target };
    int child_err = 0;
    int ret = run_in_mnt_ns(pid, do_bind_mount, &args, &child_err);
    if (ret < 0 && child_err != 0) errno = child_err;
    return ret;
}

int ns_umount_recursive(int pid, const char* target) {
    return run_in_mnt_ns(pid, do_umount_recursive, (void*)target, NULL);
}

int ns_umount_and_rmdir(int pid, const char* target) {
    return run_in_mnt_ns(pid, do_umount_and_rmdir, (void*)target, NULL);
}

int ns_move_mount(int pid, const char* source, const char* target) {
    struct MountArgs args = { source, target };
    int child_err = 0;
    int ret = run_in_mnt_ns(pid, do_move_mount, &args, &child_err);
    if (ret < 0 && child_err != 0) errno = child_err;
    return ret;
}

int ns_make_shared(int pid, const char* target) {
    int child_err = 0;
    int ret = run_in_mnt_ns(pid, do_make_shared, (void*)target, &child_err);
    if (ret < 0 && child_err != 0) errno = child_err;
    return ret;
}

int ns_find_native_submounts(int pid, const char* base_path, char mount_points[][256], int max_count) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mountinfo", pid);
    FILE* fp = fopen(path, "re");
    if (!fp) return 0;

    int count = 0;
    char line[4096];
    size_t base_len = strlen(base_path);

    while (fgets(line, sizeof(line), fp) && count < max_count) {
        char mount_point[1024] = {0};
        char fstype[64] = {0};
        char* p = line;
        for (int f = 0; f < 4 && p; f++) {
            p = strchr(p, ' ');
            if (p) while (*p == ' ') p++;
        }
        if (!p) continue;
        char* mp_start = p;
        p = strchr(p, ' ');
        if (!p) continue;
        size_t mp_len = p - mp_start;
        if (mp_len >= sizeof(mount_point)) mp_len = sizeof(mount_point) - 1;
        memcpy(mount_point, mp_start, mp_len);
        mount_point[mp_len] = '\0';

        if (strncmp(mount_point, base_path, base_len) != 0) continue;
        if (mount_point[base_len] != '/' && mount_point[base_len] != '\0') continue;
        if (strcmp(mount_point, base_path) == 0) continue; 

        char* sep = strstr(line, " - ");
        if (!sep) continue;
        if (sscanf(sep + 3, "%63s", fstype) < 1) continue;

        if (strcmp(fstype, "fuse") == 0 || strcmp(fstype, "sdcardfs") == 0) continue;

        strncpy(mount_points[count], mount_point, 255);
        mount_points[count][255] = '\0';
        count++;
    }
    fclose(fp);
    return count;
}

struct PreserveMountArgs {
    const char* source;
    const char* target;
    char (*preserve_paths)[256];
    int preserve_count;
};

static int do_bind_mount_with_preserve(void* raw_args) {
    struct PreserveMountArgs* args = (struct PreserveMountArgs*)raw_args;
    const char* source = args->source;
    const char* target = args->target;
    char (*preserve_paths)[256] = args->preserve_paths;
    int preserve_count = args->preserve_count;

    if (mount(source, target, NULL, MS_BIND | MS_REC, NULL) != 0) return errno;

    char backup_base[PATH_MAX];
    snprintf(backup_base, sizeof(backup_base), BACKUP_DIR "/nsp_sys_storage");
    size_t target_len = strlen(target);

    for (int i = 0; i < preserve_count; i++) {
        const char* mp = preserve_paths[i];
        if (mp[0] == '\0') continue;

        const char* rel = mp + target_len; 
        while (*rel == '/') rel++;
        char backup_src[PATH_MAX];
        snprintf(backup_src, sizeof(backup_src), "%s/%s", backup_base, rel);

        mkdir_recursive(mp);
        mount(backup_src, mp, NULL, MS_BIND | MS_REC, NULL);
    }
    return 0;
}

int ns_bind_mount_with_preserve(int pid, const char* source, const char* target, char preserve_paths[][256], int preserve_count) {
    struct PreserveMountArgs args = { source, target, preserve_paths, preserve_count };
    int child_err = 0;
    int ret = run_in_mnt_ns(pid, do_bind_mount_with_preserve, &args, &child_err);
    if (ret < 0 && child_err != 0) errno = child_err;
    return ret;
}

int ns_is_mounted(int pid, const char* target_mount, const char* match_fs_name) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mountinfo", pid);
    FILE* fp = fopen(path, "re"); 
    if (!fp) return -1;
    int found = 0;
    char line[2048], mount_point[1024];
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, " - ") && sscanf(line, "%*s %*s %*s %*s %1023s", mount_point) == 1) {
            if (strcmp(mount_point, target_mount) == 0) {
                if (!match_fs_name || strstr(line, match_fs_name)) { found = 1; break; }
            }
        }
    }
    fclose(fp);
    return found;
}