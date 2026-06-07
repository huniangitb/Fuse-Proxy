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
#include <time.h>
#include <stdarg.h>
#include "common.h"
#include "ns_utils.h"
#include "fast_search.h"

struct DebugMountArgs {
    const char* pkg;
    int pid;
    const char* stage;
};

/* 安全异步信号日志输出，直接追加写入 error.log，确保路径可见 */
static void log_ns_error(const char* format, ...) {
    int fd = open(ERROR_LOG_PATH, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0666);
    if (fd >= 0) {
        char buf[512];
        va_list args;
        va_start(args, format);
        int len = vsnprintf(buf, sizeof(buf), format, args);
        va_end(args);
        if (len > 0) {
            write(fd, buf, len);
        }
        close(fd);
    }
}

static int run_in_mnt_ns_timeout(int target_pid, int (*func)(void*), void* args, int* child_err, int timeout_ms) {
    struct timespec t_start;
    clock_gettime(CLOCK_MONOTONIC, &t_start);

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
    struct timespec start, now;
    clock_gettime(CLOCK_MONOTONIC, &start);
    int timeout_us = timeout_ms * 1000;
    while (1) {
        pid_t ret = waitpid(child, &status, WNOHANG);
        if (ret == child) {
            clock_gettime(CLOCK_MONOTONIC, &now);
            long elapsed = (now.tv_sec - t_start.tv_sec) * 1000 +
                           (now.tv_nsec - t_start.tv_nsec) / 1000000;
            if (WIFEXITED(status)) {
                int code = WEXITSTATUS(status);
                if (code != 0)
                    LOG("ns操作 pid=%d 耗时: %ldms, 失败码: %d", target_pid, elapsed, code);
                else if (elapsed > 50)
                    LOG("ns操作 pid=%d 耗时: %ldms", target_pid, elapsed);
                if (code == 0) return 0;
                if (child_err) *child_err = code;
                return -1;
            }
            if (elapsed > 50)
                LOG("ns操作 pid=%d 耗时: %ldms, 非正常退出", target_pid, elapsed);
            return -1;
        }
        if (ret == -1 && errno != EINTR) return -1;

        clock_gettime(CLOCK_MONOTONIC, &now);
        long elapsed_us = (now.tv_sec - start.tv_sec) * 1000000 + (now.tv_nsec - start.tv_nsec) / 1000;
        if (elapsed_us >= timeout_us) {
            kill(child, SIGKILL);
            for (int w = 0; w < 10; w++) {
                if (waitpid(child, NULL, WNOHANG) == child) {
                    break;
                }
                usleep(5000);
            }
            if (child_err) *child_err = ETIMEDOUT;
            errno = ETIMEDOUT;
            clock_gettime(CLOCK_MONOTONIC, &now);
            LOG("ns操作 pid=%d 超时(%dms), 总耗时: %ldms", target_pid, timeout_ms,
                (now.tv_sec - t_start.tv_sec) * 1000 + (now.tv_nsec - t_start.tv_nsec) / 1000000);
            return -1;
        }
        usleep(5000);
    }
}

static int run_in_mnt_ns(int target_pid, int (*func)(void*), void* args, int* child_err) {
    return run_in_mnt_ns_timeout(target_pid, func, args, child_err, 500);
}

struct MountArgs { const char *src; const char *target; };

static int do_bind_mount(void* raw_args) {
    struct MountArgs* args = (struct MountArgs*)raw_args;
    if (access(args->src, F_OK) != 0) return errno;
    struct stat st;
    if (stat(args->target, &st) != 0) mkdir(args->target, 0755);

    if (mount(args->src, args->target, nullptr, MS_BIND | MS_REC, nullptr) != 0)
        return errno;
    return 0;
}

static int do_umount_recursive(void* raw_args) {
    const char* target = (const char*)raw_args;
    size_t tlen = strlen(target);

    FILE* fp = fopen("/proc/self/mountinfo", "re");
    if (fp) {
        char mounts[128][PATH_MAX];
        int count = 0;
        char line[4096];
        while (fgets(line, sizeof(line), fp) && count < 128) {
            char mp[PATH_MAX] = {0};
            if (sscanf(line, "%*d %*d %*d:%*d %*s %4095s", mp) != 1) continue;
            if (strcmp(mp, target) == 0) continue;
            if (strncmp(mp, target, tlen) == 0 &&
                (mp[tlen] == '/' || mp[tlen] == '\0')) {
                strncpy(mounts[count], mp, PATH_MAX - 1);
                count++;
            }
        }
        fclose(fp);
        for (int i = count - 1; i >= 0; i--)
            for (int t = 0; t < 8; t++)
                if (umount2(mounts[i], MNT_DETACH) == 0) break;
    }

    for (int t = 0; t < 8; t++)
        if (umount2(target, MNT_DETACH) == 0) break;
    return 0;
}

static int do_umount_and_rmdir(void* raw_args) {
    const char* target = (const char*)raw_args;
    size_t tlen = strlen(target);
    FILE* fp = fopen("/proc/self/mountinfo", "re");
    if (fp) {
        char mounts[64][PATH_MAX];
        int count = 0;
        char line[4096];
        while (fgets(line, sizeof(line), fp) && count < 64) {
            char mp[PATH_MAX] = {0};
            if (sscanf(line, "%*d %*d %*d:%*d %*s %4095s", mp) != 1) continue;
            if (strcmp(mp, target) == 0) continue;
            if (strncmp(mp, target, tlen) == 0 && mp[tlen] == '/') {
                strncpy(mounts[count], mp, PATH_MAX - 1);
                count++;
            }
        }
        fclose(fp);
        for (int i = count - 1; i >= 0; i--)
            for (int t = 0; t < 8; t++)
                if (umount2(mounts[i], MNT_DETACH) == 0) break;
    }
    for (int t = 0; t < 8; t++) {
        if (umount2(target, MNT_DETACH) == 0) break;
    }
    rmdir(target);
    return 0;
}

static int do_make_shared(void* raw_args) {
    const char* target = (const char*)raw_args;
    if (mount(nullptr, target, nullptr, MS_SHARED, nullptr) != 0) return errno;
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
    if (mount(args->src, args->target, nullptr, MS_MOVE, nullptr) != 0)
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
    return run_in_mnt_ns(pid, do_umount_recursive, (void*)target, nullptr);
}

int ns_umount_and_rmdir(int pid, const char* target) {
    return run_in_mnt_ns(pid, do_umount_and_rmdir, (void*)target, nullptr);
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
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;

    char* buf = malloc(65536);
    if (!buf) { close(fd); return 0; }

    ssize_t nread = 0;
    while (nread < 65535) {
        ssize_t r = read(fd, buf + nread, 65535 - nread);
        if (r < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (r == 0) break;
        nread += r;
    }
    buf[nread] = '\0';
    close(fd);

    int count = 0;
    size_t base_len = strlen(base_path);
    char* line = buf;
    while (line < buf + nread && count < max_count) {
        char* next_line = strchr(line, '\n');
        if (next_line) *next_line = '\0';

        if (fast_strstr(line, base_path) != nullptr) {
            char* p = line;
            int fields_skipped = 0;
            while (fields_skipped < 4 && *p) {
                if (*p == ' ') {
                    fields_skipped++;
                    while (*p == ' ') p++;
                } else {
                    p++;
                }
            }

            if (fields_skipped == 4 && *p) {
                char* mp_start = p;
                while (*p && *p != ' ') p++;
                size_t mp_len = p - mp_start;

                if (mp_len > 0 && mp_len < 256) {
                    char mount_point[256];
                    memcpy(mount_point, mp_start, mp_len);
                    mount_point[mp_len] = '\0';

                    if (strncmp(mount_point, base_path, base_len) == 0 &&
                        (mount_point[base_len] == '/' || mount_point[base_len] == '\0') &&
                        strcmp(mount_point, base_path) != 0) {

                        const char* sep = fast_strstr(p, " - ");
                        if (sep) {
                            char fstype[64] = {0};
                            if (sscanf(sep + 3, "%63s", fstype) == 1) {
                                if (fast_strstr(fstype, "fuse") == nullptr) {
                                    strncpy(mount_points[count], mount_point, 255);
                                    mount_points[count][255] = '\0';
                                    count++;
                                }
                            }
                        }
                    }
                }
            }
        }

        if (!next_line) break;
        line = next_line + 1;
    }

    free(buf);
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

    if (mount(source, target, nullptr, MS_BIND | MS_REC, nullptr) != 0) return errno;

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
        mount(backup_src, mp, nullptr, MS_BIND | MS_REC, nullptr);
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

struct BackupTargetArgs {
    const char* target;
    const char* backup;
};

static int do_backup_and_clear_target(void* raw_args) {
    struct BackupTargetArgs* args = (struct BackupTargetArgs*)raw_args;
    const char* target = args->target;
    const char* backup = args->backup;
    size_t tlen = strlen(target);
    size_t blen = strlen(backup);

    FILE* fp = fopen("/proc/self/mountinfo", "re");
    if (fp) {
        char line[4096], mounts[128][PATH_MAX];
        int count = 0;
        while (fgets(line, sizeof(line), fp) && count < 128) {
            char mp[PATH_MAX] = {0};
            if (sscanf(line, "%*d %*d %*d:%*d %*s %4095s", mp) != 1) continue;
            if (strcmp(mp, backup) == 0) continue;
            if (strncmp(mp, backup, blen) == 0 && (mp[blen] == '/' || mp[blen] == '\0')) {
                strncpy(mounts[count], mp, PATH_MAX - 1);
                count++;
            }
        }
        fclose(fp);
        for (int i = count - 1; i >= 0; i--)
            for (int t = 0; t < 8; t++)
                if (umount2(mounts[i], MNT_DETACH) == 0) break;
    }
    for (int t = 0; t < 8; t++)
        if (umount2(backup, MNT_DETACH) == 0) break;

    if (mount(target, backup, nullptr, MS_BIND | MS_REC, nullptr) != 0)
        return errno;

    fp = fopen("/proc/self/mountinfo", "re");
    if (fp) {
        char line[4096], mounts[128][PATH_MAX];
        int count = 0;
        while (fgets(line, sizeof(line), fp) && count < 128) {
            char mp[PATH_MAX] = {0};
            if (sscanf(line, "%*d %*d %*d:%*d %*s %4095s", mp) != 1) continue;
            if (strcmp(mp, target) == 0) continue;
            if (strncmp(mp, target, tlen) == 0 && (mp[tlen] == '/' || mp[tlen] == '\0')) {
                strncpy(mounts[count], mp, PATH_MAX - 1);
                count++;
            }
        }
        fclose(fp);
        for (int i = count - 1; i >= 0; i--)
            for (int t = 0; t < 8; t++)
                if (umount2(mounts[i], MNT_DETACH) == 0) break;
    }
    for (int t = 0; t < 8; t++)
        if (umount2(target, MNT_DETACH) == 0) break;

    return 0;
}

int ns_backup_and_clear_target(int pid, const char* target, const char* backup) {
    struct BackupTargetArgs bargs = { target, backup };
    int child_err = 0;
    int ret = run_in_mnt_ns(pid, do_backup_and_clear_target, &bargs, &child_err);
    if (ret < 0 && child_err != 0) errno = child_err;
    return ret;
}

struct CombinedMountArgs {
    const char* source;
    const char* target;
    const char* backup;
    char (*preserve_paths)[256];
    int preserve_count;
};

static int do_combined_mount(void* raw_args) {
    struct CombinedMountArgs* args = (struct CombinedMountArgs*)raw_args;
    const char* source = args->source;
    const char* target = args->target;
    const char* backup = args->backup;
    char (*preserve_paths)[256] = args->preserve_paths;
    int preserve_count = args->preserve_count;

    size_t tlen = strlen(target);
    size_t blen = strlen(backup);

    int fd = open("/proc/self/mountinfo", O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        log_ns_error("[ns_error] open /proc/self/mountinfo failed, errno=%d\n", errno);
        return errno;
    }

    char* buf = malloc(65536);
    if (!buf) {
        close(fd);
        log_ns_error("[ns_error] malloc memory failed\n");
        return ENOMEM;
    }

    ssize_t nread = 0;
    while (nread < 65535) {
        ssize_t r = read(fd, buf + nread, 65535 - nread);
        if (r < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (r == 0) break;
        nread += r;
    }
    buf[nread] = '\0';
    close(fd);

    char backup_mounts[128][PATH_MAX];
    int backup_count = 0;
    char target_mounts[128][PATH_MAX];
    int target_count = 0;

    char* line = buf;
    while (line < buf + nread) {
        char* next_line = strchr(line, '\n');
        if (next_line) *next_line = '\0';

        if (fast_strstr(line, backup) != nullptr || fast_strstr(line, target) != nullptr) {
            char* p = line;
            int fields_skipped = 0;
            while (fields_skipped < 4 && *p) {
                if (*p == ' ') {
                    fields_skipped++;
                    while (*p == ' ') p++;
                } else {
                    p++;
                }
            }

            if (fields_skipped == 4 && *p) {
                char* mp_start = p;
                while (*p && *p != ' ') p++;
                size_t mp_len = p - mp_start;

                if (mp_len > 0 && mp_len < PATH_MAX) {
                    char mp[PATH_MAX];
                    memcpy(mp, mp_start, mp_len);
                    mp[mp_len] = '\0';

                    if (strcmp(mp, backup) != 0 && strncmp(mp, backup, blen) == 0 && (mp[blen] == '/' || mp[blen] == '\0')) {
                        if (backup_count < 128) {
                            strcpy(backup_mounts[backup_count++], mp);
                        }
                    }
                    if (strcmp(mp, target) != 0 && strncmp(mp, target, tlen) == 0 && (mp[tlen] == '/' || mp[tlen] == '\0')) {
                        if (target_count < 128) {
                            strcpy(target_mounts[target_count++], mp);
                        }
                    }
                }
            }
        }

        if (!next_line) break;
        line = next_line + 1;
    }
    free(buf);

    /* 1. 递归卸载旧备份挂载点 */
    for (int i = backup_count - 1; i >= 0; i--) {
        for (int t = 0; t < 8; t++) {
            if (umount2(backup_mounts[i], MNT_DETACH) == 0) break;
        }
    }
    for (int t = 0; t < 8; t++) {
        if (umount2(backup, MNT_DETACH) == 0) break;
    }

    // 强健性安全保护：保证备份点物理目录存在，防止后续挂载失败
    if (mkdir(backup, 0755) != 0 && errno != EEXIST) {
        log_ns_error("[ns_error] Combined mount mkdir backup failed: mkdir(%s) errno=%d\n", backup, errno);
    }

    /* 2. 将目标挂载树备份到备份点 */
    if (mount(target, backup, nullptr, MS_BIND | MS_REC, nullptr) != 0) {
        int err = errno;
        log_ns_error("[ns_error] Combined mount backup failed: mount(%s -> %s) errno=%d (%s)\n", target, backup, err, strerror(err));
        return err;
    }

    /* 3. 递归卸载目标路径下的原生子挂载 */
    for (int i = target_count - 1; i >= 0; i--) {
        for (int t = 0; t < 8; t++) {
            if (umount2(target_mounts[i], MNT_DETACH) == 0) break;
        }
    }
    for (int t = 0; t < 8; t++) {
        if (umount2(target, MNT_DETACH) == 0) break;
    }

    // 强健性安全保护：保证物理目标目录存在
    if (mkdir(target, 0755) != 0 && errno != EEXIST) {
        log_ns_error("[ns_error] Combined mount mkdir target failed: mkdir(%s) errno=%d\n", target, errno);
    }

    /* 4. 将全局 FUSE 挂载源 bind 到目标路径 */
    if (mount(source, target, nullptr, MS_BIND | MS_REC, nullptr) != 0) {
        int err = errno;
        log_ns_error("[ns_error] Combined mount FUSE source failed: mount(%s -> %s) errno=%d (%s)\n", source, target, err, strerror(err));
        return err;
    }

    /* 5. 还原需要保留的原生子挂载点 */
    for (int i = 0; i < preserve_count; i++) {
        const char* mp = preserve_paths[i];
        if (mp[0] == '\0') continue;

        const char* rel = mp + tlen;
        while (*rel == '/') rel++;
        char backup_src[PATH_MAX];
        snprintf(backup_src, sizeof(backup_src), "%s/%s", backup, rel);

        mkdir_recursive(mp);
        if (mount(backup_src, mp, nullptr, MS_BIND | MS_REC, nullptr) != 0) {
            int err = errno;
            log_ns_error("[ns_error] Combined mount preserve path failed: mount(%s -> %s) errno=%d (%s)\n", backup_src, mp, err, strerror(err));
        }
    }

    return 0;
}

int ns_combined_mount(int pid, const char* source, const char* target, const char* backup,
                      char preserve_paths[][256], int preserve_count) {
    struct CombinedMountArgs args = { source, target, backup, preserve_paths, preserve_count };
    int child_err = 0;
    int ret = run_in_mnt_ns(pid, do_combined_mount, &args, &child_err);
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
        if (!fast_strstr(line, target_mount)) continue;
        if (match_fs_name && !fast_strstr(line, match_fs_name)) continue;

        if (fast_strstr(line, " - ") && sscanf(line, "%*s %*s %*s %*s %1023s", mount_point) == 1) {
            if (strcmp(mount_point, target_mount) == 0) {
                found = 1;
                break;
            }
        }
    }
    fclose(fp);
    return found;
}

static int do_debug_log_mounts(void* raw_args) {
    struct DebugMountArgs* args = (struct DebugMountArgs*)raw_args;
    mkdir_recursive("/data/Namespace-Proxy/log");
    FILE* log_fp = fopen("/data/Namespace-Proxy/log/mount_debug.log", "ae");
    if (!log_fp) return errno;

    time_t now = time(nullptr);
    struct tm tm_buf;
    localtime_r(&now, &tm_buf);
    char time_buf[64];
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", &tm_buf);

    fprintf(log_fp, "[%s] [PKG: %s] [PID: %d] [STAGE: %s]\n", time_buf, args->pkg, args->pid, args->stage);

    FILE* mounts_fp = fopen("/proc/self/mounts", "re");
    if (mounts_fp) {
        char line[1024];
        bool found = false;
        while (fgets(line, sizeof(line), mounts_fp)) {
            if (fast_strstr(line, "/storage/emulated") != nullptr) {
                fprintf(log_fp, "  %s", line);
                found = true;
            }
        }
        if (!found) {
            fprintf(log_fp, "  (未找到包含 /storage/emulated 的挂载点)\n");
        }
        fclose(mounts_fp);
    } else {
        fprintf(log_fp, "  错误：无法读取 /proc/self/mounts\n");
    }
    fprintf(log_fp, "------------------------------------------------------------\n");
    fflush(log_fp);
    fclose(log_fp);
    return 0;
}

int ns_debug_log_mounts(int pid, const char* pkg, const char* stage) {
    struct DebugMountArgs args = { pkg, pid, stage };
    return run_in_mnt_ns(pid, do_debug_log_mounts, &args, nullptr);
}

struct SysFuseArgs {
    char fuse_src[PATH_MAX];
    char backup_path[PATH_MAX];
};

static int do_backup_and_remove_sys_fuse(void* raw_args) {
    struct SysFuseArgs* args = (struct SysFuseArgs*)raw_args;

    struct stat st;
    if (stat("/storage/emulated", &st) != 0) return -1;

    if (umount2("/storage/emulated", MNT_DETACH) != 0) {
        return -1;
    }

    mkdir_recursive(args->backup_path);
    if (mount("/storage/emulated", args->backup_path, nullptr, MS_BIND | MS_REC, nullptr) != 0) {
        mount(args->fuse_src, "/storage/emulated", nullptr, MS_BIND | MS_REC, nullptr);
        mount(nullptr, "/storage/emulated", nullptr, MS_SHARED, nullptr);
        return -2;
    }

    umount2("/storage/emulated", MNT_DETACH);

    if (mount(args->fuse_src, "/storage/emulated", nullptr, MS_BIND | MS_REC, nullptr) != 0) {
        mount(args->backup_path, "/storage/emulated", nullptr, MS_BIND | MS_REC, nullptr);
        return -2;
    }
    mount(nullptr, "/storage/emulated", nullptr, MS_SHARED, nullptr);

    return 0;
}

static int do_restore_sys_fuse(void* raw_args) {
    struct SysFuseArgs* args = (struct SysFuseArgs*)raw_args;

    if (access(args->backup_path, F_OK) != 0) return -1;

    umount2("/storage/emulated", MNT_DETACH);

    struct stat st;
    if (stat("/storage/emulated", &st) != 0) {
        mount(args->backup_path, "/storage/emulated", nullptr, MS_BIND | MS_REC, nullptr);
        return 0;
    }

    mount(args->backup_path, "/storage/emulated", nullptr, MS_BIND | MS_REC, nullptr);
    return 0;
}

int ns_backup_and_remove_system_fuse(int mnt_ns_pid, const char* fuse_src, const char* backup_path) {
    struct SysFuseArgs args;
    memset(&args, 0, sizeof(args));
    strncpy(args.fuse_src, fuse_src, sizeof(args.fuse_src) - 1);
    strncpy(args.backup_path, backup_path, sizeof(args.backup_path) - 1);

    int child_err = 0;
    int ret = run_in_mnt_ns_timeout(mnt_ns_pid, do_backup_and_remove_sys_fuse, &args, &child_err, 2000);
    if (ret != 0) {
        LOG_ERR("系统 FUSE 备份/卸载失败 (ret=%d, err=%d)", ret, child_err);
    } else {
        LOG("系统 FUSE 已备份至 %s 并卸载", backup_path);
    }
    return ret;
}

int ns_restore_system_fuse(int mnt_ns_pid, const char* fuse_src, const char* backup_path) {
    (void)fuse_src;
    struct SysFuseArgs args;
    memset(&args, 0, sizeof(args));
    strncpy(args.backup_path, backup_path, sizeof(args.backup_path) - 1);

    int ret = run_in_mnt_ns_timeout(mnt_ns_pid, do_restore_sys_fuse, &args, nullptr, 2000);
    if (ret == 0) {
        LOG("系统 FUSE 已从 %s 恢复", backup_path);
    }
    return ret;
}