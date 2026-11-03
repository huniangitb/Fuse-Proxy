#include "nsp_events_status.h"

#include "nsp_constants.h"

#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define NSP_EVENTS_MAX_DAEMONS 8

typedef struct {
    int pid;
    int kind;
} DaemonProc;

/* 读 /proc/<pid>/cmdline 并判定是不是 fuse_daemon（以及是全局还是媒体实例）。
   cmdline 的 NUL 分隔在判空前统一换成空格：--media-fuse 可能落在任一参数位。 */
static bool read_cmdline(int pid, char* buf, size_t cap) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    ssize_t n = read(fd, buf, cap - 1);
    close(fd);
    if (n <= 0) return false;
    buf[n] = '\0';
    for (ssize_t i = 0; i < n; i++)
        if (buf[i] == '\0') buf[i] = ' ';
    return true;
}

/* argv[0] 的 basename 恰好是 fuse_daemon 才算实例。只看整串里有没有这个名字，
   会把命令行里提到它的 shell / grep / 诊断命令都算进来（用户敲 `pidof
   fuse_daemon` 的当下就会多出一个「全局实例」）。 */
NspEventsOwner nsp_events_classify_cmdline(const char* cmd) {
    if (!cmd || *cmd == '\0') return NSP_EVENTS_OWNER_NONE;
    const char* end = cmd;
    while (*end && *end != ' ') end++;
    const char* base = cmd;
    for (const char* p = cmd; p < end; p++)
        if (*p == '/') base = p + 1;
    static const char kName[] = "fuse_daemon";
    size_t len = (size_t)(end - base);
    if (len != sizeof(kName) - 1 || strncmp(base, kName, len) != 0) return NSP_EVENTS_OWNER_NONE;
    return strstr(cmd, "--media-fuse") ? NSP_EVENTS_OWNER_MEDIA : NSP_EVENTS_OWNER_GLOBAL;
}

static int collect_daemons(DaemonProc* out, int max) {
    DIR* d = opendir("/proc");
    if (!d) return 0;
    int n = 0;
    struct dirent* de;
    while ((de = readdir(d)) != nullptr && n < max) {
        if (!isdigit((unsigned char)de->d_name[0])) continue;
        int pid = atoi(de->d_name);
        if (pid <= 0) continue;
        char cmd[512];
        if (!read_cmdline(pid, cmd, sizeof(cmd))) continue;
        NspEventsOwner kind = nsp_events_classify_cmdline(cmd);
        if (kind == NSP_EVENTS_OWNER_NONE) continue;
        out[n].pid = pid;
        out[n].kind = (int)kind;
        n++;
    }
    closedir(d);
    return n;
}

/* 抽象命名空间的 socket 在 /proc/net/unix 里以 @<名字> 出现在 Path 列，Inode 列
   是内核 inode 号；持有该 inode 的进程就是「绑着这个名字的人」。 */
static long unix_socket_inode(const char* name) {
    FILE* fp = fopen("/proc/net/unix", "r");
    if (!fp) return 0;
    char line[512];
    long found = 0;
    while (fgets(line, sizeof(line), fp)) {
        char* save = nullptr;
        char* tok = strtok_r(line, " \t\n", &save);
        int idx = 0;
        long inode = 0;
        bool match = false;
        while (tok) {
            if (idx == 6)
                inode = strtol(tok, nullptr, 10);
            else if (idx == 7 && name && strcmp(tok, name) == 0)
                match = true;
            idx++;
            tok = strtok_r(nullptr, " \t\n", &save);
        }
        if (match && inode > 0) {
            found = inode;
            break;
        }
    }
    fclose(fp);
    return found;
}

static bool fd_scan_for_inode(int pid, long inode) {
    char dir[64];
    snprintf(dir, sizeof(dir), "/proc/%d/fd", pid);
    DIR* d = opendir(dir);
    if (!d) return false;
    int dfd = dirfd(d);
    char want[48];
    snprintf(want, sizeof(want), "socket:[%ld]", inode);
    bool hit = false;
    struct dirent* de;
    while ((de = readdir(d)) != nullptr) {
        if (de->d_name[0] == '.') continue;
        char buf[128];
        ssize_t n = readlinkat(dfd, de->d_name, buf, sizeof(buf) - 1);
        if (n <= 0) continue;
        buf[n] = '\0';
        if (strcmp(buf, want) == 0) {
            hit = true;
            break;
        }
    }
    closedir(d);
    return hit;
}

/* 先只扫候选实例（快），未命中时再扫全表——名字被别的进程占着时也要能点名，
   否则「通道哑了」只能看到「没人绑」。 */
static int resolve_owner(long inode, const DaemonProc* procs, int n, bool full_scan, int* kind) {
    *kind = NSP_EVENTS_OWNER_NONE;
    if (inode <= 0) return 0;
    for (int i = 0; i < n; i++) {
        if (fd_scan_for_inode(procs[i].pid, inode)) {
            *kind = procs[i].kind;
            return procs[i].pid;
        }
    }
    if (!full_scan) return 0;
    DIR* d = opendir("/proc");
    if (!d) return 0;
    int owner = 0;
    struct dirent* de;
    while ((de = readdir(d)) != nullptr) {
        if (!isdigit((unsigned char)de->d_name[0])) continue;
        int pid = atoi(de->d_name);
        if (pid <= 0) continue;
        bool is_daemon = false;
        for (int i = 0; i < n; i++)
            if (procs[i].pid == pid) {
                is_daemon = true;
                break;
            }
        if (is_daemon) continue;
        if (fd_scan_for_inode(pid, inode)) {
            owner = pid;
            *kind = NSP_EVENTS_OWNER_FOREIGN;
            break;
        }
    }
    closedir(d);
    return owner;
}

static void read_last_failure(NspEventsStatus* st, const char* log_dir) {
    char path[128];
    snprintf(path, sizeof(path), "%s/events_socket.status",
             (log_dir && *log_dir) ? log_dir : NSP_LOG_DIR);
    snprintf(st->last_fail_path, sizeof(st->last_fail_path), "%s", path);
    FILE* fp = fopen(path, "r");
    if (!fp) return;
    st->last_fail_present = true;
    if (fgets(st->last_fail, sizeof(st->last_fail), fp)) {
        size_t len = strlen(st->last_fail);
        while (len > 0 && (st->last_fail[len - 1] == '\n' || st->last_fail[len - 1] == '\r'))
            st->last_fail[--len] = '\0';
    }
    fclose(fp);
}

void nsp_events_status_collect(NspEventsStatus* st, bool enabled, const char* log_dir) {
    if (!st) return;
    memset(st, 0, sizeof(*st));
    st->enabled = enabled;
    read_last_failure(st, log_dir);
    if (!enabled) return;

    DaemonProc procs[NSP_EVENTS_MAX_DAEMONS];
    int n = collect_daemons(procs, NSP_EVENTS_MAX_DAEMONS);
    st->daemon_count = n;
    for (int i = 0; i < n; i++) {
        if (procs[i].kind == NSP_EVENTS_OWNER_MEDIA)
            st->media_daemons++;
        else
            st->global_daemons++;
    }
    st->events_inode = unix_socket_inode("@" NSP_EVENTS_SOCK_NAME);
    st->query_inode = unix_socket_inode("@" NSP_EVENTS_QUERY_SOCK_NAME);
    st->events_owner_pid =
        resolve_owner(st->events_inode, procs, n, true, &st->events_owner);
    st->query_owner_pid = resolve_owner(st->query_inode, procs, n, false, &st->query_owner);
}

const char* nsp_events_state(const NspEventsStatus* st) {
    if (!st) return "unknown";
    if (!st->enabled) return "disabled";
    if (st->events_inode <= 0) return "missing";
    if (st->events_owner_pid <= 0) return "unknown-owner";
    if (st->events_owner == NSP_EVENTS_OWNER_GLOBAL) return "ok";
    if (st->events_owner == NSP_EVENTS_OWNER_MEDIA) return "media-owner";
    return "foreign";
}

const char* nsp_events_hint(const NspEventsStatus* st) {
    const char* state = nsp_events_state(st);
    if (strcmp(state, "disabled") == 0) return "事件通道未启用（[GLOBAL] FUSE_EVENTS 默认 OFF）";
    if (strcmp(state, "ok") == 0) return "";
    if (strcmp(state, "missing") == 0)
        return "没有进程绑着 nsp_fs_events：看 events_socket.status，或 log_ctl search-sys 事件 socket 绑定";
    if (strcmp(state, "media-owner") == 0)
        return "媒体实例占着事件通道，应用侧事件会全部丢失：重启模块，让全局实例独占";
    if (strcmp(state, "unknown-owner") == 0)
        return "名字已绑但持有者不可见（需要 root 才能读 /proc/<pid>/fd）";
    if (strcmp(state, "foreign") == 0) return "nsp_fs_events 被非 fuse_daemon 进程占用";
    return "";
}