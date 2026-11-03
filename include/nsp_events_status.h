#ifndef NSP_EVENTS_STATUS_H
#define NSP_EVENTS_STATUS_H
/*
 * nsp_events_status.h — 事件通道归属的可观测快照
 *
 * nsp_fs_events / nsp_fs_query 是抽象命名空间的 UDS：内核对名字唯一，谁先 bind
 * 谁能收到订阅。两个 fuse_daemon 实例（全局 / 媒体）都曾尝试绑定同一个名字，
 * 归属由启动竞态决定——输的那条实例的应用事件永远发不出去，而外部表现只是
 * 「事件功能时而可用时而全哑」。归属现在固定给全局实例，本模块负责把「此刻究竟
 * 谁绑着」变成可查事实（log_ctl events / log_ctl status）。
 *
 * 判定只看 /proc（进程命令行 + /proc/net/unix + /proc/<pid>/fd），不做任何假设：
 * 名字没人绑、被媒体实例绑、被非本项目进程占，都能区分出来。
 */
#include <stdbool.h>

/* 持有者身份 */
typedef enum {
    NSP_EVENTS_OWNER_NONE = 0, /* 未解析出持有者 */
    NSP_EVENTS_OWNER_GLOBAL,   /* 全局实例（命令行无 --media-fuse） */
    NSP_EVENTS_OWNER_MEDIA,    /* 媒体实例（--media-fuse） */
    NSP_EVENTS_OWNER_FOREIGN,  /* 非 fuse_daemon 进程 */
} NspEventsOwner;

typedef struct {
    bool enabled;          /* [GLOBAL] FUSE_EVENTS */
    int daemon_count;      /* 检出的 fuse_daemon 进程数 */
    int global_daemons;
    int media_daemons;
    long events_inode;     /* @nsp_fs_events 的 socket inode；0=名字没人绑 */
    int events_owner_pid;  /* 持有该 inode 的 pid；0=未解析出 */
    int events_owner;      /* NspEventsOwner */
    long query_inode;      /* @nsp_fs_query */
    int query_owner_pid;
    int query_owner;
    bool last_fail_present; /* log 目录下 events_socket.status 是否存在 */
    char last_fail[192];    /* 该文件首行（已截断、去换行） */
    char last_fail_path[128];
} NspEventsStatus;

/* 纯判定：把 /proc/<pid>/cmdline（NUL 已换成空格）分类成 NONE/GLOBAL/MEDIA。
   只看 argv[0] 的 basename——命令行里顺手提到 fuse_daemon 的 shell（例如
   `sh -c "pidof fuse_daemon"`）不是实例，把这种进程算进去会让计数虚增。
   返回 NONE 表示不是 fuse_daemon 进程。 */
NspEventsOwner nsp_events_classify_cmdline(const char* cmd);

/* 采集快照。enabled=false 时只读状态文件，不扫 /proc（与「开关关闭零开销」一致）。
   log_dir 传 NULL 时用编译期 LOG_DIR。 */
void nsp_events_status_collect(NspEventsStatus* st, bool enabled, const char* log_dir);

/* 纯状态机（单测直接覆盖）：ok / disabled / missing / unknown-owner / media-owner / foreign */
const char* nsp_events_state(const NspEventsStatus* st);
/* 对应的处置提示；ok/disabled 返回空串 */
const char* nsp_events_hint(const NspEventsStatus* st);

#endif /* NSP_EVENTS_STATUS_H */