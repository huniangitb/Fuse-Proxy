#ifndef FW_EVENTS_H
#define FW_EVENTS_H
/*
 * fw_events.h — FUSE 事件通道（跨项目接口 P1 的生产侧，默认 OFF）
 *
 * 契约见 Media-Provider-Manager 的 FUSE-EVENTS.md（v5 冻结）。我们只做**生产
 * 侧**，不做消费侧：本模块负责把「存储视图里发生过什么」广播给订阅者，并按
 * 需回答「这个绝对路径此刻对某个 uid 是什么状态」。
 *
 * 两条抽象命名空间 UDS（服务端 = fuse_daemon）：
 *   接口 A nsp_fs_events  SOCK_DGRAM   订阅 + NDJSON 事件推送（≤1KB/帧）
 *   接口 B nsp_fs_query   SOCK_SEQPACKET 一次性查询（请求/响应各一帧）
 *
 * 三条硬承诺（实现见 fw_events.c 顶部注释）：
 *   1. 开关 [GLOBAL] FUSE_EVENTS（默认 OFF）：关闭时**零线程、零 socket、零
 *      内存**，埋点处只有一次 relaxed atomic 读（fw_events_active 内联）。
 *   2. IO 路径绝不阻塞：埋点只做一次 memcpy 进有界环形队列（4096，满丢最旧
 *      并计 dropped），排空、合并、路径解析、socket 发送全在独立线程。
 *   3. 判定复用单点：QUERY 的规则决策走 fw_rules_resolve、访问控制走
 *      fw_acl_check——本模块只读它们的声明结果，不另写 hidden/ro 判定。
 *
 * 埋点语义（谁调、何时调）：
 *   - write_done：vfs_write 落盘成功（op=close_write）、vfs_create/vfs_mkdir
 *     成功（op=create/mkdir）、vfs_rename 成功（op=rename，带 src_vpath/
 *     src_spath）、写句柄 release（op=close_write）。200ms 内同路径合并。
 *   - write_denied：fw_route 因 RO/HIDE/ACL 语义返回负 errno（带 errno 与
 *     spath）。只在变更操作上发布——读被拒不是「写没落盘」，扫描侧不关心。
 */
#include "fw_acl.h"
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

/* 事件 op（对应契约的 op 字段） */
typedef enum {
    FW_EV_OP_CREATE = 0,
    FW_EV_OP_MKDIR,
    FW_EV_OP_RENAME,
    FW_EV_OP_CLOSE_WRITE,
} FwEventOp;

/* 事件种类（对应契约的 type 字段） */
typedef enum {
    FW_EV_WRITE_DONE = 0,
    FW_EV_WRITE_DENIED,
    FW_EV_PING,
} FwEventKind;

/* 「通道活着且至少有一个订阅者」标志：埋点热路径只读它一次。
   关闭 / 无订阅者时为 false，埋点立即返回（无锁、无系统调用、无分配）。 */
extern _Atomic bool g_fw_events_hot;

static inline bool fw_events_active(void) {
    return atomic_load_explicit(&g_fw_events_hot, memory_order_relaxed);
}

/* 埋点：写入落盘成功。fuse_path 为 FUSE 视角路径（"/<user>/<sub>"），
   src_fuse 仅 rename 用（源路径，其余传 NULL）。
   内部再判一次 fw_events_active()，因此调用方可以直接调用。 */
void fw_events_note_write_done(uid_t uid, pid_t pid, const char* fuse_path, FwEventOp op,
                               const char* src_fuse);

/* 埋点：变更操作被拒。acl_op 决定 op 字段（CREATE→create、MKDIR→mkdir、
   RENAME_*→rename；其余操作不发布——契约只定义这四个 op）。
   err 为 fw_route 返回的负 errno（正数入参按原样取绝对值）。 */
void fw_events_note_write_denied(uid_t uid, pid_t pid, const char* fuse_path, NspAclOp acl_op,
                                 int err);

/* 启动/停止通道。start 读 [GLOBAL] FUSE_EVENTS（默认 OFF，直接返回 0 且
   不创建任何线程/socket/内存）；必须在 fuse_daemonize 之后调用（fork 不保留
   线程）。stop 幂等，在 module_system_shutdown 之前调用。 */
int fw_events_start(void);
void fw_events_stop(void);

/* 测试钩子：覆盖内部单调时钟（毫秒），用于确定性地断言合并窗口与 exists
   TTL。传 -1 恢复真实时钟。仅 GNU 测试使用，生产代码永不调用。 */
void fw_events_set_test_now_ms(int64_t ms);

#endif /* FW_EVENTS_H */
