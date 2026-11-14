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
 *   - media_refresh：**主动**要求对端补一次媒体扫描（reason=redirect_write 由
 *     落点被改写的写操作触发；reason=ftp_upload 由 FTP 后端写收尾触发）。与 write_done
 *     的区别是语义：write_done 说「有人写了」，media_refresh 说「这个落点现在
 *     需要立刻进媒体库」，后者带 kind（image/audio/video）供对端排优先级。
 *     spath 是落点对应的存储视图路径（喂扫描的唯一正确路径域）。
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
    FW_EV_MEDIA_REFRESH,
} FwEventKind;

/* media_refresh 的媒体类别（按落点扩展名判定）。对端只按它排优先级，不做其它
   推断：分类错误最多让一次扫描晚一点，不会让扫错路径。 */
typedef enum {
    FW_MEDIA_NONE = 0,
    FW_MEDIA_IMAGE = 1,
    FW_MEDIA_AUDIO = 2,
    FW_MEDIA_VIDEO = 3,
} FwMediaKind;

/* media_refresh 的触发来源（对应契约的 reason 字段） */
typedef enum {
    FW_REFRESH_NONE = 0,
    FW_REFRESH_REDIRECT_WRITE = 1, /* 写经 REDIRECT/沙盒改写到落点后触发 */
    FW_REFRESH_FTP_UPLOAD = 2,     /* 后端（FTP）上传完成，本地无对应写事件 */
} FwRefreshReason;

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

/* 扩展名 → 媒体类别（FW_MEDIA_NONE = 非媒体）。发布侧按它决定一条刷新请求发不发，
   后端落点物化按它决定要不要在本地留一份副本（见 fw_ingest.h）：两处必须同一份表。 */
uint8_t fw_media_kind_of(const char* path);

/* FUSE 视角路径 → 真实落盘路径：只经 fw_rules_resolve（决策单点），解析不出
   用户层时退回默认存储路径。事件的 rpath 与后端落点物化都用它，两处必须是
   同一个答案——副本落在事件没说的目录里，扫描侧就永远看不到它。 */
void fw_resolve_real(uid_t uid, pid_t pid, const char* fuse_path, char* out, size_t sz);

/* 埋点：主动要求对端补一次媒体扫描。fuse_path 为落点对应的 FUSE 视角路径
   （"/<user>/<sub>"），reason 取 FwRefreshReason。媒体类别由扩展名判定，非媒体
   文件整条不发。内部再判一次通道开关与订阅者，因此调用方可以直接调用——与
   fw_events_note_write_done 同一套热路径约束（有界队列，绝不阻塞调用方）。 */
void fw_events_note_media_refresh(uid_t uid, pid_t pid, const char* fuse_path, uint8_t reason);

/* 启动/停止通道。start 读 [GLOBAL] FUSE_EVENTS（默认 OFF，直接返回 0 且
   不创建任何线程/socket/内存）；必须在 fuse_daemonize 之后调用（fork 不保留
   线程）。stop 幂等，在 module_system_shutdown 之前调用。 */
int fw_events_start(void);
void fw_events_stop(void);

/* 测试钩子：覆盖内部单调时钟（毫秒），用于确定性地断言合并窗口与 exists
   TTL。传 -1 恢复真实时钟。仅 GNU 测试使用，生产代码永不调用。 */
void fw_events_set_test_now_ms(int64_t ms);

#endif /* FW_EVENTS_H */
