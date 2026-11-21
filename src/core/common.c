#include "common.h"
#include "nsp_comm.h"
#include "nsp_util.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <pthread.h>
#include <sys/time.h>
#include <fcntl.h>
#include <unistd.h>
#ifdef TARGET_ANDROID
#include <sys/system_properties.h>
#endif
#include <stdatomic.h>
#ifdef TARGET_ANDROID
#include <sys/xattr.h>
#endif
#define FALLBACK_ERR_LOG ERROR_LOG_PATH

LogLevel g_min_log_level = LOG_INFO;
char g_real_root[PATH_MAX] = {0};
bool g_persist_all_logs = false;
bool g_strip_o_direct = false;
/* 日志合并周期：batch 期间 log_internal 将日志累积到批量缓冲（不逐条写
   环形缓冲），log_batch_end 时把整个周期合并为单条日志写入，前端最终只
   显示一条（多个发送请求并入一个日志）。原子嵌套计数 + 互斥锁保护缓冲 */
static volatile sig_atomic_t g_log_batch_depth = 0; /* >0 = 合并周期中 */
static pthread_mutex_t g_log_batch_mutex = PTHREAD_MUTEX_INITIALIZER;
static char g_log_batch_buf[65536];
static size_t g_log_batch_len = 0;

static char g_self_dir[PATH_MAX] = {0};
static char g_proc_name[64] = "unknown";
static bool g_log_inited = false;
static pthread_mutex_t g_persist_mutex = PTHREAD_MUTEX_INITIALIZER;

/* LOG 通道载荷组帧（与 log_monitor 行协议对齐，旧 log_entry_packet 语义）：
   kind=0 普通：level==LOG_IO → "LOG_IO:%s\n"；LOG_LOGCAT → "LOG_LOGCAT:%s\n"；
     否则 "LOG_SYS:<level>:[proc] <msg>\n"
   kind=1 合并： "LOG_BATCH\n<content>\nLOG_BATCH_END\n"（level 字节忽略） */
#define LOG_KIND_NORMAL 0
#define LOG_KIND_MERGED 1
static int log_frame_packet(uint8_t kind, uint8_t level, const char* msg, char* packet, size_t sz) {
    if (kind == LOG_KIND_MERGED) return snprintf(packet, sz, "LOG_BATCH\n%s\nLOG_BATCH_END\n", msg);
    if (level == LOG_IO) return snprintf(packet, sz, "LOG_IO:%s\n", msg);
    if (level == LOG_LOGCAT) return snprintf(packet, sz, "LOG_LOGCAT:%s\n", msg);
    return snprintf(packet, sz, "LOG_SYS:%d:[%s] %s\n", level, g_proc_name, msg);
}

/* 日志合并周期控制：原子嵌套计数（>0 = 周期中），支持并发/嵌套 begin/end，
   最后一个 end 把累积日志合并为单条写入环形缓冲 */
void log_batch_begin(void) {
    __sync_fetch_and_add(&g_log_batch_depth, 1);
}
void log_batch_end(void) {
    /* __sync_fetch_and_sub 返回旧值：旧值 == 1 说明这是最后一个周期，
       旧值 > 1 说明仍有外层周期（返回，不合并）。
       注意：原子减已把计数归零（旧值 1 → 0），不得再用普通赋值清零，
       否则会 clobber 并发线程的 log_batch_begin */
    if (__sync_fetch_and_sub(&g_log_batch_depth, 1) > 1) return;
    /* 取走累积内容 */
    pthread_mutex_lock(&g_log_batch_mutex);
    size_t n = g_log_batch_len;
    char merged[NSP_LOG_MSG_MAX];
    if (n >= sizeof(merged)) n = sizeof(merged) - 1;
    memcpy(merged, g_log_batch_buf, n);
    merged[n] = '\0';
    g_log_batch_len = 0;
    pthread_mutex_unlock(&g_log_batch_mutex);
    if (n == 0 || !g_log_inited) return;
    /* 合并为单条经 comm 线程发送（kind=MERGED，log_monitor 整块接收合并为
       一条入库，前端只显示一条）。单行输出：[proc] <条目1>\t<条目2>...
       （条目间以制表符连接，不用换行，避免前端按行拆分导致长内容截断/中文乱码） */
    char line[NSP_LOG_MSG_MAX];
    snprintf(line, sizeof(line), "[%s] %s", g_proc_name, merged);
    uint8_t buf[2 + NSP_LOG_MSG_MAX];
    buf[0] = LOG_KIND_MERGED;
    buf[1] = (uint8_t)LOG_DEBUG; /* 合并日志归为 debug 级别，--level>=1 不显示 */
    size_t llen = strlen(line);
    memcpy(buf + 2, line, llen + 1);
    nsp_comm_post(NSP_CH_LOG, buf, llen + 3);
}
/* 子进程日志转发 fd：run_in_mnt_ns_* fork 的子进程内 sender 线程不可达，
   子进程经此管道回传日志，父进程读取后统一写入环形缓冲（默认 -1=未启用） */
int g_log_forward_fd = -1;
_Atomic(bool) g_log_shutdown = false;
void init_timezone() {
    const char* tz = getenv("TZ");
    if (tz && tz[0] != '\0') {
        tzset();
        return;
    }
    char prop_buf[256];
#ifdef TARGET_ANDROID
    int len = __system_property_get("persist.sys.timezone", prop_buf);
    if (len > 0) {
        setenv("TZ", prop_buf, 1);
        tzset();
        return;
    }
    FILE* fp = fopen("/data/property/persist.sys.timezone", "re");
#else
    FILE* fp = fopen("/etc/timezone", "re");
#endif
    if (fp) {
        if (fgets(prop_buf, sizeof(prop_buf), fp)) {
            size_t plen = strlen(prop_buf);
            while (plen > 0 && (prop_buf[plen - 1] == '\n' || prop_buf[plen - 1] == '\r'))
                prop_buf[--plen] = '\0';
            if (plen > 0) {
                setenv("TZ", prop_buf, 1);
                tzset();
            }
        }
        fclose(fp);
    }
}
static const char* get_current_time_str(char* buf, size_t size) {
    time_t now = time(nullptr);
    struct tm tm_buf;
    localtime_r(&now, &tm_buf);
    strftime(buf, size, "%Y-%m-%d %H:%M:%S", &tm_buf);
    return buf;
}
void persist_log_to_disk(const char* log_type, const char* message, bool append_timestamp) {
    if (!g_persist_all_logs) return;
    pthread_mutex_lock(&g_persist_mutex);
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/persistent_%s.log", LOG_DIR, log_type);
    FILE* fp = fopen(path, "a");
    if (fp) {
        if (append_timestamp) {
            char time_buf[64];
            fprintf(fp, "[%s] ", get_current_time_str(time_buf, sizeof(time_buf)));
        }
        fprintf(fp, "%s\n", message);
        fclose(fp);
    }
    pthread_mutex_unlock(&g_persist_mutex);
}

/* 监控日志落盘（不看 g_persist_all_logs）：写 **LOG_DIR/persistent_io.log**，
   与 log_monitor 的 io.log 是两个文件。

   可用性边界（排查时勿误判）：仅在 `NSP_ENABLE_IO_LOG` 下编译（meson 只给
   debug 加该宏，发布构建不写），且当前**没有任何查询出口**——log_ctl 只读
   io.log/sys.log 与内存环，不读本文件。故它不是"UDS 不可用时的兜底可查
   历史"：真要兜底须同时补查询路径，否则落了盘也无人可读（YAGNI，不做）。
   主链路的丢失可观测性由两处负责：生产者侧 nsp_log_report（comm 拥塞覆盖
   旧数据，限频 5s）与 log_monitor 侧 report_drops_once（环满/合并队列满/
   落盘拒收，限频 10s）。 */
void persist_io_log(const char* message) {
    if (!message) return;
    mkdir_recursive(LOG_DIR);
    pthread_mutex_lock(&g_persist_mutex);
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/persistent_io.log", LOG_DIR);
    FILE* fp = fopen(path, "a");
    if (fp) {
        char time_buf[64];
        fprintf(fp, "[%s] %s\n", get_current_time_str(time_buf, sizeof(time_buf)), message);
        fclose(fp);
    }
    pthread_mutex_unlock(&g_persist_mutex);
}
void escape_cgroup() {
    /* 实现与 cgroup 路径表统一在 nsp_util（唯一出口，避免两份路径表漂移）。
       行为差异：原先此处对写入失败打 LOG_DBG 明细，现与 nsp_util 版一致静默
       ——cgroup 路径在不同 Android 版本/配置下本就可能不存在或无写权限，
       属预期内失败；需要明细时可在 nsp_escape_cgroup 内单独加。 */
    nsp_escape_cgroup();
}
/* IPC 短连接 helper（500ms 收发超时 + abstract namespace）：
   仅 comm 线程的 IPC 后端使用，调用线程一律 nsp_comm_post(NSP_CH_IPC) */
static int connect_ipc(void) {
    int sock_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (sock_fd < 0) return -1;
    struct timeval tv = {.tv_sec = 0, .tv_usec = 500000};
    setsockopt(sock_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    struct sockaddr_un server_addr;
    socklen_t len = nsp_uds_abstract_addr(&server_addr, IPC_SOCKET_NAME);
    if (connect(sock_fd, (struct sockaddr*)&server_addr, len) < 0) {
        close(sock_fd);
        return -1;
    }
    return sock_fd;
}

/* IPC 后端（comm 线程）：每条消息独立短连接（与 injector ipc_server 短连接
   语义一致：send 后即关，不读回包） */
static int nsp_ipc_emit(void* ctx, const void* data, size_t len) {
    (void)ctx;
    int fd = connect_ipc();
    if (fd < 0) return -1;
    if (!nsp_send_all(fd, data, len)) {
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}
void set_self_dir(const char* path) {
    if (path && *path) strncpy(g_self_dir, path, sizeof(g_self_dir) - 1);
}
char* get_self_dir() {
    if (g_self_dir[0] != 0) return g_self_dir;
    char buf[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (len != -1) {
        buf[len] = '\0';
        char* last_slash = strrchr(buf, '/');
        if (last_slash) *last_slash = '\0';
        strncpy(g_self_dir, buf, sizeof(g_self_dir) - 1);
    } else {
        strncpy(g_self_dir, "/data/local/tmp", sizeof(g_self_dir) - 1);
        g_self_dir[sizeof(g_self_dir) - 1] = '\0';
    }
    return g_self_dir;
}
/* 读取整个文件到堆内存（动态扩容，尾随 NUL）：injector 的 mount_manager
   与 ns_utils 原各自实现一份，现统一为公共工具（见 common.h 声明） */
char* read_file_dynamic(const char* path, size_t* out_size, size_t max_size) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return NULL;
    size_t capacity = 65536;
    size_t size = 0;
    char* buf = malloc(capacity);
    if (!buf) {
        close(fd);
        return NULL;
    }
    while (1) {
        ssize_t r = read(fd, buf + size, capacity - size - 1);
        if (r < 0) {
            if (errno == EINTR) continue;
            free(buf);
            close(fd);
            return NULL;
        }
        if (r == 0) break;
        size += r;
        if (max_size > 0 && size > max_size) { /* 超上限：拒绝，防超大文件撑爆内存 */
            free(buf);
            close(fd);
            errno = EFBIG;
            return NULL;
        }
        if (size >= capacity - 1) {
            capacity *= 2;
            char* nb = realloc(buf, capacity);
            if (!nb) {
                free(buf);
                close(fd);
                return NULL;
            }
            buf = nb;
        }
    }
    close(fd);
    buf[size] = '\0';
    if (out_size) *out_size = size;
    return buf;
}

/* 共享存储的落点形状：父目录给属主、属组，以及「组/其他」的读写位。

   共享存储里的条目由 MediaProvider 以**调用方凭证**去读（本模块不置
   FUSE_CAP_DONT_MASK，也不开 default_permissions，DAC 只在 access(2) 与
   MediaProvider 侧生效），所以条目最终长什么样，直接决定别的应用能不能打开它：
   实测同一目录里属主是应用、mode 0600 的条目，除写入者以外的应用 open 全部
   EACCES；补上组位（0660，属组仍是树属组）或 o+r 之后即可读。

   宽度取共享存储的固定形状（文件 0660、目录 0770），与 MediaProvider 自己建条目
   时用的位一致：那是一层与 umask 无关的「这棵树里彼此可读写」声明，按父目录实际
   位去推反而会让 0775/0771 这类目录传出 0664/0661 的第四条形状。

   只加位、不减位：调用方显式的 0644/0755 与其它位都保留。目录的 setgid 仍跟随
   父目录（POSIX：父目录带 S_ISGID 才继承），文件不加执行位。 */
static mode_t shared_storage_mode(mode_t want, const struct stat* pst, bool is_dir) {
    mode_t final_mode = want | (is_dir ? 0770 : 0660);
    if (is_dir)
        final_mode = (pst->st_mode & S_ISGID) ? (final_mode | S_ISGID) : (final_mode & ~S_ISGID);
    return final_mode;
}

/* 条目是否落在「共享存储」：<存储根>/<用户层> 之下，且不在根层的
   Android/{data,obb,media} 三棵私有树里。判定只认根层那三个名字，同名深层目录
   （应用自己建的 /sdcard/x/Android/data）照共享存储对待。

   存储根之外的路径（后端、临时目录）一律不算共享存储：那里的属主与 mode 由调用方
   与后端自己决定，套共享存储的形状没有依据。 */
static const char* const k_private_trees[] = {"/Android/data", "/Android/obb",
                                               "/Android/media"};

/* sub 是否正好落在根层三棵私有树之一（相等或以 '/' 接续）。同名深层目录不算。 */
static bool private_tree_prefix(const char* sub) {
    for (size_t i = 0; i < sizeof(k_private_trees) / sizeof(k_private_trees[0]); i++) {
        size_t tlen = strlen(k_private_trees[i]);
        if (strncmp(sub, k_private_trees[i], tlen) == 0 && (sub[tlen] == '\0' || sub[tlen] == '/'))
            return true;
    }
    return false;
}

static bool path_in_shared_storage(const char* real_path) {
    char base[PATH_MAX];
    common_storage_base(base, sizeof(base));
    size_t blen = strlen(base);
    if (blen == 0 || strncmp(real_path, base, blen) != 0 || real_path[blen] != '/') return false;
    int user_id = -1;
    const char* sub = NULL;
    if (common_parse_user_layer(real_path + blen, &user_id, &sub) != 1) return false;
    return !private_tree_prefix(sub);
}

/* 条目是否落在根层私有树里：与 path_in_shared_storage 同一套解析，判据相反。
   存储根之外、用户层解析不了的路径都不算。 */
static bool path_in_private_tree(const char* real_path) {
    char base[PATH_MAX];
    common_storage_base(base, sizeof(base));
    size_t blen = strlen(base);
    if (blen == 0 || strncmp(real_path, base, blen) != 0 || real_path[blen] != '/') return false;
    int user_id = -1;
    const char* sub = NULL;
    if (common_parse_user_layer(real_path + blen, &user_id, &sub) != 1) return false;
    return private_tree_prefix(sub);
}

/* 新建条目的属性收尾（唯一出口）：create / mkdir / mknod / symlink / 父目录补建 /
   沙盒落点全部经这里定最终 mode 与属主，各回调不得再自己 chmod。

   mode 口径：**调用方 mode 是权威值**。本模块不置 FUSE_CAP_DONT_MASK，VFS 在进
   FUSE 回调之前就已按请求者 umask 归一过 mode（mode & ~umask），daemon 拿到的是
   最终值。若再拿父目录 mode 覆盖它，umask 与应用显式指定的 0600/0700 会一起失效
   （实测：umask 000 / 022 / 077 建同一目录，结果都是父目录的 2770）。父目录只提供
   两件事：属主（新建条目归父目录属主，与 MediaProvider 建条目一致）与 setgid
   （POSIX：父目录带 S_ISGID 时子目录继承，否则不带——反过来把 setgid 送给不带它的
   父目录下的一切，就会造出 setgid 目录树，其中所有条目都归 _media_rw 组）。

   共享存储的落点另加一层：调用方 mode 只说明「它自己想给多少」，条目还要能被树里的
   其他应用打开，故最终 mode 再按父目录的组位与其他位补齐（见 shared_storage_mode），
   与 MediaProvider 自己建条目的形状一致。

   私有树（Android/{data,obb,media}）另按一条窄口径补位：普通文件补组位（0060），
   目录保持调用方 mode。这三棵树的属主与属组由 installd 体系给出（包目录 2770 归
   ext_data_rw），能穿过包目录的身份本来就只有全盘访问能力应用与系统组件（
   MediaProvider 的直通视图、MES 文件管理器）；应用在下载目录里写下的条目常被自己的
   umask 削到 0600，这批身份便读不到（实测 MediaProvider 身份读 0600 条目 EACCES、
   读 0660 条目成功）。补组位只对这批身份生效——不加 o 位（不暴露给任意应用）、不加
   x 位（不造可执行文件）、不动属主位（应用显式建的 0400 不会变成可写）。
   目录不补：树的隔离靠目录位，连目录一起放宽才会造出第二个共享存储。

   caller_mode 为 0 表示调用点确实没有 mode 可传（符号链接的 mode 在内核恒为 0777，
   真实值无意义）：此时回落父目录 mode，只作「值未知」的缺省，不用来覆盖已知值。

   符号链接不改 mode：chmod(2) 会穿透链接改到目标文件（旧实现正是如此）。 */
void nsp_new_entry_attrs(const char* real_path, mode_t caller_mode) {
    if (!real_path || real_path[0] != '/') return;
    char parent[PATH_MAX];
    int wn = snprintf(parent, sizeof(parent), "%s", real_path);
    if (wn <= 0 || (size_t)wn >= sizeof(parent)) return; /* 放不下就不猜：保持创建时的值 */
    char* last = strrchr(parent, '/');
    if (!last) return;
    if (last == parent)
        parent[1] = '\0';
    else
        *last = '\0';
    struct stat pst;
    if (lstat(parent, &pst) != 0) return;
    struct stat est;
    if (lstat(real_path, &est) != 0) return; /* 条目已不在（并发删）：无事可做 */
    /* 属主跟随父目录：daemon 以 root 建出来的条目必须归回父目录属主，否则应用在
       自己的存储树里拿到 root 属主的条目，后续 open/chmod 全被 DAC 拒掉。 */
    if (lchown(real_path, pst.st_uid, pst.st_gid) != 0) {
        /* 失败不致命（例如后端目标不支持 chown）：mode 照旧收敛，errno 留给调用点 */
    }
    if (!S_ISLNK(est.st_mode)) {
        bool is_dir = S_ISDIR(est.st_mode);
        mode_t final_mode = caller_mode & 07777;
        if (final_mode == 0) final_mode = pst.st_mode & 07777;
        if (path_in_shared_storage(real_path)) {
            final_mode = shared_storage_mode(final_mode, &pst, is_dir);
        } else if (is_dir) {
            final_mode =
                (pst.st_mode & S_ISGID) ? (final_mode | S_ISGID) : (final_mode & ~S_ISGID);
        } else if (S_ISREG(est.st_mode) && path_in_private_tree(real_path)) {
            final_mode |= 0060;
        }
        chmod(real_path, final_mode);
    }
#ifdef TARGET_ANDROID
    char context[256];
    ssize_t ctx_len = lgetxattr(parent, "security.selinux", context, sizeof(context));
    if (ctx_len > 0) {
        lsetxattr(real_path, "security.selinux", context, (size_t)ctx_len, 0);
    } else if (strncmp(real_path, STORAGE_BASE, sizeof(STORAGE_BASE) - 1) == 0) {
        /* 长度用 sizeof（含 NUL）：与 fuse_daemon 侧回填同一常量、同一算法，
           消除「手写字节数」这一类越界读来源 */
        lsetxattr(real_path, "security.selinux", NSP_DEFAULT_FILE_CONTEXT,
                  sizeof(NSP_DEFAULT_FILE_CONTEXT), 0);
    }
#endif
}

/* 条目落位后的属性重挂（rename 的唯一收尾）。

   rename(2) 只换名字、不换属性：条目会带着**来源树**的属主与 mode 落地。应用私有
   树的条目属主是应用 uid、mode 常被应用自己的 umask 削到 0600；一旦被搬进共享
   存储（"下载到 /sdcard"这类另存动作就是 rename），MediaProvider 会以调用方凭证
   去读这个**他属主**的文件——实测同一目录里属主为应用的 0600 条目，除写入者自己
   以外的应用全部 open EACCES，而属主为存储卷所有者的同名条目可读。新建条目没有
   这个问题（属主本就跟随父目录），
   缺口只在 rename 这条「不产生新条目」的路径上。

   口径与 nsp_new_entry_attrs 一致：属主/属组跟随目标父目录，mode 再按父目录的组位
   与其他位补齐（shared_storage_mode 是两条路径的唯一出处）。二者的差别只在时机：
   新建条目是「daemon 替应用造出来的」，落位条目是「应用自己造完搬过来的」，但落到
   共享存储之后，别的应用能不能打开只看最终属性，来源无关。

   判据必须按落点归类、不能按「属主是否与父目录相同」：应用私有树与共享存储可能被
   同一个 uid 拥有（私有树里的文件本来就归应用，父目录也可能归应用），此时属主一致
   却正是「来源树 mode 削到 0600」的典型现场。故这里不设「属主一致就早退」，只判
   落点在不在共享存储；应用私有树的落点一律不动——那里的属主由 installd 的 ACL
   体系决定，把共享存储的形状搬进去只会造出第二个共享存储。

   同属共享存储内部的改名也照同一口径收敛：宽度由树决定，不由上一次是谁写的决定。

   失败不致命：属性没挂上是可访问性问题，不该让 rename 本身失败（源可能已删，回滚
   只会连搬移一起丢掉），故只记日志。符号链接跳过：chmod 会穿透链接改到目标文件。 */
void nsp_rehome_moved_entry(const char* real_path) {
    if (!real_path || real_path[0] != '/') return;
    if (!path_in_shared_storage(real_path)) return;
    struct stat est;
    if (lstat(real_path, &est) != 0) return; /* 已不在（并发删）：无事可做 */
    if (S_ISLNK(est.st_mode)) return;
    char parent[PATH_MAX];
    int wn = snprintf(parent, sizeof(parent), "%s", real_path);
    if (wn <= 0 || (size_t)wn >= sizeof(parent)) return;
    char* slash = strrchr(parent, '/');
    if (!slash || slash == parent) return;
    *slash = '\0';
    struct stat pst;
    if (lstat(parent, &pst) != 0) return;
    if ((est.st_uid != pst.st_uid || est.st_gid != pst.st_gid) &&
        lchown(real_path, pst.st_uid, pst.st_gid) != 0)
        LOG_WRN("落位条目改属主失败: path=%s uid=%u gid=%u errno=%d", real_path,
                (unsigned)pst.st_uid, (unsigned)pst.st_gid, errno);
    mode_t want = est.st_mode & 07777;
    mode_t final_mode = shared_storage_mode(want, &pst, S_ISDIR(est.st_mode));
    if (final_mode != want && chmod(real_path, final_mode) != 0)
        LOG_WRN("落位条目改 mode 失败: path=%s mode=%04o errno=%d", real_path,
                (unsigned)final_mode, errno);
#ifdef TARGET_ANDROID
    char context[256];
    ssize_t ctx_len = lgetxattr(parent, "security.selinux", context, sizeof(context));
    if (ctx_len > 0) {
        lsetxattr(real_path, "security.selinux", context, (size_t)ctx_len, 0);
    } else if (strncmp(real_path, STORAGE_BASE, sizeof(STORAGE_BASE) - 1) == 0) {
        lsetxattr(real_path, "security.selinux", NSP_DEFAULT_FILE_CONTEXT,
                  sizeof(NSP_DEFAULT_FILE_CONTEXT), 0);
    }
#endif
    LOG("落位条目重挂属性: path=%s uid=%u gid=%u mode=%04o -> %04o", real_path,
        (unsigned)pst.st_uid, (unsigned)pst.st_gid, (unsigned)want, (unsigned)final_mode);
}

/* 父目录补建时的收尾：中间目录没有「调用方 mode」，用 mkdir 时给的 mode 作
   权威值（同一趟循环里的 mode 参数），语义与其余创建路径完全一致。 */
static void inherit_from_parent(const char* real_path, mode_t mode) {
    nsp_new_entry_attrs(real_path, mode);
}

/* 递归建目录的唯一实现。inherit=true 时对新目录套用父目录的属主与 setgid，
   mode 仍取本函数的 mode 参数（Android 另含 SELinux 上下文），供 mkdir_recursive_p；
   mkdir_recursive 保持历史语义（不继承属性、固定 0755）。
   两者语义确有差异故保留两个入口，但共用本实现——此前各写一份循环，
   且 mkdir_recursive 用 256 字节栈缓冲，超长路径会被静默拒绝。 */
static int mkdir_p_impl(const char* path, mode_t mode, bool inherit, size_t start) {
    if (!path || !path[0]) return -1;
    char tmp[PATH_MAX];
    /* 放不下即拒绝（同"路径合成不截断"约定）：静默截断后会沿错误路径逐级建目录 */
    int wn = snprintf(tmp, sizeof(tmp), "%s", path);
    if (wn < 0 || (size_t)wn >= sizeof(tmp)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    size_t len = strlen(tmp);
    if (len == 0) return -1;
    if (tmp[len - 1] == '/') tmp[len - 1] = '\0';
    len = strlen(tmp);
    if (start < 1) start = 1;
    if (start > len) start = len;
    /* start = 第一个允许**本函数创建**的组件的起始下标（之前的组件视为已存在）。
       start>1 时循环首轮的截断点是更深的路径前缀——一级组件因此永不参与 mkdir；
       它若真的不存在，首次 mkdir 自然返回 ENOENT（结构性 fail-closed）。 */
    for (char* p = tmp + start; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (access(tmp, F_OK) != 0) {
                if (mkdir(tmp, mode) == 0) {
                    if (inherit) inherit_from_parent(tmp, mode);
                } else if (errno != EEXIST) {
                    return -1;
                }
            }
            *p = '/';
        }
    }
    if (access(tmp, F_OK) != 0) {
        if (mkdir(tmp, mode) == 0) {
            if (inherit) inherit_from_parent(tmp, mode);
        } else if (errno != EEXIST) {
            return -1;
        }
    }
    return 0;
}

int mkdir_recursive(const char* dir) {
    return mkdir_p_impl(dir, 0755, false, 1);
}

int mkdir_recursive_p(const char* path, mode_t mode) {
    return mkdir_p_impl(path, mode, true, 1);
}
/* 核心修复：共享的无效 Unicode/控制字符检测逻辑。
   增加全面的 Null 终止探测防御，绝不发生指针越过结束符 '\0' 的情况，阻断任何越界或野指针异常 */
static int path_char_is_invalid(const unsigned char* p) {
    if (*p == '\0') return 0;
    if (*p < 0x08) return 1;
    if (*p > 0x09 && *p < 0x20) return 1;
    if (*p == 0x7F) return 1;
    // 2 字节 UTF-8 校验，需确保 p[1] 并非终止符
    if (p[0] == 0xC2 && p[1] != '\0' && (p[1] == 0xA0 || p[1] == 0xAD)) return 2;
    // 3 字节 UTF-8 校验，需确保 p[1], p[2] 并非终止符
    if (p[0] == 0xE2 && p[1] != '\0' && p[2] != '\0') {
        if (p[1] == 0x80 && p[2] >= 0x80 && p[2] <= 0xAF) return 3;
        if (p[1] == 0x81 && p[2] >= 0xA0 && p[2] <= 0xAF) return 3;
    }
    if (p[0] == 0xE1 && p[1] != '\0' && p[2] != '\0') {
        if (p[1] == 0xA0 && p[2] == 0x8E) return 3;
    }
    if (p[0] == 0xEF && p[1] != '\0' && p[2] != '\0') {
        if (p[1] == 0xBB && p[2] == 0xBF) return 3;
    }
    // 4 字节 UTF-8 校验，需确保 p[1], p[2], p[3] 并非终止符
    if (p[0] == 0xF3 && p[1] != '\0' && p[2] != '\0' && p[3] != '\0') {
        if (p[1] == 0xA0 && p[2] == 0x80 && p[3] >= 0x80 && p[3] <= 0xBF) return 4;
        if (p[1] == 0xA0 && p[2] == 0x81 && p[3] >= 0x80 && p[3] <= 0xAF) return 4;
    }
    return 0;
}
bool path_contains_invalid_chars(const char* path) {
    if (!path) return false;
    const unsigned char* p = (const unsigned char*)path;
    while (*p) {
        int skip = path_char_is_invalid(p);
        if (skip > 0) return true;
        p++;
    }
    return false;
}
void path_sanitize(char* out, size_t size, const char* path) {
    if (!out || size == 0) return;
    if (!path) {
        out[0] = '\0';
        return;
    }
    const unsigned char* p = (const unsigned char*)path;
    size_t o = 0;
    size_t max = size - 1;
    while (*p && o < max) {
        int skip = path_char_is_invalid(p);
        if (skip > 0) {
            p += skip;
        } else {
            out[o++] = *p;
            p++;
        }
    }
    out[o] = '\0';
}
/* LOG 通道载荷：[kind:1][level:1][msg...]（调用线程组帧头，发送组包） */
typedef struct {
    int sock; /* -1=未建链（仅 comm 线程触碰） */
} log_be_ctx_t;
static log_be_ctx_t g_log_be = {.sock = -1};

static bool nsp_log_ensure_link(void* ctx) {
    log_be_ctx_t* c = ctx;
    if (c->sock >= 0) return true;
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return false;
    struct timeval tv = {.tv_sec = 0, .tv_usec = 50000};
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    struct sockaddr_un addr;
    socklen_t len = nsp_uds_abstract_addr(&addr, LOG_SOCKET_NAME);
    if (connect(fd, (struct sockaddr*)&addr, len) < 0) {
        close(fd);
        return false;
    }
    c->sock = fd;
    return true;
}

static int nsp_log_emit(void* ctx, const void* data, size_t len) {
    log_be_ctx_t* c = ctx;
    if (len < 2 || c->sock < 0) return -1;
    const uint8_t* p = data;
    char packet[NSP_LOG_MSG_MAX * 2 + 128];
    /* msg 段以 NUL 截断防越界（post 载荷恒以 NUL 结尾，见 log_internal） */
    size_t mlen = len - 2;
    if (mlen >= NSP_LOG_MSG_MAX) mlen = NSP_LOG_MSG_MAX - 1;
    char msg[NSP_LOG_MSG_MAX];
    memcpy(msg, p + 2, mlen);
    msg[mlen] = '\0';
    int plen = log_frame_packet(p[0], p[1], msg, packet, sizeof(packet));
    if (plen <= 0) return 0;
    if (!nsp_send_all(c->sock, packet, (size_t)plen)) {
        close(c->sock);
        c->sock = -1;
        return -1;
    }
    return 0;
}

static void nsp_log_fini(void* ctx) {
    log_be_ctx_t* c = ctx;
    if (c->sock >= 0) {
        close(c->sock);
        c->sock = -1;
    }
}

/* 拥塞上报：本 drain 轮有覆盖丢弃时经 LOG 通道发一行 SYS 可查
   （post 永不阻塞；LOG 自身拥塞时该行亦可能被覆盖，计数以 API 为准。
   若本进程未注册 LOG 后端（如 log_monitor），该行计 dropped，无限循环） */
void nsp_log_report(nsp_ch_t ch, uint64_t n, void* ctx) {
    (void)ctx;
    /* 限频 5s：LOG 自身拥塞时报告回注会加剧拥塞、下轮再报，限频后每轮
       最多一条；精确计数以 nsp_comm_dropped() 为准 */
    static uint64_t last_ms = 0;
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t now = (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
    if (now - last_ms < 5000) return;
    last_ms = now;
    static const char* names[NSP_CH__N] = {"LOG", "IPC", "BCAST"};
    char msg[128];
    int mlen = snprintf(msg, sizeof(msg), "comm: %s 通道拥塞，覆盖旧数据 %llu 条", names[ch],
                        (unsigned long long)n);
    if (mlen <= 0) return;
    uint8_t buf[2 + 128];
    buf[0] = LOG_KIND_NORMAL;
    buf[1] = (uint8_t)LOG_WARN;
    memcpy(buf + 2, msg, (size_t)mlen + 1);
    nsp_comm_post(NSP_CH_LOG, buf, (size_t)mlen + 3);
}

void log_init(const char* process_name) {
    init_timezone();
    strncpy(g_proc_name, process_name, sizeof(g_proc_name) - 1);
    mkdir_recursive(LOG_DIR);
    atomic_store_explicit(&g_log_shutdown, false, memory_order_relaxed);
    /* 统一通讯线程：LOG + IPC 后端常驻（调用线程只 post，永不碰 socket） */
    if (nsp_comm_init() != 0) {
        g_log_inited = false;
        return;
    }
    nsp_comm_backend_t log_be = {
        .ctx = &g_log_be,
        .ensure_link = nsp_log_ensure_link,
        .emit = nsp_log_emit,
        .fini = nsp_log_fini,
        .report = nsp_log_report,
    };
    nsp_comm_register(NSP_CH_LOG, &log_be);
    nsp_comm_backend_t ipc_be = {
        .ctx = NULL,
        .ensure_link = NULL,
        .emit = nsp_ipc_emit,
        .fini = NULL,
        .report = nsp_log_report,
    };
    nsp_comm_register(NSP_CH_IPC, &ipc_be);
    g_log_inited = true;
}

void log_close(void) {
    if (!g_log_inited) return;
    nsp_comm_fini(); /* 最尽力 drain + join */
    g_log_inited = false;
}

void log_internal(LogLevel level, const char* format, ...) {
    if (level < g_min_log_level && level != LOG_DEBUG) return;
    char msg_buf[NSP_LOG_MSG_MAX];
    va_list args;
    va_start(args, format);
    vsnprintf(msg_buf, sizeof(msg_buf), format, args);
    va_end(args);
    size_t mlen = strlen(msg_buf);
    while (mlen > 0 && (msg_buf[mlen - 1] == '\n' || msg_buf[mlen - 1] == '\r'))
        msg_buf[--mlen] = '\0';
    /* 子进程日志转发：fork 后的子进程内 sender 线程不可达（fork 不复制线程），
       环形缓冲写了也没人消费；检测到 g_log_forward_fd 时把日志行写入管道，
       由父进程读取后统一写入环形缓冲（保持行格式 [时间]|[进程]|msg） */
    if (g_log_forward_fd >= 0) {
        char fwd_buf[NSP_LOG_MSG_MAX + 96];
        int flen = snprintf(fwd_buf, sizeof(fwd_buf), "%d|%s\n", (int)level, msg_buf);
        if (flen > 0) {
            ssize_t w = write(g_log_forward_fd, fwd_buf, (size_t)flen);
            (void)w;
        }
        return;
    }
    if (level == LOG_IO) {
#ifdef NSP_ENABLE_IO_LOG
        /* 监控日志落盘（LOG_DIR/persistent_io.log）：仅调试/监控构建
           （-DNSP_ENABLE_IO_LOG）启用——发布构建默认关闭该文件输出，
           避免弱网/低端设备上频繁 I/O 落盘；log_ctl/UDS 查询不受影响 */
        persist_io_log(msg_buf);
#endif
    } else if (g_persist_all_logs) {
        if (level == LOG_LOGCAT)
            persist_log_to_disk("logcat", msg_buf, true);
        else
            persist_log_to_disk("sys", msg_buf, true);
    }
    if (!g_log_inited) return;
    /* 合并周期内：累积到批量缓冲（不逐条写环形缓冲），由 log_batch_end
       合并为单条日志，前端最终只显示一条（多个发送请求并入一个日志）。
       只累积内容本身（不带 [proc] 前缀），条目间以制表符连接（不用换行，
       避免前端按行拆分导致长内容截断/中文乱码），标签由合并单条统一带。
       原子读 depth：log_batch_end 用 __sync_fetch_and_sub 归零，若此处
       用普通读可能看到陈旧值 1，在 batch 已结束归零后仍追加内容到已
       重置缓冲，造成消息丢失且残留字节并入下一周期 */
    if (__sync_fetch_and_add(&g_log_batch_depth, 0) > 0) {
        pthread_mutex_lock(&g_log_batch_mutex);
        int w = snprintf(g_log_batch_buf + g_log_batch_len,
                         sizeof(g_log_batch_buf) - g_log_batch_len, "%s\t", msg_buf);
        if (w > 0 && g_log_batch_len + (size_t)w < sizeof(g_log_batch_buf))
            g_log_batch_len += (size_t)w;
        pthread_mutex_unlock(&g_log_batch_mutex);
        return;
    }
    /* 调用线程仅组帧头 + post（永不碰 socket/mutex 长临界区/eventfd 细则） */
    uint8_t buf[2 + NSP_LOG_MSG_MAX];
    buf[0] = LOG_KIND_NORMAL;
    buf[1] = (uint8_t)level;
    size_t mlen2 = strlen(msg_buf);
    memcpy(buf + 2, msg_buf, mlen2 + 1);
    nsp_comm_post(NSP_CH_LOG, buf, mlen2 + 3);
}

bool is_media_provider(const char* pkg) {
    return (strstr(pkg, "com.android.providers.media") != nullptr);
}

/* 存储路径合成统一出口：fuse_daemon fw_default_real_path、br_rules 回退分支、
 * path_vars build_real_base 尾部分支原各写一份 STORAGE_BASE snprintf，现收敛至此。
 * 语义与原手写逻辑逐分支一致（g_real_root 非空则用测试/注入指定的真实根）。
 * 失败闭合：保持 void 签名（不断模块 ABI，见 nsp_module.h），放不下时写空串
 * 而非截断串——调用方以截断路径 open 会读写**错误的文件**，空串则以 ENOENT
 * 失败（fail-closed）。P3：每展开点独立计数、前 3 次带调用点告警（不同场景
 * 不再被一次性标志屏蔽），之后每 1024 次补一行抑制计数。
 * 输入恒受 MAX_PATH_LEN/PATH_MAX 约束，实际不可达；一旦出现即排查。 */
#define PATH_SNPRINTF(out, sz, ...)                                                                \
    do {                                                                                           \
        int _pn = snprintf(out, sz, __VA_ARGS__);                                                  \
        if (_pn < 0 || (size_t)_pn >= (sz)) {                                                      \
            (out)[0] = '\0'; /* 失败闭合：截断串永不外流 */                                        \
            static _Atomic unsigned _pwarn_n = 0;                                                  \
            unsigned _n0 = atomic_fetch_add(&_pwarn_n, 1);                                         \
            if (_n0 < 3)                                                                           \
                LOG_WRN("路径合成截断[%s:%d]（需 %d/限 %zu），已置空失败", __func__, __LINE__,     \
                        _pn, (size_t)(sz));                                                        \
            else if (_n0 % 1024 == 0)                                                              \
                LOG_WRN("路径合成截断[%s:%d]已累计 %u 次（抑制中）", __func__, __LINE__, _n0);     \
        }                                                                                          \
    } while (0)

void common_default_real_path(int user_id, const char* sub_path, char* out, size_t sz) {
    if (!out || sz == 0) return;
    if (!sub_path) sub_path = "/";
    if (user_id >= 0) {
        if (g_real_root[0])
            PATH_SNPRINTF(out, sz, "%s/%d%s", g_real_root, user_id, sub_path);
        else
            PATH_SNPRINTF(out, sz, STORAGE_BASE "/%d%s", user_id, sub_path);
    } else {
        if (g_real_root[0])
            PATH_SNPRINTF(out, sz, "%s%s", g_real_root, sub_path);
        else
            PATH_SNPRINTF(out, sz, STORAGE_BASE "%s", sub_path);
    }
}

/* FUSE 视角路径 "/<user_id><sub_path>"：common_parse_user_layer 的逆运算。
   事件通道的 QUERY 把绝对 spath 反解成 (user, sub) 后，必须换回这个层级再交给
   fw_acl_check/fw_rules_resolve（两者的 path 入参都是 FUSE 视角）。放不下返回 -1
   并清空输出：截断会让判定作用在**另一个路径**上（ACL/规则按路径前缀分类，
   截断后可能从"他包 Android/data"变成"自己的普通目录"，即放行）。 */
int common_fuse_user_path(int user_id, const char* sub_path, char* out, size_t sz) {
    if (!out || sz == 0) return -1;
    if (!sub_path) sub_path = "/";
    int n = (user_id < 0) ? snprintf(out, sz, "%s", sub_path)
                          : snprintf(out, sz, "/%d%s", user_id, sub_path);
    if (n < 0 || (size_t)n >= sz) {
        out[0] = '\0';
        return -1;
    }
    return 0;
}

/* 存储视图路径：应用看到的绝对路径 NSP_ANDROID_EMULATED_ROOT/<user_id><sub_path>。
   user_id<0 表无用户层（挂载点根）：原样输出 sub_path——视图里没有用户层可拼。
   与 common_default_real_path 的分工见 common.h：本函数恒为**视图**口径，
   不读 g_real_root（测试根是 daemon 内部实现细节，应用看不到）。 */
void common_view_path(int user_id, const char* sub_path, char* out, size_t sz) {
    if (!out || sz == 0) return;
    if (!sub_path) sub_path = "/";
    if (user_id < 0) {
        PATH_SNPRINTF(out, sz, "%s", sub_path);
        return;
    }
    PATH_SNPRINTF(out, sz, NSP_ANDROID_EMULATED_ROOT "/%d%s", user_id, sub_path);
}

void common_storage_root(int user_id, char* out, size_t sz) {
    if (!out || sz == 0) return;
    if (user_id < 0) user_id = 0;
    if (g_real_root[0])
        PATH_SNPRINTF(out, sz, "%s/%d", g_real_root, user_id);
    else
        PATH_SNPRINTF(out, sz, STORAGE_BASE "/%d", user_id);
}

/* 沙盒目录名：默认 NSP_SANDBOX_DIRNAME，配置发布时经 common_set_sandbox_dirname
   单点覆盖（[GLOBAL] 段 SANDBOX_DIR，热重载生效）；common_sandbox_path 唯一消费 */
static char g_sandbox_dirname[64] = NSP_SANDBOX_DIRNAME;

void common_set_sandbox_dirname(const char* name) {
    if (!name || !name[0] || strlen(name) >= sizeof(g_sandbox_dirname) || strchr(name, '/'))
        return; /* 非法回退：保持现值（解析层已挡，此处兜底） */
    strcpy(g_sandbox_dirname, name);
}

int common_sandbox_path(int uid, const char* pkg, char* out, size_t sz) {
    if (!pkg || !pkg[0] || !out || sz == 0) return -1;
    if (uid < 0) uid = 0;
    /* 落点是应用外部数据目录 <STORAGE_BASE>/<uid>/Android/data/<pkg>/<沙盒目录名>
       （默认 "sandbox"，配置可覆盖） */
    const char* dirname = g_sandbox_dirname;
    int need;
    if (g_real_root[0])
        need = snprintf(nullptr, 0, "%s/%d/Android/data/%s/%s", g_real_root, uid, pkg, dirname);
    else
        need = snprintf(nullptr, 0, STORAGE_BASE "/%d/Android/data/%s/%s", uid, pkg, dirname);
    if (need <= 0 || (size_t)need >= sz) return -1;
    if (g_real_root[0])
        snprintf(out, sz, "%s/%d/Android/data/%s/%s", g_real_root, uid, pkg, dirname);
    else
        snprintf(out, sz, STORAGE_BASE "/%d/Android/data/%s/%s", uid, pkg, dirname);
    return 0;
}

/* ================= 存储根一级条目守卫 =================
 * 历史缺陷：/data/media（= /storage/emulated）顶层反复出现纯数字垃圾目录，
 * 只能在 /data/media 下删掉。链路：被注入的应用请求 /<数字>/… → fw_parse_path
 * 把第一个全数字段当 user_id（没有任何存在性校验）→ 真实路径
 * <STORAGE_BASE>/<数字>/… → mkdir/open(O_CREAT) 的父目录补建把
 * <STORAGE_BASE>/<数字> 造出来；守护进程以 root 执行，普通应用借此获得了
 * 「在存储根造条目」这一本应只有 vold/root 才有的能力。
 *
 * 因此把「存储根一级条目」提升为框架级不变量：**FUSE 视图永不创建/删除一级
 * 条目**（读写既有条目照旧）；「不存在的用户层」读写都按 ENOENT（根级 REDIRECT
 * 下规则引擎会把 /<数字> 合成为“已存在目录”，读侧不拦应用就会下探并触发出落盘）。
 * 判定由路由层 fail-closed，三个出口集中在本节，禁止各回调私刻判定（与 fw_route
 * 的 hidden/ro 单点同一红线）。 */

/* 有效存储根：--root=<测试/注入根> 优先，否则 STORAGE_BASE（与
   common_default_real_path 同口径）。放不下写空串失败闭合。 */
void common_storage_base(char* out, size_t sz) {
    if (!out || sz == 0) return;
    PATH_SNPRINTF(out, sz, "%s", g_real_root[0] ? g_real_root : STORAGE_BASE);
    /* 归一尾部 '/'：--root=<dir>/ 这种写法会让 base 以 '/' 结尾，层级判定
       （real_path[bl] != '/'）与一级组件切片整体错位、守卫静默失效——统一剥掉 */
    size_t n = strlen(out);
    while (n > 1 && out[n - 1] == '/') out[--n] = '\0';
}

/* real_path 是否恰为「存储根一级条目」：<base>/<单个组件>（其后不再有 '/'）。
   存储根本身、更深层路径、以及不在存储根下的路径（FTP 目标、测试根外重定向）
   均返回 false——只拦「在存储根下新建/删改一级条目」这一件事。 */
bool common_is_storage_root_entry(const char* real_path) {
    if (!real_path || real_path[0] != '/') return false;
    /* 尾部斜杠归一：real_path 由 <base>/<uid><sub_path> 合成，sub_path 为 "/"
       时会带尾 '/'（如 /data/media/999/ 指的就是用户根条目本身）——不归一会漏判 */
    size_t rl = strlen(real_path);
    while (rl > 1 && real_path[rl - 1] == '/') rl--;
    char base[PATH_MAX];
    common_storage_base(base, sizeof base);
    size_t bl = strlen(base);
    if (bl == 0 || rl <= bl + 1) return false;
    if (strncmp(real_path, base, bl) != 0) return false;
    if (real_path[bl] != '/') return false; /* <base> 本身 或 <base>xxx 同前缀异名 */
    const char* name = real_path + bl + 1;
    size_t nl = rl - bl - 1; /* 一级组件长度（已去尾斜杠） */
    if (nl == 0) return false; /* 存储根本身 */
    for (size_t i = 0; i < nl; i++) {
        if (name[i] == '/') return false; /* 更深层：不是一级条目 */
    }
    return true;
}

/* 创建类回调的父目录补建唯一出口（daemon 的 create/mkdir/symlink/rename 与
   沙盒落点共用）：**绝不创建存储根一级组件**——一级组件缺失即失败
   （errno=ENOENT，由调用方原样回给内核），避免 mkdir_recursive_p 替普通应用
   在存储根下 materialize 目录。非存储根路径沿用原语义（FTP 相对目标等）。
   注意：本函数只保证「不新建一级组件」，已有的一级组件（用户根/obb）下照常
   递归补建。 */
int common_mkdir_within_storage(const char* dir, mode_t mode) {
    if (!dir || dir[0] != '/') {
        errno = EINVAL;
        return -1;
    }
    char base[PATH_MAX];
    common_storage_base(base, sizeof base);
    size_t bl = strlen(base);
    if (bl > 0 && strncmp(dir, base, bl) == 0 && dir[bl] == '/') {
        const char* name = dir + bl + 1;
        if (name[0] == '\0') return 0; /* 存储根本身：必然已存在 */
        const char* slash = strchr(name, '/');
        if (!slash) {
            /* 目标**就是**存储根一级组件本身：永不创建（由 vold 掌管） */
            errno = ENOENT;
            return -1;
        }
        /* 从一级组件之后的第二个组件起递归补建：一级组件只作前缀、不参与
           mkdir（连 access/mkdir 都不做，顺带堵掉「查与建之间被删→重建」的窄窗口）。
           它若缺失，首次 mkdir 自然 ENOENT。 */
        return mkdir_p_impl(dir, mode, true, (size_t)(slash - dir) + 1);
    }
    return mkdir_recursive_p(dir, mode);
}

/* ================= FUSE 路径 <uid>/ 用户层解析（唯一实现） =================
 * fw_parse_path（框架路由）与 br_strip_and_sanitize（规则引擎）历史上各写一份、
 * 语义必须逐行一致——现共用本函数。三点约定：
 *   - 只有「完整 user_id 目录」才剥离：数字序列后是结尾或 '/'（/0、/10/…）；
 *     数字前缀文件名（/1_abc.txt、/12_34）不剥离（见 vfs_readdir 的 uid_dir 判定）；
 *   - 数字串超出 int 范围返回 -1（非法用户层）：atoi 溢出是 UB，实测
 *     /4294967296/x 会被别名成 /0/x——把别人的存储当成本用户，必须 fail-closed；
 *   - 返回值：1=命中（*user_id 与 *sub_path 有效）、0=无用户层（*sub_path 指回原
 *     路径）、-1=非法（调用方按 ENOENT 处理）。 */
int common_parse_user_layer(const char* path, int* user_id, const char** sub_path) {
    if (user_id) *user_id = -1;
    if (sub_path) *sub_path = path;
    if (!path || path[0] != '/' || path[1] < '0' || path[1] > '9') return 0;
    const char* d = path + 1;
    long v = 0;
    while (*d >= '0' && *d <= '9') {
        int digit = *d - '0';
        if (v > (INT_MAX - digit) / 10) return -1; /* 超出 int：非法用户层 */
        v = v * 10 + digit;
        d++;
    }
    if (*d != '\0' && *d != '/') return 0; /* 数字前缀文件名：不剥离 */
    if (user_id) *user_id = (int)v;
    if (sub_path) *sub_path = (*d == '/') ? d : "/";
    return 1;
}
