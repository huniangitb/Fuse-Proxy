#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
/*
 * fw_pkg.c — 框架侧 uid → 包名解析（见 fw_pkg.h）
 *
 * 解析顺序与模块 br_get_app_cfg 保持一致（uid.map → /proc），使框架与模块对同一
 * 请求得到同一个包名；差别只在本文件不做 AppConfig 关联（那是 fw_config 的事）。
 * 例外是**带真实调用方 pid** 的请求：共享 uid 下 uid.map 只有一条，先按进程自身
 * cmdline 解析才能区分兄弟包（见 resolve_from_pid）。
 */
#include "fw_pkg.h"
#include "common.h"
#include "nsp_constants.h"
#include "uid_map.h"
#include "fast_pid.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char** environ;

#define FW_PKG_CACHE_SIZE 2048
#define FW_PKG_NAME_MAX 128

/* 槽位：uid→包名是进程事实，规则重载只使代际失效（gen 不匹配即重新解析）。
   热路径（每次 FUSE 请求读 current_pkg）用 seqlock 无锁读，填充走互斥锁。 */
typedef struct {
    _Atomic uint64_t seq; /* 奇数 = 写者进行中 */
    uint64_t gen;
    uid_t uid;
    bool lookup_ok;
    char pkg[FW_PKG_NAME_MAX];
} FwPkgSlot;

static FwPkgSlot g_slots[FW_PKG_CACHE_SIZE];
static pthread_mutex_t g_fill_lock = PTHREAD_MUTEX_INITIALIZER;
static _Atomic uint64_t g_gen = 1;

static UidMapEntry* g_uid_maps = nullptr;
static int g_uid_map_count = 0;

/* uid.map 条目数随已启动应用增长：按需扩容装载（同模块 load_uid_map） */
static void load_uid_map(void) {
    int cap = UID_MAP_INIT_CAPACITY;
    UidMapEntry* maps = malloc((size_t)cap * sizeof(UidMapEntry));
    if (!maps) return;
    int count = uid_map_load(maps, cap);
    while (count > 0 && count == cap) {
        cap *= 2;
        UidMapEntry* bigger = realloc(maps, (size_t)cap * sizeof(UidMapEntry));
        if (!bigger) break; /* 扩容失败：用已装载部分，缺失项走 /proc 回退 */
        maps = bigger;
        count = uid_map_load(maps, cap);
    }
    UidMapEntry* old = g_uid_maps;
    g_uid_maps = maps;
    g_uid_map_count = count;
    free(old);
}

void fw_pkg_reload(void) {
    load_uid_map();
    atomic_fetch_add_explicit(&g_gen, 1, memory_order_release);
}

static void appops_children_shutdown(void);

void fw_pkg_shutdown(void) {
    appops_children_shutdown();
    free(g_uid_maps);
    g_uid_maps = nullptr;
    g_uid_map_count = 0;
}

/* /data/system/packages.list：Android 全量已装应用清单（"pkg uid ..."），
   系统共享 uid（1000 等）的包名唯一可靠来源（uid.map 无条目、caller pid 不可得）。
   找到返回 true 并写入 out；找不到/打不开返回 false。seinfo 非空时顺带带回
   该行的 MAC 权限标签（如 "platform:privapp:targetSdkVersion=36"），供特权
   判定（fw_pkg_is_privileged）使用。路径可用 fw_pkg_set_packagelist_path
   注入（仅测试；生产恒为 /data/system/packages.list）。 */
static const char g_packagelist_path[] = "/data/system/packages.list";
static const char* g_packagelist_override = nullptr;

void fw_pkg_set_packagelist_path(const char* path) { g_packagelist_override = path; }

/* packages.list 的唯一打开点：uid→包名、包名→uid、特权判定三处共用同一个
   路径钩子（测试注入一份夹具就同时覆盖三个查询）。 */
static FILE* open_packagelist(void) {
    return fopen(g_packagelist_override ? g_packagelist_override : g_packagelist_path, "re");
}

static bool resolve_sys_pkg_from_packagelist(uid_t uid, char* out, size_t size,
                                             char* seinfo, size_t seinfo_size) {
    FILE* fp = open_packagelist();
    if (!fp) return false;
    bool found = false;
    char line[1024];
    while (fgets(line, sizeof line, fp)) {
        char name[FW_PKG_NAME_MAX];
        unsigned int puid = 0;
        if (sscanf(line, "%127s %u", name, &puid) == 2 && puid == (unsigned int)uid) {
            snprintf(out, size, "%s", name);
            if (seinfo && seinfo_size > 0) {
                /* 第 4 字段 dataDir 第 5 字段 seinfo："pkg uid debug dataDir seinfo ..." */
                seinfo[0] = '\0';
                char datadir[256];
                if (sscanf(line, "%*127s %*u %*u %255s %127s", datadir, seinfo) != 2)
                    seinfo[0] = '\0';
            }
            found = true;
            break;
        }
    }
    fclose(fp);
    return found;
}

/* uid 是否为特权应用（Android 权限体系自动判定，见 fw_pkg.h）。缓存独立于
   包名解析槽位：privileged 是"uid → 布尔"的稳定事实（packages.list 只在
   应用安装/升级时变化），包名缓存 gen 失效不影响它。 */
typedef struct {
    _Atomic uint64_t seq; /* 奇数 = 写者进行中 */
    uint64_t gen;
    uid_t uid;
    bool known; /* packages.list 有该 uid 的行（不可读/未命中 = false） */
    bool priv;
} FwPkgPrivSlot;

static FwPkgPrivSlot g_priv_slots[FW_PKG_CACHE_SIZE];
static pthread_mutex_t g_priv_fill_lock = PTHREAD_MUTEX_INITIALIZER;

/* seinfo 以 "platform" 开头 = platform 签名（system/priv-app/签名共享）。
   实测 packages.list：DocumentsUI "platform:privapp:…"、Settings "platform:privapp:…"、
   系统签名覆盖层 "platform:targetSdkVersion=…"；普通应用恒为 "default:…"。
   "privapp" 子串单独判会漏掉纯 platform 签名应用，故判前缀。 */
static bool seinfo_is_privileged(const char* seinfo) {
    return strncmp(seinfo, "platform", 8) == 0 &&
           (seinfo[8] == '\0' || seinfo[8] == ':');
}

bool fw_pkg_is_privileged(uid_t uid) {
    FwPkgPrivSlot* s = &g_priv_slots[uid % FW_PKG_CACHE_SIZE];
    uint64_t gen = atomic_load_explicit(&g_gen, memory_order_acquire);
    for (;;) {
        uint64_t v1 = atomic_load_explicit(&s->seq, memory_order_acquire);
        if (!(v1 & 1)) {
            if (v1 == s->seq && s->gen == gen && s->uid == uid && s->known)
                return s->priv;
        }
        if (atomic_load_explicit(&s->seq, memory_order_acquire) & 1) continue;
        pthread_mutex_lock(&g_priv_fill_lock);
        char pkg[FW_PKG_NAME_MAX];
        char seinfo[128];
        bool known = resolve_sys_pkg_from_packagelist(uid, pkg, sizeof pkg, seinfo,
                                                      sizeof seinfo);
        bool priv = known && seinfo_is_privileged(seinfo);
        /* 槽位写回只依赖 g_priv_fill_lock（本函数独占路径）+ 自身 seqlock 标记；
           绝不碰 g_fill_lock——包名填充路径（g_fill_lock）会调用本函数，嵌套即死锁 */
        atomic_store_explicit(&s->seq, atomic_load_explicit(&s->seq, memory_order_relaxed) + 1,
                              memory_order_release); /* 奇：写中 */
        s->uid = uid;
        s->known = known;
        s->priv = priv;
        s->gen = gen;
        atomic_store_explicit(&s->seq, atomic_load_explicit(&s->seq, memory_order_relaxed) + 1,
                              memory_order_release); /* 偶：写完 */
        pthread_mutex_unlock(&g_priv_fill_lock);
        return priv;
    }
}


/* ---- uid → 存储类 appop（All files access / 安装器） ----
   Android 11+ 的 All files access 是一个 appop，没有可读的状态文件：AOSP 14+
   已不再写 /data/system/appops.xml，本机 /data/system/appops/ 下只有 discrete/
   与 history/（访问历史，不是 mode）。应用"能装包"同样是一个 appop
   （REQUEST_INSTALL_PACKAGES；系统应用另有同名权限 INSTALL_PACKAGES）。
   唯一可靠来源是 AppOpsService 自身，故按 uid 解析出包名后跑一次
   `cmd appops get <pkg>`（root 直跑，实测约 40ms；不带 op 参数时只输出非默认项，
   一屏以内），一次拿两个结论：
     Uid mode: MANAGE_EXTERNAL_STORAGE: allow   —— uid 模式（共享 uid 的应用）
     MANAGE_EXTERNAL_STORAGE: allow             —— 包模式
     INSTALL_PACKAGES: allow                    —— 覆盖 REQUEST_INSTALL_PACKAGES
                                                   appop 与 INSTALL_PACKAGES 权限
                                                   （两者都以同一子串结尾）
   "default" / "deny" / "ignore" 都不算。

   成功结果缓存 30s，失败冷却 1s，规则重载按 gen 失效。填充锁只保护缓存
   认领和发布，packages.list I/O 与外部命令都在锁外。 */
typedef struct {
    _Atomic uint64_t seq; /* 奇数 = 写者进行中 */
    _Atomic uint64_t gen;
    _Atomic uint64_t stamp_ms;
    _Atomic uid_t uid;
    _Atomic bool known;
    _Atomic bool pending; /* 同槽 uid/gen 存续期间去重；查询中暂不授予能力 */
    _Atomic bool query_ok; /* 失败短冷却，成功保留正常 TTL */
    _Atomic bool manage_external;
    _Atomic bool installer;
} FwPkgExtSlot;

static FwPkgExtSlot g_ext_slots[FW_PKG_CACHE_SIZE];
static pthread_mutex_t g_ext_fill_lock = PTHREAD_MUTEX_INITIALIZER;
static bool (*g_manage_external_probe)(const char* pkg);
static bool (*g_installer_probe)(const char* pkg);

void fw_pkg_set_manage_external_probe(bool (*fn)(const char* pkg)) {
    g_manage_external_probe = fn;
}

void fw_pkg_set_installer_probe(bool (*fn)(const char* pkg)) {
    g_installer_probe = fn;
}

/* 查询预算包括 stdout 和退出确认；超时回收绝不在 FUSE 回调里 waitpid(0)。 */
#define FW_PKG_APPOPS_TIMEOUT_MS 250u
#define FW_PKG_APPOPS_REAP_MS 20u
#define FW_PKG_APPOPS_QUERY_MS (FW_PKG_APPOPS_TIMEOUT_MS - FW_PKG_APPOPS_REAP_MS)
#define FW_PKG_APPOPS_CHILD_MAX 32

typedef struct {
    pid_t pid; /* -1 = 查询线程占用，>0 = 已移交回收线程 */
} AppopsChild;
static AppopsChild g_appops_children[FW_PKG_APPOPS_CHILD_MAX];
static pthread_mutex_t g_appops_child_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_appops_child_cv;
static pthread_t g_appops_reaper;
static bool g_appops_cv_ready;
static bool g_appops_reaper_started;
static bool g_appops_stopping;

static uint64_t ext_clock_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

/* 只收自己移交的 pid，不抢模块的子进程；D 状态子进程也不能卡住回收线程。 */
static void* appops_reaper(void* arg) {
    (void)arg;
    pthread_mutex_lock(&g_appops_child_lock);
    for (;;) {
        bool pending = false;
        for (int i = 0; i < FW_PKG_APPOPS_CHILD_MAX; i++) {
            pid_t pid = g_appops_children[i].pid;
            if (pid <= 0) continue;
            pid_t w = waitpid(pid, nullptr, WNOHANG);
            if (w == pid || (w < 0 && errno == ECHILD)) {
                g_appops_children[i].pid = 0;
            } else {
                pending = true;
            }
        }
        if (g_appops_stopping) break;
        if (!pending) {
            pthread_cond_wait(&g_appops_child_cv, &g_appops_child_lock);
        } else {
            struct timespec until;
            if (clock_gettime(CLOCK_MONOTONIC, &until) != 0) break;
            until.tv_nsec += 20000000;
            if (until.tv_nsec >= 1000000000) {
                until.tv_sec++;
                until.tv_nsec -= 1000000000;
            }
            pthread_cond_timedwait(&g_appops_child_cv, &g_appops_child_lock, &until);
        }
    }
    pthread_mutex_unlock(&g_appops_child_lock);
    return nullptr;
}

/* 先预留固定槽再 spawn：回收不及时最多占满 32 槽，不能无限堆线程或僵尸。 */
static int appops_child_reserve(void) {
    pthread_mutex_lock(&g_appops_child_lock);
    if (g_appops_stopping) goto unavailable;
    if (!g_appops_cv_ready) {
        pthread_condattr_t attr;
        if (pthread_condattr_init(&attr) != 0) goto unavailable;
        int rc = pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
        if (rc == 0) rc = pthread_cond_init(&g_appops_child_cv, &attr);
        pthread_condattr_destroy(&attr);
        if (rc != 0) goto unavailable;
        g_appops_cv_ready = true;
    }
    if (!g_appops_reaper_started) {
        if (pthread_create(&g_appops_reaper, nullptr, appops_reaper, nullptr) != 0)
            goto unavailable;
        g_appops_reaper_started = true;
    }
    for (int i = 0; i < FW_PKG_APPOPS_CHILD_MAX; i++) {
        if (g_appops_children[i].pid == 0) {
            g_appops_children[i].pid = -1;
            pthread_mutex_unlock(&g_appops_child_lock);
            return i;
        }
    }
unavailable:
    pthread_mutex_unlock(&g_appops_child_lock);
    return -1;
}

static void appops_child_finish(int slot, pid_t pid, bool reaped) {
    /* 尚未 wait 到退出的独占子进程才可 kill；已回收 pid 可能被内核复用。 */
    if (pid > 0 && !reaped) {
        kill(pid, SIGKILL);
        /* 总预算预留 20ms 给通常立即退出的 cmd；仍只用 WNOHANG。
           超出这段或 D 状态交后台，绝不退回无限 waitpid。 */
        uint64_t start = ext_clock_ms();
        for (;;) {
            pid_t w = waitpid(pid, nullptr, WNOHANG);
            if (w == pid || (w < 0 && errno == ECHILD)) {
                reaped = true;
                break;
            }
            uint64_t now = ext_clock_ms();
            if (start == 0 || now == 0 || now - start >= FW_PKG_APPOPS_REAP_MS) break;
            poll(nullptr, 0, 1);
        }
    }
    pthread_mutex_lock(&g_appops_child_lock);
    g_appops_children[slot].pid = pid > 0 && !reaped ? pid : 0;
    pthread_cond_signal(&g_appops_child_cv);
    pthread_mutex_unlock(&g_appops_child_lock);
}

/* fuse 请求已停后的终态关闭；join 只等非阻塞回收线程，不等某个子进程。 */
static void appops_children_shutdown(void) {
    pthread_mutex_lock(&g_appops_child_lock);
    g_appops_stopping = true;
    bool started = g_appops_reaper_started;
    pthread_t reaper = g_appops_reaper;
    g_appops_reaper_started = false;
    if (started) pthread_cond_signal(&g_appops_child_cv);
    pthread_mutex_unlock(&g_appops_child_lock);
    if (started) pthread_join(reaper, nullptr);
}

/* 跑 `cmd appops get <pkg>` 并解析输出。
   子进程用 posix_spawn，不经过 shell；stdout 收到管道，stderr 丢 /dev/null。
   预算限制 spawn 返回后的输出/退出等待，不能中断同步 spawn 或此前的查包名。
   返回 false = 命令失败或超时，调用方按短冷却缓存。 */
static bool appops_query_storage_ops(const char* pkg, bool* manage_external_out,
                                     bool* installer_out) {
    *manage_external_out = false;
    *installer_out = false;
    uint64_t start = ext_clock_ms();
    if (start == 0) return false;
    int slot = appops_child_reserve();
    if (slot < 0) return false;
    int fds[2];
    if (pipe2(fds, O_CLOEXEC) != 0) {
        appops_child_finish(slot, -1, true);
        return false;
    }
    /* 只把读端设成非阻塞；子进程 stdout 仍须能正常写完整输出。 */
    int flags = fcntl(fds[0], F_GETFL);
    if (flags < 0 || fcntl(fds[0], F_SETFL, flags | O_NONBLOCK) < 0) {
        close(fds[0]);
        close(fds[1]);
        appops_child_finish(slot, -1, true);
        return false;
    }
    posix_spawn_file_actions_t fa;
    if (posix_spawn_file_actions_init(&fa) != 0) {
        close(fds[0]);
        close(fds[1]);
        appops_child_finish(slot, -1, true);
        return false;
    }
    int rc = posix_spawn_file_actions_adddup2(&fa, fds[1], STDOUT_FILENO);
    if (rc == 0)
        rc = posix_spawn_file_actions_addopen(&fa, STDERR_FILENO, "/dev/null", O_WRONLY, 0);
    if (rc == 0) rc = posix_spawn_file_actions_addclose(&fa, fds[0]);
    if (rc == 0) rc = posix_spawn_file_actions_addclose(&fa, fds[1]);
    char* argv[] = {(char*)"cmd", (char*)"appops", (char*)"get", (char*)pkg, nullptr};
    pid_t pid = -1;
    if (rc == 0) rc = posix_spawn(&pid, "/system/bin/cmd", &fa, nullptr, argv, environ);
    posix_spawn_file_actions_destroy(&fa);
    close(fds[1]);
    if (rc != 0) {
        close(fds[0]);
        appops_child_finish(slot, -1, true);
        return false;
    }
    char buf[4096];
    size_t used = 0;
    bool eof = false;
    bool reaped = false;
    bool ok = false;
    int status = 0;
    for (;;) {
        uint64_t now = ext_clock_ms();
        if (now == 0 || now - start >= FW_PKG_APPOPS_QUERY_MS) break;
        while (!eof) {
            /* 持续输出也必须服从总预算，不能仅在 poll 前检查。 */
            now = ext_clock_ms();
            if (now == 0 || now - start >= FW_PKG_APPOPS_QUERY_MS) goto done;
            char tmp[256];
            ssize_t n = read(fds[0], tmp, sizeof tmp);
            if (n > 0) {
                size_t take = (size_t)n;
                if (take > sizeof(buf) - 1 - used) take = sizeof(buf) - 1 - used;
                memcpy(buf + used, tmp, take);
                used += take;
            } else if (n == 0) {
                eof = true;
            } else if (errno == EINTR) {
                continue;
            } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            } else {
                goto done;
            }
        }
        if (!reaped) {
            pid_t w = waitpid(pid, &status, WNOHANG);
            if (w == pid) reaped = true;
            else if (w < 0 && errno != EINTR) {
                if (errno == ECHILD) reaped = true;
                goto done;
            }
        }
        if (eof && reaped) {
            ok = WIFEXITED(status) && WEXITSTATUS(status) == 0;
            break;
        }
        now = ext_clock_ms();
        if (now == 0 || now - start >= FW_PKG_APPOPS_QUERY_MS) break;
        int remaining = (int)(FW_PKG_APPOPS_QUERY_MS - (now - start));
        int interval = remaining < 5 ? remaining : 5;
        struct pollfd pfd = {.fd = fds[0], .events = POLLIN};
        /* EOF 后不能 poll 一个一直 HUP 的 fd 忙转；只按预算等待子进程退出。 */
        rc = poll(eof ? nullptr : &pfd, eof ? 0 : 1, interval);
        if (rc < 0 && errno != EINTR) break;
        if (rc > 0 && (pfd.revents & (POLLERR | POLLNVAL))) break;
    }
done:
    close(fds[0]);
    appops_child_finish(slot, pid, reaped);
    if (!ok) return false; /* 部分 allow 输出不构成授权，必须 EOF + 正常退出。 */
    buf[used] = '\0';
    *manage_external_out = strstr(buf, "MANAGE_EXTERNAL_STORAGE: allow") != nullptr;
    *installer_out = strstr(buf, "INSTALL_PACKAGES: allow") != nullptr;
    return true;
}

/* 结果有效期：appops 模式是运行期可变的（用户在设置里随时授予/撤销 All files
   access，应用升级也可能改写），只靠 g_gen 失效会让 daemon 一直用旧结论直到配置
   重载或重启。取 30s：一次查询约 40ms，最长 30s 内自愈，代价可忽略。 */
#define FW_PKG_EXT_TTL_MS 30000u
#define FW_PKG_EXT_FAILURE_TTL_MS 1000u

/* 命中槽位即返回；未命中/过期则解析包名并查一次 appops（两个 op 共用一次查询），
   写回槽位后再返回。两个结论同进同出，避免为第二个 op 再 fork 一次。 */
/* 读取完整原子快照后再核 seq，避免并发写入的字段拼成另一个 uid 的授权。 */
static bool ext_cached(FwPkgExtSlot* s, uid_t uid, uint64_t gen, uint64_t now,
                       bool* manage_external_out, bool* installer_out) {
    uint64_t seq = atomic_load_explicit(&s->seq, memory_order_acquire);
    if (seq & 1) return false;
    uint64_t slot_gen = s->gen;
    uid_t slot_uid = s->uid;
    uint64_t stamp = s->stamp_ms;
    bool pending = s->pending;
    bool known = s->known;
    bool query_ok = s->query_ok;
    bool manage = s->manage_external;
    bool installer = s->installer;
    if (seq != atomic_load_explicit(&s->seq, memory_order_acquire) ||
        slot_gen != gen || slot_uid != uid) return false;
    if (pending) {
        *manage_external_out = false;
        *installer_out = false;
        return true;
    }
    uint64_t ttl = query_ok ? FW_PKG_EXT_TTL_MS : FW_PKG_EXT_FAILURE_TTL_MS;
    if (!known || now < stamp || now - stamp >= ttl) return false;
    *manage_external_out = manage;
    *installer_out = installer;
    return true;
}

static void ext_lookup(uid_t uid, bool* manage_external_out, bool* installer_out) {
    FwPkgExtSlot* s = &g_ext_slots[uid % FW_PKG_CACHE_SIZE];
    uint64_t gen = atomic_load_explicit(&g_gen, memory_order_acquire);
    if (ext_cached(s, uid, gen, ext_clock_ms(), manage_external_out, installer_out)) return;
    pthread_mutex_lock(&g_ext_fill_lock);
    gen = atomic_load_explicit(&g_gen, memory_order_acquire);
    /* 同 uid 的并发 miss 在锁内复查；进行中的查询不阻塞其它 FUSE worker。 */
    if (ext_cached(s, uid, gen, ext_clock_ms(), manage_external_out, installer_out)) {
        pthread_mutex_unlock(&g_ext_fill_lock);
        return;
    }
    uint64_t seq = atomic_load_explicit(&s->seq, memory_order_relaxed);
    atomic_store_explicit(&s->seq, seq + 1, memory_order_release);
    s->uid = uid;
    s->gen = gen;
    s->known = false;
    s->pending = true;
    s->query_ok = false;
    s->manage_external = false;
    s->installer = false;
    atomic_store_explicit(&s->seq, seq + 2, memory_order_release);
    uint64_t claim = seq + 2;
    pthread_mutex_unlock(&g_ext_fill_lock);

    /* packages.list I/O 与外部命令全部在全局锁外，避免跨 uid 放大等待。 */
    char pkg[FW_PKG_NAME_MAX];
    bool resolved = resolve_sys_pkg_from_packagelist(uid, pkg, sizeof pkg, nullptr, 0);
    bool manage_external = false;
    bool installer = false;
    bool done = resolved;
    if (resolved) {
        if (g_manage_external_probe || g_installer_probe) {
            manage_external = g_manage_external_probe && g_manage_external_probe(pkg);
            installer = g_installer_probe && g_installer_probe(pkg);
        } else {
            done = appops_query_storage_ops(pkg, &manage_external, &installer);
        }
    }
    if (!done) manage_external = installer = false;
    pthread_mutex_lock(&g_ext_fill_lock);
    bool current = gen == atomic_load_explicit(&g_gen, memory_order_acquire);
    /* 哈希碰撞或重载的新查询拥有该槽后，旧完成不能覆盖新授权。 */
    if (current && s->uid == uid && s->gen == gen && s->seq == claim) {
        atomic_store_explicit(&s->seq, claim + 1, memory_order_release);
        s->known = true;
        s->pending = false;
        s->query_ok = done;
        s->manage_external = manage_external;
        s->installer = installer;
        s->stamp_ms = ext_clock_ms();
        atomic_store_explicit(&s->seq, claim + 2, memory_order_release);
    }
    pthread_mutex_unlock(&g_ext_fill_lock);
    *manage_external_out = current && manage_external;
    *installer_out = current && installer;
}

bool fw_pkg_manages_external(uid_t uid) {
    bool manage_external = false;
    bool installer = false;
    ext_lookup(uid, &manage_external, &installer);
    return manage_external;
}

bool fw_pkg_can_install_packages(uid_t uid) {
    bool manage_external = false;
    bool installer = false;
    ext_lookup(uid, &manage_external, &installer);
    return installer;
}

/* ---- 包名 → uid（FUSE 事件通道的白名单自动解析用） ----
   与上面两条缓存三足鼎立、互不嵌套：本组只用 g_pkguid_fill_lock，且函数体内
   只解析 packages.list（fopen/fgets，不取任何锁），**不**调用 resolve_uncached
   → g_fill_lock、也不调用 fw_pkg_is_privileged → g_priv_fill_lock。反过来那两条
   路径完全不会进本函数，故不存在「持一把锁再取另一把」的环。 */
typedef struct {
    uint64_t gen;
    char pkg[FW_PKG_NAME_MAX];
    bool known; /* packages.list 有该包名的行 */
    uid_t uid;
} FwPkgUidSlot;

#define FW_PKG_UID_SLOTS 8 /* 只有固定的两个 MediaProvider 包名会来查，留余量 */

static FwPkgUidSlot g_pkguid_slots[FW_PKG_UID_SLOTS];
static pthread_mutex_t g_pkguid_fill_lock = PTHREAD_MUTEX_INITIALIZER;

/* 按包名扫 packages.list 取 uid（"pkg uid ..."）。找不到/打不开返回 false。 */
static bool resolve_uid_from_packagelist(const char* pkg, uid_t* out) {
    FILE* fp = open_packagelist();
    if (!fp) return false;
    bool found = false;
    char line[1024];
    while (fgets(line, sizeof line, fp)) {
        char name[FW_PKG_NAME_MAX];
        unsigned int puid = 0;
        if (sscanf(line, "%127s %u", name, &puid) == 2 && strcmp(name, pkg) == 0) {
            *out = (uid_t)puid;
            found = true;
            break;
        }
    }
    fclose(fp);
    return found;
}

bool fw_pkg_uid_for_package(const char* pkg, uid_t* out) {
    if (!pkg || !pkg[0]) return false;
    uint64_t gen = atomic_load_explicit(&g_gen, memory_order_acquire);
    pthread_mutex_lock(&g_pkguid_fill_lock);
    int use = -1;
    for (int i = 0; i < FW_PKG_UID_SLOTS && use < 0; i++) {
        if (g_pkguid_slots[i].gen == gen && strcmp(g_pkguid_slots[i].pkg, pkg) == 0) use = i;
    }
    if (use < 0) {
        /* 未命中：先找本代外的空槽（代际失效即空槽），都被占则用 0 号 */
        use = 0;
        for (int i = 0; i < FW_PKG_UID_SLOTS; i++) {
            if (g_pkguid_slots[i].gen != gen) {
                use = i;
                break;
            }
        }
        FwPkgUidSlot* s = &g_pkguid_slots[use];
        snprintf(s->pkg, sizeof s->pkg, "%s", pkg);
        s->known = resolve_uid_from_packagelist(pkg, &s->uid); /* 失败也缓存，直到下次重载 */
        s->gen = gen;
    }
    bool known = g_pkguid_slots[use].known;
    uid_t uid = g_pkguid_slots[use].uid;
    pthread_mutex_unlock(&g_pkguid_fill_lock);
    if (known && out) *out = uid;
    return known;
}

/* 共享 uid（android:sharedUserId / 同进程宿主）下同一 uid 挂着多个包，uid.map
   与 packages.list 都只能给出其中一个。包身份因此必须取自**进程自身**：zygote
   fork 出的应用进程 cmdline 就是它的包名，兄弟包各不相同。只有该名字确属本 uid
   名下已安装的包时才采信，其余情形（非应用进程、cmdline 被改）一律回退，
   避免把 /proc 里的任意字符串当包名参与白名单与应用段匹配。 */
static bool resolve_from_pid(uid_t uid, pid_t tid, char* out, size_t size) {
    if (tid <= 0) return false;
    /* /proc/<tid>/status 的 Tgid：线程 id 亦可用，但 cmdline 只有主线程保证 */
    pid_t main_pid = tid;
    char status_path[64];
    snprintf(status_path, sizeof status_path, "/proc/%d/status", (int)tid);
    FILE* fp = fopen(status_path, "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof line, fp)) {
            if (strncmp(line, "Tgid:", 5) == 0) {
                main_pid = (pid_t)atoi(line + 5);
                break;
            }
        }
        fclose(fp);
    }
    char pkg[FW_PKG_NAME_MAX] = {0};
    if (!proc_get_cmdline(main_pid, pkg, sizeof pkg)) return false;
    char* colon = strchr(pkg, ':');
    if (colon) *colon = '\0';
    if (strlen(pkg) < 3 || strstr(pkg, "zygote") || strstr(pkg, "<pre-")) return false;
    uid_t pkg_uid = 0;
    if (!fw_pkg_uid_for_package(pkg, &pkg_uid) || pkg_uid != uid) return false;
    snprintf(out, size, "%s", pkg);
    return true;
}

/* 取展示包名并判定其可否用于段匹配（等价模块 br_get_app_cfg 的不可解析分支：
   过短 / zygote / <pre- 一律只能命中 GLOBAL） */
static void resolve_uncached(uid_t uid, pid_t tid, char* out, size_t size, bool* lookup_ok) {
    char pkg[FW_PKG_NAME_MAX] = {0};
    const char* mapped = uid_map_lookup(g_uid_maps, g_uid_map_count, uid);
    if (mapped) {
        snprintf(pkg, sizeof pkg, "%s", mapped);
    } else if (uid < NSP_SYSTEM_APP_UID_MIN) {
        /* 系统共享 uid（1000 等）在 uid.map 里通常没有条目（injector 只在应用
           REPORT 时写入），而 FUSE 请求侧拿不到 caller pid（q->pid 是 daemon
           伪造的连接标识），cmdline 回退也不可用——实机验证：系统应用的显式
           应用段（[com.android.settings] 等）永不命中，而 GLOBAL/类别段正常。
           /data/system/packages.list 的 "pkg uid ..." 行覆盖全部已装应用，
           按 uid 取第一个匹配包名。共享 uid（android.uid.system 下多个包）只取
           其一，其余包的应用段规则要生效需等 uid.map 随 REPORT 增长补上；
           伪包 "system" 的 SYSTEM_APPS 类别层判定不受影响。 */
        resolve_sys_pkg_from_packagelist(uid, pkg, sizeof pkg, nullptr, 0);
        if (pkg[0] == '\0' && tid > 0) {
            /* packages.list 不可读（非 Android 环境）时退回 cmdline */
            goto cmdline_fallback;
        }
    } else if (tid > 0) {
      cmdline_fallback:;
        /* 主线程 id 取自 /proc/<tid>/status 的 Tgid：应用线程的 cmdline 就是包名，
           但只保证主线程可读（zygote fork 后线程组细节），故先定位 Tgid */
        pid_t main_pid = tid;
        char status_path[64];
        snprintf(status_path, sizeof status_path, "/proc/%d/status", tid);
        FILE* fp = fopen(status_path, "r");
        if (fp) {
            char line[256];
            while (fgets(line, sizeof line, fp)) {
                if (strncmp(line, "Tgid:", 5) == 0) {
                    main_pid = (pid_t)atoi(line + 5);
                    break;
                }
            }
            fclose(fp);
        }
        proc_get_cmdline(main_pid, pkg, sizeof pkg);
    }
    /* 多开/隔离进程形如 <pkg>:<suffix>：段匹配与展示都取基础包名 */
    char* colon = strchr(pkg, ':');
    if (colon) *colon = '\0';
    if (pkg[0] == '\0') snprintf(pkg, sizeof pkg, "unknown");

    *lookup_ok = !(strlen(pkg) < 3 || strstr(pkg, "zygote") || strstr(pkg, "<pre-"));
    snprintf(out, size, "%s", pkg);
}

bool fw_pkg_resolve(uid_t uid, pid_t tid, char* out, size_t size) {
    if (!out || size == 0) return false;
    if (uid < NSP_SYSTEM_APP_UID_MIN) {
        snprintf(out, size, "system");
        return false; /* system 伪包只参与 SYSTEM_APPS 类别层，不属于应用段 */
    }
    return fw_pkg_resolve_exact(uid, tid, out, size);
}

bool fw_pkg_resolve_exact(uid_t uid, pid_t tid, char* out, size_t size) {
    if (!out || size == 0) return false;
    /* 有真实调用方 pid 时按进程自身解析，且**不进 uid 槽缓存**：同一 uid 下的
       多个包各有各的进程，缓存按 uid 存会让先到的包顶替后来者。 */
    if (resolve_from_pid(uid, tid, out, size)) return true;
    FwPkgSlot* s = &g_slots[uid % FW_PKG_CACHE_SIZE];
    uint64_t gen = atomic_load_explicit(&g_gen, memory_order_acquire);
    for (;;) {
        uint64_t s1 = atomic_load_explicit(&s->seq, memory_order_acquire);
        if (s1 & 1) continue; /* 填充进行中：重试 */
        uid_t suid = s->uid;
        uint64_t sgen = s->gen;
        bool sok = s->lookup_ok;
        char spkg[FW_PKG_NAME_MAX];
        memcpy(spkg, s->pkg, sizeof spkg);
        uint64_t s2 = atomic_load_explicit(&s->seq, memory_order_acquire);
        if (s1 != s2) continue; /* 快照撕裂：重试 */
        if (suid == uid && sgen == gen) {
            snprintf(out, size, "%s", spkg);
            return sok;
        }
        break;
    }

    char pkg[FW_PKG_NAME_MAX];
    bool lookup_ok = false;
    resolve_uncached(uid, tid, pkg, sizeof pkg, &lookup_ok);

    pthread_mutex_lock(&g_fill_lock);
    uint64_t seq = atomic_load_explicit(&s->seq, memory_order_relaxed);
    atomic_store_explicit(&s->seq, seq + 1, memory_order_release);
    s->uid = uid;
    s->gen = gen;
    s->lookup_ok = lookup_ok;
    memcpy(s->pkg, pkg, sizeof s->pkg);
    atomic_store_explicit(&s->seq, seq + 2, memory_order_release);
    pthread_mutex_unlock(&g_fill_lock);

    snprintf(out, size, "%s", pkg);
    return lookup_ok;
}
