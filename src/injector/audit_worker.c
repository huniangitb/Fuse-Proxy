/* 配置重载后的运行中应用对账 worker：语义见 audit_worker.h 与 docs/architecture.md。 */
#include "audit_worker.h"

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <string.h>
#include <time.h>

#include "mount_ops.h"
#include "inject_target.h" /* audit_tracked_apps / audit_and_remount_specific_apps /
                                  audit_running_apps */
#include "injector.h"      /* inject_is_global_replace / inject_restore_nontarget */

#define AUDIT_IDLE_MS 200

/* 待处理（已合并）的一轮：变更集合 + 是否升级成全量。 */
typedef struct {
    bool reset;
    int count;
    ChangedPkg items[NSP_AUDIT_MAX_CHANGED];
} AuditJob;

static pthread_mutex_t g_aw_mu = PTHREAD_MUTEX_INITIALIZER;
/* 空闲等待只有 200ms：墙钟被改最多让 worker 早退/晚退一会儿，没有正确性影响，所以
   直接用默认时钟的静态初始化。不要去 pthread_cond_init 一个已经静态初始化的条件
   变量（那是未定义行为），也不留「时钟设置失败」这种半初始化分支。 */
static pthread_cond_t g_aw_cv = PTHREAD_COND_INITIALIZER;

static AuditJob g_aw_job;     /* 受 g_aw_mu 保护 */
static bool g_aw_pending;     /* 有未跑的一轮（含 worker 正在跑时新到的） */
static bool g_aw_running;     /* 已有 worker 线程 */
static bool g_aw_stopping;
/* 正在执行对账的 worker 数（恒 0 或 1，测试用来证明没有并发/线程泄漏） */
static _Atomic int g_aw_active;

/* 合并一次请求（调用方持锁）：同一 pkg/user_id 去重；集合溢出或 reset 一律升级。 */
static void audit_merge_locked(const ChangedPkg* changed, int count, bool global_reset) {
    if (global_reset) {
        g_aw_job.reset = true;
        return;
    }
    if (!changed || count <= 0) return;
    /* 已经升级成全量也继续收条目：全量扫描只走 tracked 表，运行中但未追踪的应用
       要靠具体条目那一轮才碰得到，提前丢掉等于漏对账（worker 会两路都跑）。 */
    for (int i = 0; i < count; i++) {
        const char* pkg = changed[i].pkg_name;
        bool dup = false;
        for (int k = 0; k < g_aw_job.count; k++) {
            if (g_aw_job.items[k].user_id == changed[i].user_id &&
                strcmp(g_aw_job.items[k].pkg_name, pkg) == 0) {
                dup = true;
                break;
            }
        }
        if (dup) continue;
        if (g_aw_job.count >= NSP_AUDIT_MAX_CHANGED) {
            /* 放不下了：升级成全量审计。超出上限的条目无法逐条送达（固定上限是
               入队的代价），由全量扫描兜住已追踪的应用；未追踪的运行中应用留给
               下一次重载或启动扫描。 */
            g_aw_job.reset = true;
            g_aw_job.count = 0;
            return;
        }
        ChangedPkg* dst = &g_aw_job.items[g_aw_job.count++];
        memset(dst, 0, sizeof *dst);
        strncpy(dst->pkg_name, pkg, sizeof(dst->pkg_name) - 1);
        dst->user_id = changed[i].user_id;
    }
}

/* 真正跑一轮对账。粒度在**这一刻**按当前注入方法重选：排队期间模式可能被切走，
 * 用入队时的模式会漏挂/漏还原。 */
static void audit_run_job(AuditJob* job) {
    if (inject_is_global_replace() || inject_restore_nontarget()) {
        /* v2/v3：全局替换 + 还原策略，保持原有审计粒度。先按具体变更重挂（精确），
           再做 tracked 全量扫描（兜住其余）——两路可能同时存在：排队期间既有整体
           变化又有具体变更，只跑后者会漏掉已追踪应用。 */
        if (job->count > 0) {
            audit_and_remount_specific_apps(job->items, job->count);
        }
        if (job->reset) {
            audit_tracked_apps();
        }
        return;
    }
    /* v1（逐应用挂载）：每次重载都对运行中应用做一次全量对账（该挂的挂上、
       该卸的卸掉），与旧行为一致。 */
    audit_running_apps();
}

static void* audit_worker(void* arg) {
    (void)arg;
    for (;;) {
        pthread_mutex_lock(&g_aw_mu);
        while (!g_aw_pending && !g_aw_stopping) {
            struct timespec deadline;
            clock_gettime(CLOCK_REALTIME, &deadline);
            deadline.tv_nsec += (long)AUDIT_IDLE_MS * 1000000L;
            if (deadline.tv_nsec >= 1000000000L) {
                deadline.tv_sec += 1;
                deadline.tv_nsec -= 1000000000L;
            }
            /* 空闲到期 = 这一阵子没新请求：worker 自己退出，不常驻 */
            if (pthread_cond_timedwait(&g_aw_cv, &g_aw_mu, &deadline) == ETIMEDOUT) break;
        }
        if (!g_aw_pending) { /* 空闲到期，或 stopping 且已无待处理请求 */
            g_aw_running = false;
            pthread_cond_broadcast(&g_aw_cv);
            pthread_mutex_unlock(&g_aw_mu);
            return NULL;
        }
        AuditJob job = g_aw_job; /* 私有副本：锁外跑，期间新请求改的是 g_aw_job */
        memset(&g_aw_job, 0, sizeof g_aw_job);
        g_aw_pending = false;
        pthread_mutex_unlock(&g_aw_mu);
        atomic_fetch_add_explicit(&g_aw_active, 1, memory_order_acq_rel);
        /* 一整轮对账独占挂载视图：与维护 worker（恢复/重挂/媒体）、事件循环的重试
           派发互斥——同时改挂载会「刚挂上又被清理」，同一次进程遍历也会被两边各改一遍。
           事件循环侧只用 trylock，故这里持锁不会把循环按在等锁上。 */
        mount_ops_begin();
        audit_run_job(&job); /* items 只被读（fnmatch 匹配），私有副本可以传非 const */
        mount_ops_end();
        atomic_fetch_sub_explicit(&g_aw_active, 1, memory_order_acq_rel);
    }
}

void nsp_audit_request(const ChangedPkg* changed, int count, bool global_reset) {
    bool spawn = false;
    pthread_mutex_lock(&g_aw_mu);
    if (g_aw_stopping) {
        pthread_mutex_unlock(&g_aw_mu);
        return;
    }
    audit_merge_locked(changed, count, global_reset);
    g_aw_pending = true;
    if (!g_aw_running) {
        g_aw_running = true;
        spawn = true;
    }
    pthread_cond_signal(&g_aw_cv);
    pthread_mutex_unlock(&g_aw_mu);
    if (!spawn) return; /* 已有 worker：请求已并入它的下一轮 */
    pthread_attr_t attr;
    pthread_t tid;
    if (pthread_attr_init(&attr) != 0) {
        spawn = false;
    } else {
        (void)pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        spawn = pthread_create(&tid, &attr, audit_worker, NULL) == 0;
        pthread_attr_destroy(&attr);
    }
    if (!spawn) {
        /* 起不来：绝不在调用线程上同步跑对账。把 running 放回去但保留 pending——
           下一请求会重新拉起 worker 把这一轮跑掉（并发并入的变更不会凭空消失）。
           broadcast 不可省：此刻可能已经有人在 nsp_audit_shutdown 里等 running
           归零，只清标志不唤醒就是永久挂住。 */
        pthread_mutex_lock(&g_aw_mu);
        g_aw_running = false;
        pthread_cond_broadcast(&g_aw_cv);
        pthread_mutex_unlock(&g_aw_mu);
    }
}

bool nsp_audit_active(void) {
    pthread_mutex_lock(&g_aw_mu);
    const bool running = g_aw_running;
    pthread_mutex_unlock(&g_aw_mu);
    return running || atomic_load_explicit(&g_aw_active, memory_order_acquire) > 0;
}

void nsp_audit_shutdown(void) {
    pthread_mutex_lock(&g_aw_mu);
    g_aw_stopping = true;
    /* 未开始的那一轮丢弃（进程随后退出清理，下一次启动全量扫描补上）；
       正在跑的那一轮等它结束，不取消。 */
    if (g_aw_pending) {
        g_aw_pending = false;
        memset(&g_aw_job, 0, sizeof g_aw_job);
    }
    pthread_cond_broadcast(&g_aw_cv);
    while (g_aw_running) {
        if (pthread_cond_wait(&g_aw_cv, &g_aw_mu) != 0) break;
    }
    pthread_mutex_unlock(&g_aw_mu);
}
