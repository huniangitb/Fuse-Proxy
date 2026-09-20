/* fuse_thread_naming.c — libfuse worker 线程命名
 *
 * 背景：libfuse 3.x 的 fuse_loop_mt 在库内部 pthread_create worker，
 * 无命名钩子，worker 默认继承主线程 comm（fuse_daemon），top -H /
 * 崩溃 TID 归因时与主线程混淆。主线程名不能改（service.sh 的
 * pgrep -x / killall 与 rule_server 的 find_proc_pid 都按 comm 发现进程）。
 *
 * 做法：本文件定义全局 pthread_create 截持（仅编入 fuse_daemon 二进制）：
 *   - 动态链接（GNU 系统 libfuse3.so）：主程序全局符号天然优先于共享库
 *     PLT 解析（配合 -Wl,--export-dynamic），libfuse 的调用落到本包装器；
 *   - 静态链接（Android fuse3.a）：归档成员的未定义 pthread_create 在链接
 *     期按顺序解析到本定义（本目标对象排在归档之前）。
 * 包装器经蹦床（trampoline）先把新线程命名为 fuse_worker 再调真正入口；
 * 本进程自有线程（nsp_comm/nsp_modmon/...）入口首行即覆盖为语义名，
 * 无缝替换。第三方库线程（如 libcurl 内部）若从不自命名，会显示为
 * fuse_worker——诊断时按 TID 回调栈甄别，不作精确区分。
 *
 * 开销：每次建线程多一次 malloc/free + 一次 setname 系统调用（建线程本身
 * 已是重操作，可忽略）；setname 在新线程内执行，无 detached 竞态。
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <pthread.h>
#include <stdlib.h>
#include <dlfcn.h>

/* 真实 pthread_create：首次调用时经 RTLD_NEXT 解析（dlsym 本身不建线程，
 * 懒初始化安全；解析失败直接返回 EAGAIN，调用方按建线程失败处理） */
static int (*s_real_pthread_create)(pthread_t*, const pthread_attr_t*, void* (*)(void*),
                                    void*) = NULL;

typedef struct {
    void* (*start)(void*);
    void* arg;
} FuseThreadTrampoline;

static void* fuse_thread_entry(void* raw) {
    FuseThreadTrampoline* t = raw;
    void* (*start)(void*) = t->start;
    void* arg = t->arg;
    free(t);
    /* 默认名：libfuse worker 保留此名；自有线程入口随即覆盖 */
    pthread_setname_np(pthread_self(), "fuse_worker");
    return start(arg);
}

int pthread_create(pthread_t* thread, const pthread_attr_t* attr, void* (*start_routine)(void*),
                   void* arg) {
    if (!s_real_pthread_create) {
        void* sym = dlsym(RTLD_NEXT, "pthread_create");
        if (!sym) return 11; /* EAGAIN：调用方走建线程失败分支 */
        s_real_pthread_create = sym;
    }
    if (!start_routine) return 22; /* EINVAL：与 glibc 语义对齐 */
    FuseThreadTrampoline* t = malloc(sizeof *t);
    if (!t) return 11; /* EAGAIN */
    t->start = start_routine;
    t->arg = arg;
    int rc = s_real_pthread_create(thread, attr, fuse_thread_entry, t);
    if (rc != 0) free(t);
    return rc;
}
