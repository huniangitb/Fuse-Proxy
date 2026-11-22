#ifndef NSP_FUSE_THREADS_H
#define NSP_FUSE_THREADS_H
/*
 * fuse_threads.h — FUSE worker 线程数的默认取值
 *
 * 全局连接服务多个应用，默认按核数保留并发调度余量：
 * 下限 4、上限 16，4 核 → 4、8 核 → 8、16 核及以上 → 16。
 * 这只调整并发默认值，不能代替消除阻塞回调或回入。
 * 显式值仍由 --fuse-threads 覆盖（0=单线程，-1=libfuse 默认 10）。
 */
static inline int nsp_default_fuse_threads(int ncpu) {
    if (ncpu < 4) return 4;
    if (ncpu > 16) return 16;
    return ncpu;
}
#endif /* NSP_FUSE_THREADS_H */
