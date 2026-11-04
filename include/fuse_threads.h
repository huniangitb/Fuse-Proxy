#ifndef NSP_FUSE_THREADS_H
#define NSP_FUSE_THREADS_H
/*
 * fuse_threads.h — FUSE worker 线程数的默认取值
 *
 * libfuse 的多线程 loop 自身默认 10 个 worker；项目长期固定 2 个。2 个 worker
 * 在「单个应用冷启动」这种成百上千次并发 getattr/open/read 的窗口里容易排队，
 * 而按核数一把梭（8 核给 8 个）在 4 核低端机上是让线程互相抢 CPU：同一条 FUSE
 * 连接上的请求并没有变多，多出来的只是调度开销。
 *
 * 折中取一半、下限 2、上限 8：4 核 → 2、6 核 → 3、8 核 → 4、16 核 → 8。
 * 显式值仍由 --fuse-threads 覆盖（0=单线程，-1=libfuse 默认 10）。
 */
static inline int nsp_default_fuse_threads(int ncpu) {
    if (ncpu <= 0) return 2;
    int half = ncpu / 2;
    if (half < 2) half = 2;
    if (half > 8) half = 8;
    return half;
}
#endif /* NSP_FUSE_THREADS_H */
