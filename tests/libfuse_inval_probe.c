/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * libfuse_inval_probe.c — 验证 libfuse 分支新增的 dentry 级失效 API
 *
 * 被测接口：fuse_invalidate_path_entry()（subprojects/libfuse 分支追加，
 * 导出版本节点 FUSE_3.19）。它与既有 fuse_invalidate_path()（inode 级）
 * 的区别：inode 级只丢属性/数据缓存，dentry 仍在；entry 级把内核 dentry
 * 一并丢掉，下次访问必然重新 lookup()——这才是「让某个文件/目录的
 * FUSE 目录缓存立即失效」所需要的语义。
 *
 * 探针挂一个极简文件系统（根目录下单个文件 /f，其存在性由全局标志
 * g_present 控制），用长超时（60s）把内核缓存钉住，于是：
 *   A. 正缓存：文件消失后 stat 仍成功（证明缓存生效）→ 失效 → stat ENOENT
 *   B. 负缓存：文件出现后 stat 仍 ENOENT（证明负缓存生效）→ 失效 → stat 成功
 * B 正是 FTP「上传后立即 open」的场景。
 *
 * 用法：libfuse_inval_probe <挂载点>；全部检查通过返回 0，否则返回 1。
 */
#define FUSE_USE_VERSION 317

#include <errno.h>
#include <fuse.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* 文件 /f 是否「存在」。测试线程翻转它模拟后端变化（如 FTP 远端增删）。 */
static volatile int g_present = 1;
static struct fuse* g_fuse;

static int t_getattr(const char* path, struct stat* st, struct fuse_file_info* fi) {
    (void)fi;
    memset(st, 0, sizeof *st);
    if (strcmp(path, "/") == 0) {
        st->st_mode = S_IFDIR | 0755;
        st->st_nlink = 2;
        return 0;
    }
    if (strcmp(path, "/f") == 0 && g_present) {
        st->st_mode = S_IFREG | 0644;
        st->st_nlink = 1;
        st->st_size = 1;
        return 0;
    }
    return -ENOENT;
}

static int t_readdir(const char* path, void* buf, fuse_fill_dir_t filler, off_t off,
                     struct fuse_file_info* fi, enum fuse_readdir_flags flags) {
    (void)off;
    (void)fi;
    (void)flags;
    if (strcmp(path, "/") != 0) return -ENOENT;
    filler(buf, ".", NULL, 0, 0);
    filler(buf, "..", NULL, 0, 0);
    if (g_present) filler(buf, "f", NULL, 0, 0);
    return 0;
}

static const struct fuse_operations t_ops = {
    .getattr = t_getattr,
    .readdir = t_readdir,
};

static void* loop_thread(void* arg) {
    (void)arg;
    fuse_loop_mt(g_fuse, NULL); /* config=NULL → 默认（多线程） */
    return NULL;
}

/* lstat 是否成功（成功即「内核认为该文件存在」） */
static int exists(const char* p) {
    struct stat st;
    return lstat(p, &st) == 0;
}

static int g_fail;

static void check(int cond, const char* what) {
    printf("  [%s] %s\n", cond ? "PASS" : "FAIL", what);
    if (!cond) g_fail = 1;
}

/* 等待挂载就绪：首次 lookup 成功即视为可访问 */
static int wait_ready(const char* target) {
    for (int i = 0; i < 200; i++) {
        if (exists(target)) return 1;
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 10 * 1000 * 1000};
        nanosleep(&ts, NULL);
    }
    return 0;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "用法：%s <挂载点>\n", argv[0]);
        return 2;
    }
    const char* mnt = argv[1];
    char target[4096];
    if (snprintf(target, sizeof target, "%s/f", mnt) >= (int)sizeof target) {
        fprintf(stderr, "挂载点过长\n");
        return 2;
    }

    /* 超时全部拉到 60s：缓存一旦建立就不会自行过期，故观察到的变化
       只可能来自显式失效，不可能来自超时——这是本探针的证明力所在。 */
    struct fuse_args args = FUSE_ARGS_INIT(0, NULL);
    fuse_opt_add_arg(&args, "libfuse_inval_probe");
    fuse_opt_add_arg(&args, "-o");
    fuse_opt_add_arg(&args,
                     "attr_timeout=60,entry_timeout=60,negative_timeout=60,fsname=invprobe");

    g_fuse = fuse_new(&args, &t_ops, sizeof t_ops, NULL);
    if (!g_fuse) {
        fprintf(stderr, "fuse_new 失败\n");
        return 2;
    }
    if (fuse_mount(g_fuse, mnt) != 0) {
        fprintf(stderr, "fuse_mount 失败（%s）\n", mnt);
        fuse_destroy(g_fuse);
        return 2;
    }

    pthread_t th;
    if (pthread_create(&th, NULL, loop_thread, NULL) != 0) {
        fprintf(stderr, "pthread_create 失败\n");
        fuse_unmount(g_fuse);
        fuse_destroy(g_fuse);
        return 2;
    }

    if (!wait_ready(target)) {
        fprintf(stderr, "挂载未就绪\n");
        fuse_exit(g_fuse);
        pthread_join(th, NULL);
        fuse_unmount(g_fuse);
        fuse_destroy(g_fuse);
        return 2;
    }

    printf("A. 正 dentry：文件消失后立即失效\n");
    check(exists(target), "A1 初始 stat 成功（缓存已建立）");
    g_present = 0;
    check(exists(target), "A2 文件消失后 stat 仍成功（证明内核缓存生效）");
    int rc = fuse_invalidate_path_entry(g_fuse, "/f");
    check(rc == 0, "A3 fuse_invalidate_path_entry 返回 0");
    check(!exists(target), "A4 失效后 stat 立即 ENOENT（dentry 已丢）");

    printf("B. 负 dentry：文件出现后立即失效（FTP 上传后立即 open 的场景）\n");
    g_present = 0;
    (void)exists(target); /* 触发一次 lookup，负 dentry 入缓存 */
    g_present = 1;
    check(!exists(target), "B1 文件出现后 stat 仍 ENOENT（证明负缓存生效）");
    rc = fuse_invalidate_path_entry(g_fuse, "/f");
    check(rc == 0, "B2 fuse_invalidate_path_entry 返回 0");
    check(exists(target), "B3 失效后 stat 立即成功（负 dentry 已丢）");

    printf("C. 父目录未在缓存中时返回 -ENOENT（文档约定，非错误）\n");
    rc = fuse_invalidate_path_entry(g_fuse, "/nonexistent_dir/f");
    check(rc == -ENOENT, "C1 父路径不在缓存 → -ENOENT");
    rc = fuse_invalidate_path_entry(g_fuse, "/");
    check(rc == -ENOENT, "C2 根目录无末段 → -ENOENT");

    fuse_exit(g_fuse);
    pthread_join(th, NULL);
    fuse_unmount(g_fuse);
    fuse_destroy(g_fuse);
    fuse_opt_free_args(&args);

    printf(g_fail ? "\n结果：存在失败项\n" : "\n结果：全部通过\n");
    return g_fail ? 1 : 0;
}
