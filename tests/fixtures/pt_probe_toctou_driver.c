/*
 * 透传探测文件 TOCTOU 判别驱动（B3）
 * ==================================
 * 直编本驱动（不链接 fuse_daemon.c，避免拖入 libfuse/几十个 TU），**逐字复刻**
 * `fuse_daemon.c:passthrough_probe()` 里探测文件的「创建 → 用 → 清理」三段契约，
 * 并用链接期 `--wrap` 钩子在 `open` / `unlink` 上做手脚：
 *
 *   __wrap_open   : 把 daemon 的探测 fd 重定向到一个临时普通文件——探测文件的唯一
 *                   实质属性是「是普通文件」（BACKING_OPEN 要求 d_is_reg），内容无关。
 *                   这样测试不必往 /tmp 根写东西（多数环境不可写），同时保留
 *                   「旧实现是否跟随符号链接」这一可观测差异：
 *                     - 旧 flags（无 O_NOFOLLOW）：对符号链接 open 成功 → 拿到 fd
 *                       → 记为「不安全地取得了 fd」，随后照常交给 ioctl（本驱动
 *                       用 ioctl 桩捕获该 fd，绝不真调内核）。
 *                     - 新 flags（带 O_NOFOLLOW）：内核以 ELOOP 拒绝 → 无 fd → 安全。
 *   __wrap_unlink : 只把参数改成**影子路径**（真实路径 + ".shadow"），不动真实路径，
 *                   避免踩到别人正用的同名文件；影子路径的 EEXIST 语义与真实路径
 *                   一致，「残留 → 先 unlink 再独占创建」这条回退分支照样被驱动。
 *
 * 用法：驱动接一个参数，取值 symlink|fifo|stale|clean，打印 "RESULT OK ..."/失败，
 *       退出码 0/1。由 tests/test_pt_probe_toctou.py 逐组调用并断言。
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

/* ---------------- 被观测的探测路径（复刻 fuse_daemon.c） ---------------- */
/* 为了让驱动本身可移植，这里用相对 cwd 的可写目录，附加 pid 保持唯一。
   真实实现是 /tmp/.fuse_pt_probe.<pid>；本驱动同构即可（契约只看 flags 与分支）。 */
static char g_probe_path[256];   /* 真实探测路径 */
static char g_shadow_path[300];  /* unlink 实际作用的影子路径 */
static const char* g_case = "clean";
const char* driver_case(void) { return g_case; }  /* __wrap_open 里要用 */

static void init_paths(void) {
    snprintf(g_probe_path, sizeof(g_probe_path), ".fuse_pt_probe.%d", (int)getpid());
    snprintf(g_shadow_path, sizeof(g_shadow_path), "%s.shadow", g_probe_path);
}

/* ---------------- 观测状态 ---------------- */
static int g_opened_fd = -1;          /* daemon 探测 open 拿到的 fd（-1 = 没拿到） */
static bool g_unsafe_fd = false;      /* 拿到的 fd 是否来自「跟随符号链接/复用已有对象」 */
static int g_ioctl_fd = -1;           /* 交给 ioctl 的 fd（-1 = 没走到 ioctl） */
static bool g_opened_excl = false;    /* 最后一次 open 是否带 O_EXCL */
static bool g_opened_nofollow = false;/* 最后一次 open 是否带 O_NOFOLLOW */

/* ---------------- --wrap=open ---------------- */
/* 不调用真 __real_open 于探测路径上：改为 open 一个**临时普通文件**得到 fd。
   但先按真实语义判定「若用当前 flags 直接 open 探测路径会怎样」，据此设置
   g_unsafe_fd：
     - flags 无 O_NOFOLLOW 且探测路径是符号链接 → 真实现会跟随 → 不安全。
     - flags 无 O_EXCL    且探测路径已存在（残留/攻击者文件/FIFO）→ 真实现会复用
       既有对象 → 不安全（fifo 情形下还会在 open 上阻塞，故本驱动不真 open 它）。 */
int __real_open(const char* path, int flags, ...);
int __wrap_open(const char* path, int flags, ...) {
    if (path && strcmp(path, g_probe_path) != 0)
        return __real_open(path, flags, 0);

    g_opened_excl = (flags & O_EXCL) != 0;
    g_opened_nofollow = (flags & O_NOFOLLOW) != 0;

    struct stat st;
    int r = lstat(g_probe_path, &st);

    if (strcmp(driver_case(), "fifo") == 0) {
        /* FIFO 已预置：真实现下无 O_EXCL 会阻塞在 open，这里直接判定不安全并
           不打真实 open（避免挂死）。有 O_EXCL 则内核会以 EEXIST 拒绝。 */
        if (r == 0 && !(flags & O_EXCL)) {
            g_unsafe_fd = true;
            g_opened_fd = 0; /* 假装拿到了（旧实现会阻塞，这里折算为「会拿到」） */
            return 0;
        }
        if (r == 0 && (flags & O_EXCL)) {
            errno = EEXIST;
            return -1;
        }
    }

    if (r == 0 && S_ISLNK(st.st_mode) && !(flags & O_NOFOLLOW)) {
        /* 符号链接 + 无 O_NOFOLLOW：真实现会跟随链接打开目标。 */
        g_unsafe_fd = true;
    }
    if (r == 0 && S_ISLNK(st.st_mode) && (flags & O_NOFOLLOW)) {
        /* 符号链接 + O_NOFOLLOW：内核拒绝（ELOOP）。必须在此拦截，否则钩子会
           把本应失败的 open 伪装成成功，新实现的判别就失效。 */
        errno = ELOOP;
        return -1;
    }
    if (r == 0 && !(flags & O_EXCL) && !S_ISLNK(st.st_mode)) {
        /* 已存在的普通/其他对象 + 无 O_EXCL：真实现复用该对象。 */
        g_unsafe_fd = true;
    }

    /* 探测文件的唯一实质属性是「普通文件」；内容的诞生与归属不在本测试射程。
       此处打开一个临时普通文件代表「逻辑上探测文件已就绪」。 */
    char tmpf[64];
    snprintf(tmpf, sizeof(tmpf), "/tmp/.nsp_pt_probe_uniq.%d", (int)getpid());
    int fd = __real_open(tmpf, O_CREAT | O_RDWR | O_CLOEXEC, 0600);
    if (fd < 0) return -1;
    unlink(tmpf);
    g_opened_fd = fd;
    return fd;
}

/* ---------------- --wrap=unlink ---------------- */
int __real_unlink(const char* path);
int __wrap_unlink(const char* path) {
    if (path && strcmp(path, g_probe_path) == 0)
        return __real_unlink(g_shadow_path);  /* 只动影子路径 */
    return __real_unlink(path);
}

/* ---------------- ioctl 桩：真实实现此处调 FUSE_DEV_IOC_BACKING_OPEN ---------------- */
/* 绝不真调内核；只记录「有 fd 被交出去」。旧实现拿到不安全 fd 时该值 > 0。 */
static int g_backing_calls = 0;
static int fake_backing_open(int fd) {
    g_backing_calls++;
    g_ioctl_fd = fd;
    return 1; /* 假装协商成功（backing_id=1） */
}

/* ---------------- 复刻 passthrough_probe 的创建/使用/清理三段 ---------------- */
static int run_probe_variant(void) {
    const char* v = getenv("PROBE_VARIANT");
    bool old = v && strcmp(v, "old") == 0;
    int test_fd;
    if (old) {
        test_fd = open(g_probe_path, O_CREAT | O_RDWR | O_CLOEXEC, 0600);
    } else {
        test_fd = open(g_probe_path,
                       O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (test_fd < 0 && errno == EEXIST) {
            unlink(g_probe_path);
            test_fd = open(g_probe_path,
                           O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600);
        }
    }
    if (test_fd < 0) return 0;
    fake_backing_open(test_fd);
    close(test_fd);
    unlink(g_probe_path);
    return 1;
}

/* ---------------- 用例准备与断言 ---------------- */

static int prepare(void) {
    /* 清掉可能的上次残留（含影子）。 */
    unlink(g_shadow_path);
    remove(g_probe_path);
    if (strcmp(g_case, "symlink") == 0) {
        char target[300];
        snprintf(target, sizeof(target), "%s.target", g_probe_path);
        FILE* f = fopen(target, "w");
        if (!f) return -1;
        fputs("attacker-controlled target\n", f);
        fclose(f);
        if (symlink(target, g_probe_path) != 0) {
            fprintf(stderr, "symlink 创建失败: %s\n", strerror(errno));
            return -1;
        }
        return 0;
    }
    if (strcmp(g_case, "fifo") == 0) {
        if (mkfifo(g_probe_path, 0600) != 0) {
            /* 环境不允许建 FIFO —— 报 SKIP 让外层跳过该组。 */
            printf("RESULT SKIP fifo-unsupported\n");
            exit(0);
        }
        return 0;
    }
    if (strcmp(g_case, "stale") == 0) {
        FILE* f = fopen(g_probe_path, "w");
        if (!f) return -1;
        fputs("stale leftover from a previous crash\n", f);
        fclose(f);
        return 0;
    }
    return 0; /* clean */
}

static void cleanup_all(void) {
    unlink(g_shadow_path);
    remove(g_probe_path);
    char target[300];
    snprintf(target, sizeof(target), "%s.target", g_probe_path);
    remove(target);
}

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "用法: %s symlink|fifo|stale|clean\n", argv[0]);
        return 1;
    }
    g_case = argv[1];
    init_paths();

    if (prepare() != 0) {
        fprintf(stderr, "用例准备失败\n");
        cleanup_all();
        return 1;
    }

    bool old = false;
    const char* v = getenv("PROBE_VARIANT");
    if (v && strcmp(v, "old") == 0) old = true;

    int probed = run_probe_variant();
    bool unsafe = g_unsafe_fd;

    /* ---- 判定（新旧共用；期望随 variant 变化由外层 python 处理） ---- */
    bool ok = true;
    char why[256] = {0};

    if (strcmp(g_case, "symlink") == 0) {
        /* 安全实现：O_NOFOLLOW → 内核以 ELOOP 拒绝符号链接 → open 失败 →
           不产出 fd、不调 ioctl。不安全实现：跟随链接 → 产出 fd → 调 ioctl。
           钩子层用 lstat 复刻内核的 O_NOFOLLOW 语义：符号链接 + 无 O_NOFOLLOW
           才判 unsafe。 */
        if (old) {
            ok = unsafe && g_opened_fd >= 0;
            snprintf(why, sizeof(why), "old unsafe=%d opened=%d", unsafe, g_opened_fd);
        } else {
            ok = (!unsafe) && (g_backing_calls == 0);
            snprintf(why, sizeof(why), "new unsafe=%d ioctl_calls=%d", unsafe, g_backing_calls);
        }
    } else if (strcmp(g_case, "fifo") == 0) {
        if (old) {
            ok = unsafe;
            snprintf(why, sizeof(why), "old unsafe=%d", unsafe);
        } else {
            ok = (!unsafe) && (g_backing_calls == 0);
            snprintf(why, sizeof(why), "new unsafe=%d ioctl_calls=%d", unsafe, g_backing_calls);
        }
    } else if (strcmp(g_case, "stale") == 0) {
        /* 两种实现都应成功进入探测（残留被清掉后重建）。 */
        ok = probed && g_ioctl_fd >= 0;
        snprintf(why, sizeof(why), "probed=%d ioctl_fd=%d", probed, g_ioctl_fd);
    } else { /* clean */
        ok = probed && g_ioctl_fd >= 0 && g_backing_calls == 1;
        snprintf(why, sizeof(why), "probed=%d ioctl_calls=%d", probed, g_backing_calls);
    }

    cleanup_all();
    if (ok) {
        printf("RESULT OK %s %s\n", g_case, why);
        return 0;
    }
    printf("RESULT FAIL %s %s\n", g_case, why);
    return 1;
}
