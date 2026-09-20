/*
 * fuse_pt_probe.c —— Android FD 透传能力检测程序（独立单文件，最小依赖）
 *
 * 功能：不依赖 libfuse 与项目框架，直接 open /dev/fuse 完成一次迷你 FUSE 挂载握手，
 *       解析内核 INIT 上报的能力（上游 flags2 bit37 与老式 flags bit31），并依次探测
 *       上游 BACKING_OPEN(229/1) 与 Android 定制 V2(229/126)/V1(229/127) 旧式 ioctl，
 *       输出系统实际支持的 FD 透传方式。
 *
 * 用法（挂载需要 root 权限）：
 *   ./fuse_pt_probe [挂载点]        # 默认 <临时目录>/.fuse_pt_probe_mnt.<pid>
 *
 * 构建（Android 静态链接，仅 libc）：
 *   <NDK>/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android35-clang \
 *       -static -O2 -Wall -o fuse_pt_probe fuse_pt_probe.c
 * 本机 GNU 验证：
 *   gcc -O2 -Wall -o fuse_pt_probe fuse_pt_probe.c && sudo ./fuse_pt_probe /tmp/.pt_mnt
 *
 * 退出码：0=系统支持 FD 透传  1=系统不支持  2=检测环境错误（挂载/INIT 握手失败）
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <linux/limits.h> /* PATH_MAX */

/* ==================== 自包含 FUSE UAPI（不依赖系统/定制头，版本无关） ==================== */
#define FUSE_KERNEL_VERSION       7
#define FUSE_KERNEL_MINOR_VERSION 36
#define FUSE_INIT_OPCODE          26
/* 上游透传能力位：flags2 中 bit37（fuse_init_in.flags2 为 64 位能力的高 32 位 → 位 37-32=5） */
#define FUSE_PASSTHROUGH        (1ULL << 37)
#define FUSE_PASSTHROUGH_FLAGS2 ((uint32_t)(FUSE_PASSTHROUGH >> 32)) /* 0x20 */
/* FUSE_INIT_EXT 必须是 bit30（bit28 是 FUSE_HANDLE_KILLPRIV_V2）！
   回包若不置此位，内核不会合并 flags2 → fc->passthrough/max_stack_depth
   永不置位 → BACKING_OPEN 被门控(EPERM)或恒 ELOOP(深度>=0) */
#define FUSE_INIT_EXT (1u << 30)
/* 回包允许的最大 backing 堆叠深度（FILESYSTEM_MAX_STACK_DEPTH=2）：设为 2 允许
   backing 文件位于堆叠 fs（如 overlayfs 上的 /data，s_stack_depth=1），否则
   BACKING_OPEN 会因 backing_sb->s_stack_depth >= max_stack_depth 返回 ELOOP */
#define FUSE_BACKING_MAX_STACK_DEPTH 2
/* 老式 Android 内核（<6.9）透传能力位：flags 中 bit31 */
#define FUSE_PASSTHROUGH_LEGACY (1u << 31)
#define FOPEN_PASSTHROUGH       (1 << 7)

struct fuse_in_header {
    uint32_t len;
    uint32_t opcode;
    uint64_t unique;
    uint64_t nodeid;
    uint32_t uid;
    uint32_t gid;
    uint32_t pid;
    uint16_t total_extlen;
    uint16_t padding;
};
struct fuse_init_in {
    uint32_t major;
    uint32_t minor;
    uint32_t max_readahead;
    uint32_t flags;
    uint32_t flags2;
    uint32_t unused[11];
};
struct fuse_out_header {
    uint32_t len;
    int32_t error;
    uint64_t unique;
};
/* 内核 7.38+ 布局：flags2 之后是 max_stack_depth（fc->passthrough 置位要求其 >0），
   再后为 request_timeout 与 unused[] */
struct fuse_init_out {
    uint32_t major;
    uint32_t minor;
    uint32_t max_readahead;
    uint32_t flags;
    uint16_t max_background;
    uint16_t congestion_threshold;
    uint32_t max_write;
    uint32_t time_gran;
    uint16_t max_pages;
    uint16_t map_alignment;
    uint32_t flags2;
    uint32_t max_stack_depth;
    uint16_t request_timeout;
    uint16_t unused[11];
};

/* /dev/fuse 设备 ioctl（上游 6.9+ 并入 UAPI，此处自包含） */
#define FUSE_DEV_IOC_MAGIC         229
#define FUSE_DEV_IOC_BACKING_OPEN  _IOW(FUSE_DEV_IOC_MAGIC, 1, struct fuse_backing_map)
#define FUSE_DEV_IOC_BACKING_CLOSE _IOW(FUSE_DEV_IOC_MAGIC, 2, uint32_t)
struct fuse_backing_map {
    int32_t fd;
    uint32_t flags;
    uint64_t padding;
};

/* Android 定制旧式透传 ioctl（与项目 fuse3-android-sysroot 的 fuse_kernel.h 定义一致） */
struct fuse_passthrough_out_v0 {
    uint32_t fd;
    uint32_t len;
    void* vec;
};
#define FUSE_DEV_IOC_PASSTHROUGH_OPEN_V0 _IOW(FUSE_DEV_IOC_MAGIC, 1, struct fuse_passthrough_out_v0)
#define FUSE_DEV_IOC_PASSTHROUGH_OPEN_V1 \
    _IOW(FUSE_DEV_IOC_MAGIC, 127, struct fuse_passthrough_out_v0)
#define FUSE_DEV_IOC_PASSTHROUGH_OPEN_V2 _IOW(FUSE_DEV_IOC_MAGIC, 126, uint32_t)
/* ================================================================================== */

typedef struct {
    const char* name;
    const char* desc;
    int ok;      /* 1=成功 0=失败 */
    long detail; /* 成功: backing_id / 失败: -errno */
} ProbeResult;

static int g_supported = 0; /* 任一透传方式可用即为支持 */

static const char* errno_desc(int e) {
    switch (e) {
        case ENOTTY: return "ENOTTY(内核无此 ioctl，不支持)";
        case EINVAL: return "EINVAL(ioctl 号存在但参数/文件类型被拒)";
        case EPERM: return "EPERM(存在但被权限门控拦截，需 root/CAP_SYS_ADMIN 或 INIT 未协商)";
        case EBADF: return "EBADF(无效 fd)";
        case ELOOP:
            return "ELOOP(backing 文件系统堆叠深度过高(≥回包 max_stack_depth)，换用非堆叠路径或提升深度)";
        default: return strerror(e);
    }
}

static void print_probe(const ProbeResult* r) {
    if (r->ok) {
        printf("       %-14s %-28s ✅ 成功 backing_id=%ld\n", r->name, r->desc, r->detail);
        g_supported = 1;
    } else {
        printf("       %-14s %-28s ❌ %s\n", r->name, r->desc, errno_desc((int)-r->detail));
    }
}

int main(int argc, char* argv[]) {
    char tmpdir[PATH_MAX];
    char mnt[PATH_MAX];
    char probe_path[PATH_MAX];
    struct utsname un;
    int fuse_fd = -1, probe_fd = -1;

    /* ---- 平台临时目录：Android 用 /data/local/tmp，否则 /tmp ---- */
    if (access("/data/local/tmp", W_OK) == 0)
        snprintf(tmpdir, sizeof(tmpdir), "/data/local/tmp");
    else
        snprintf(tmpdir, sizeof(tmpdir), "/tmp");
    if (argc > 1)
        snprintf(mnt, sizeof(mnt), "%s", argv[1]);
    else
        snprintf(mnt, sizeof(mnt), "%s/.fuse_pt_probe_mnt.%d", tmpdir, (int)getpid());
    snprintf(probe_path, sizeof(probe_path), "%s/.fuse_pt_probe.%d", tmpdir, (int)getpid());

    printf("=== Android FD 透传能力检测 ===\n");
    uname(&un);
    printf("[系统] %s %s %s | 用户 uid=%d\n", un.sysname, un.release, un.version, (int)getuid());

    /* ---- 1. 打开 /dev/fuse 并挂载 ---- */
    fuse_fd = open("/dev/fuse", O_RDWR | O_CLOEXEC);
    if (fuse_fd < 0) {
        printf("[挂载] ❌ 无法打开 /dev/fuse: %s\n", strerror(errno));
        printf("=== 结论: 检测环境错误（无 /dev/fuse 或权限不足，需 root） ===\n");
        return 2;
    }
    if (mkdir(mnt, 0755) != 0 && errno != EEXIST) {
        printf("[挂载] ❌ mkdir %s: %s\n", mnt, strerror(errno));
        close(fuse_fd);
        return 2;
    }
    char mnt_opts[128];
    snprintf(mnt_opts, sizeof(mnt_opts), "fd=%d,rootmode=40000,user_id=0,group_id=0", fuse_fd);
    if (mount("fuse", mnt, "fuse", MS_NOSUID | MS_NODEV, mnt_opts) != 0) {
        printf("[挂载] ❌ mount(%s): %s\n", mnt, strerror(errno));
        rmdir(mnt);
        close(fuse_fd);
        return 2;
    }
    printf("[1/4] FUSE 挂载: ✅ %s (fd=%d)\n", mnt, fuse_fd);

    /* ---- 2. INIT 握手：读取内核上报的能力 ----
     * 注意：read 缓冲必须 >= FUSE_MIN_READ_BUFFER(8192)，否则内核返回 EINVAL */
    char ibuf[16384];
    ssize_t n = read(fuse_fd, ibuf, sizeof(ibuf));
    if (n < (ssize_t)sizeof(struct fuse_in_header)) {
        printf("[INIT] ❌ 读取 INIT 请求失败: %s\n", n < 0 ? strerror(errno) : "数据过短");
        umount2(mnt, MNT_DETACH);
        rmdir(mnt);
        close(fuse_fd);
        return 2;
    }
    struct fuse_in_header* ih = (struct fuse_in_header*)ibuf;
    if (ih->opcode != FUSE_INIT_OPCODE) {
        printf("[INIT] ❌ 非 INIT 请求 (opcode=%u len=%zd)\n", ih->opcode, n);
        umount2(mnt, MNT_DETACH);
        rmdir(mnt);
        close(fuse_fd);
        return 2;
    }
    /* 旧内核(<7.36，如 Android 12 的 5.10)的 fuse_init_in 仅含
       major/minor/max_readahead/flags 共 16 字节；flags2 字段（offset 16）为
       7.36+ 新增，仅在数据长度足够且 minor>=36 时有效 */
    if (n < (ssize_t)(sizeof(*ih) + 16)) {
        printf("[INIT] ❌ INIT 数据过短 (len=%zd)\n", n);
        umount2(mnt, MNT_DETACH);
        rmdir(mnt);
        close(fuse_fd);
        return 2;
    }
    struct fuse_init_in* inarg = (struct fuse_init_in*)(ibuf + sizeof(*ih));
    if (inarg->major != FUSE_KERNEL_VERSION) {
        printf("[INIT] ❌ 非预期协议主版本 %u (len=%zd)\n", inarg->major, n);
        umount2(mnt, MNT_DETACH);
        rmdir(mnt);
        close(fuse_fd);
        return 2;
    }
    int have_flags2 =
        (n >= (ssize_t)(sizeof(*ih) + offsetof(struct fuse_init_in, unused))) && inarg->minor >= 36;
    uint32_t kflags2 = have_flags2 ? inarg->flags2 : 0;
    int flags2_valid = have_flags2 && (inarg->flags & FUSE_INIT_EXT);
    printf("[2/4] INIT 能力协商: 内核协议 %u.%u (flags=0x%08x, flags2=0x%08x%s)\n", inarg->major,
           inarg->minor, inarg->flags, kflags2,
           flags2_valid ? "" : "，flags2 无 FUSE_INIT_EXT 标记，仅供参考");
    int init_upstream = flags2_valid && (kflags2 & FUSE_PASSTHROUGH_FLAGS2);
    int init_legacy = (inarg->flags & FUSE_PASSTHROUGH_LEGACY) != 0;
    printf("       上游 FUSE_PASSTHROUGH(flags2 bit37): %s\n",
           init_upstream ? "✅ 内核已上报" : "— 未上报");
    printf("       老式 FUSE_PASSTHROUGH(flags bit31): %s\n",
           init_legacy ? "✅ 内核已上报" : "— 未上报");

    /* 回复 INIT：按内核上报的能力镜像请求启用透传 */
    char obuf[4096];
    struct fuse_out_header* oh = (struct fuse_out_header*)obuf;
    struct fuse_init_out* outarg = (struct fuse_init_out*)(obuf + sizeof(*oh));
    memset(obuf, 0, sizeof(obuf));
    oh->len = (uint32_t)(sizeof(*oh) + sizeof(*outarg));
    oh->error = 0;
    oh->unique = ih->unique;
    outarg->major = FUSE_KERNEL_VERSION;
    outarg->minor = inarg->minor; /* 镜像内核协议版本（libfuse 同样回 45） */
    outarg->max_readahead = inarg->max_readahead;
    outarg->max_write = 1 << 20;          /* 1MB（与 libfuse 默认一致） */
    outarg->max_pages = (1 << 20) / 4096; /* 256 */
    outarg->time_gran = 1;
    outarg->flags = FUSE_INIT_EXT;                             /* 声明支持扩展 flags2 */
    if (init_legacy) outarg->flags |= FUSE_PASSTHROUGH_LEGACY; /* 老式 Android 内核透传 */
    if (init_upstream) {
        outarg->flags2 = FUSE_PASSTHROUGH_FLAGS2; /* 上游透传（flags2 bit37） */
        outarg->max_stack_depth = FUSE_BACKING_MAX_STACK_DEPTH;
    }
    if (write(fuse_fd, obuf, oh->len) != (ssize_t)oh->len) {
        printf("[INIT] ❌ 回复 INIT 失败: %s\n", strerror(errno));
        umount2(mnt, MNT_DETACH);
        rmdir(mnt);
        close(fuse_fd);
        return 2;
    }

    /* ---- 3. ioctl 探测（探测 fd 必须用普通文件：BACKING_OPEN 要求 d_is_reg） ---- */
    printf("[3/4] ioctl 探测 (backing 用普通文件 %s):\n", probe_path);
    int backing_ids[8] = {0}; /* 所有成功创建的 backing，统一 BACKING_CLOSE 清理 */
    int nback = 0;
    const char* ok_names[8] = {0}; /* 探测命中的透传方法，结论中列出 */
    int nok = 0;
    probe_fd = open(probe_path, O_CREAT | O_RDWR | O_CLOEXEC, 0600);
    if (probe_fd < 0) {
        printf("       ❌ 无法创建探测文件: %s\n", strerror(errno));
    } else {
        ProbeResult r;
        int ret;

        /* 1) 上游 BACKING_OPEN(229/1, fuse_backing_map)：主线 6.9+/GKI 6.12 新方式。
           老式 Android 内核上该 ioctl 号恰好也是 PASSTHROUGH_OPEN(V0) 处理器 */
        r.name = "BACKING_OPEN";
        r.desc = "上游(229/1, backing_map)";
        errno = 0;
        ret = (int)ioctl(fuse_fd, FUSE_DEV_IOC_BACKING_OPEN,
                         &(struct fuse_backing_map){.fd = probe_fd, .flags = 0, .padding = 0});
        if (ret >= 0) {
            r.ok = 1;
            r.detail = ret;
            if (nback < 8) backing_ids[nback++] = ret;
            ok_names[nok++] = r.name;
        } else {
            r.ok = 0;
            r.detail = -errno;
        }
        print_probe(&r);

        /* 2) V2：Android 旧式(229/126, uint32_t fd) */
        r.name = "V2";
        r.desc = "Android 旧式(229/126, fd)";
        errno = 0;
        ret =
            (int)ioctl(fuse_fd, FUSE_DEV_IOC_PASSTHROUGH_OPEN_V2, &(uint32_t){(uint32_t)probe_fd});
        if (ret >= 0) {
            r.ok = 1;
            r.detail = ret;
            if (nback < 8) backing_ids[nback++] = ret;
            ok_names[nok++] = r.name;
        } else {
            r.ok = 0;
            r.detail = -errno;
        }
        print_probe(&r);

        /* 3) V1：Android 旧式(229/127, out_v0) */
        r.name = "V1";
        r.desc = "Android 旧式(229/127, out_v0)";
        errno = 0;
        ret = (int)ioctl(
            fuse_fd, FUSE_DEV_IOC_PASSTHROUGH_OPEN_V1,
            &(struct fuse_passthrough_out_v0){.fd = (uint32_t)probe_fd, .len = 0, .vec = NULL});
        if (ret >= 0) {
            r.ok = 1;
            r.detail = ret;
            if (nback < 8) backing_ids[nback++] = ret;
            ok_names[nok++] = r.name;
        } else {
            r.ok = 0;
            r.detail = -errno;
        }
        print_probe(&r);

        /* 4) V0：Android 旧式(229/1, out_v0)——实际执行探测，非等价替代。
           64 位下 out_v0(16B) 与 backing_map(16B) 同号同尺寸，即同一 ioctl；
           32 位下 out_v0 为 12B，是独立 ioctl。两种位宽都如实上报结果 */
        r.name = "V0";
        r.desc = "Android 旧式(229/1, out_v0)";
        errno = 0;
        ret = (int)ioctl(
            fuse_fd, FUSE_DEV_IOC_PASSTHROUGH_OPEN_V0,
            &(struct fuse_passthrough_out_v0){.fd = (uint32_t)probe_fd, .len = 0, .vec = NULL});
        if (ret >= 0) {
            r.ok = 1;
            r.detail = ret;
            if (nback < 8) backing_ids[nback++] = ret;
            ok_names[nok++] = r.name;
        } else {
            r.ok = 0;
            r.detail = -errno;
        }
        print_probe(&r);

        printf("       %-14s %-28s ℹ️ %zu 位：V0 与 BACKING_OPEN %s\n", "", "", sizeof(void*) * 8,
               sizeof(struct fuse_passthrough_out_v0) == sizeof(struct fuse_backing_map)
                   ? "同号同尺寸(同一 ioctl)，结果一致"
                   : "尺寸不同(独立 ioctl)");
    }

    /* ---- 4. 清理 ---- */
    printf("[4/4] 清理:\n");
    if (nback > 0) {
        int closed = 0, no_close_ioctl = 0;
        for (int i = 0; i < nback; i++) {
            errno = 0;
            if (ioctl(fuse_fd, FUSE_DEV_IOC_BACKING_CLOSE, &(uint32_t){(uint32_t)backing_ids[i]}) ==
                0) {
                closed++;
            } else if (errno == ENOTTY) {
                /* 老内核(如 5.10 Android)无上游 229/2 BACKING_CLOSE ioctl：
                   其透传走 V2/V1/V0 老式路径，backing 由内核在连接销毁
                   （卸载）时自动释放，无需（也无法）显式关闭 */
                no_close_ioctl++;
            } else {
                printf("       BACKING_CLOSE(backing_id=%d): ❌ %s\n", backing_ids[i],
                       strerror(errno));
            }
        }
        printf("       BACKING_CLOSE: ✅ 关闭 %d/%d 个测试 backing\n", closed, nback);
        if (no_close_ioctl > 0)
            printf("       ⚠️ %d 个 backing 未显式关闭：内核无 BACKING_CLOSE(229/2) ioctl\n"
                   "         （老式透传路径），将在卸载连接时由内核自动释放\n",
                   no_close_ioctl);
    }
    if (probe_fd >= 0) close(probe_fd);
    unlink(probe_path);
    if (umount2(mnt, MNT_DETACH) == 0)
        printf("       卸载 %s: ✅\n", mnt);
    else
        printf("       卸载 %s: ❌ %s\n", mnt, strerror(errno));
    rmdir(mnt);
    close(fuse_fd);

    if (g_supported) {
        printf("=== 结论: 系统支持 FD 透传（命中: ");
        for (int i = 0; i < nok; i++) printf("%s%s", i ? " / " : "", ok_names[i]);
        printf("） ===\n");
    } else {
        printf(
            "=== 结论: 系统不支持 FD 透传（ioctl 均不可用，文件 I/O 走标准 FUSE 用户态路径） ===\n");
    }
    return g_supported ? 0 : 1;
}
