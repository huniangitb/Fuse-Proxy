/* SPDX-License-Identifier: GPL-3.0-or-later */
/* 版权所有 (C) 2026 huniangitb <3361107168@qq.com> */
/* 后端落点物化实现：语义与边界见 fw_ingest.h */
#include "fw_ingest.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "common.h"
#include "fault_fence.h"
#include "fw_events.h"
#include "module_guard.h"
#include "module_loader.h"
#include "nsp_log.h"

/* 回读块大小：一次 64KiB 进栈，后端 read 的粒度由模块自己决定 */
#define FW_INGEST_CHUNK (64 * 1024)
/* 单个落点的物化上限：字节要整段从后端回读，无上限时一个巨大的远端文件会把
   close() 拖成分钟级，本地还要多留一份同样大的副本。超限按失败处理（远端文件
   仍在上传/已上传，本地不留副本）。 */
#define FW_INGEST_MAX_BYTES (64ULL * 1024 * 1024)
/* 半成品后缀：与落点同目录（跨设备 rename 不能原子），扩展名不是媒体，
   扫描侧不会把写到一半的文件入库。 */
#define FW_INGEST_TMP_SUFFIX ".nsp-ingest"

static int ingest_write_all(int fd, const char* buf, size_t len) {
    size_t done = 0;
    while (done < len) {
        ssize_t n = write(fd, buf + done, len - done);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) {
            errno = EIO;
            return -1;
        }
        done += (size_t)n;
    }
    return 0;
}

int fw_ingest_materialize(int slot, const char* fuse_path, uid_t uid, pid_t pid) {
    /* 通道关着（缺省）或没有订阅者：本地副本没有消费者，一个字节都不复制 */
    if (!fw_events_active()) return 0;
    if (!fuse_path || fuse_path[0] != '/') return -EINVAL;
    int user_id = -1;
    const char* sub_path = NULL;
    if (common_parse_user_layer(fuse_path, &user_id, &sub_path) != 1 || user_id < 0 || !sub_path)
        return -EINVAL; /* 没有用户层的路径没有存储落点 */
    /* 落点必须与事件里的 rpath 是同一个答案：按调用方生效的规则解析（沙盒会把
       改写后的目录换掉），否则副本会落在对端根本不看的地方。 */
    char real[PATH_MAX];
    fw_resolve_real(uid, pid, fuse_path, real, sizeof real);
    if (real[0] == '\0') return -ENAMETOOLONG;
    if (fw_media_kind_of(real) == FW_MEDIA_NONE) return 0;

    char dir[PATH_MAX];
    int wn = snprintf(dir, sizeof dir, "%s", real);
    if (wn < 0 || (size_t)wn >= sizeof dir) return -ENAMETOOLONG;
    char* slash = strrchr(dir, '/');
    if (!slash || slash == dir) return -EINVAL;
    *slash = '\0';
    /* 父目录补建走守卫出口：存储根一级组件（/data/media 下的 0/999/obb）永不创建 */
    if (common_mkdir_within_storage(dir, 0775) != 0) return -errno;

    char tmp[PATH_MAX + sizeof(FW_INGEST_TMP_SUFFIX)];
    wn = snprintf(tmp, sizeof tmp, "%s%s", real, FW_INGEST_TMP_SUFFIX);
    if (wn < 0 || (size_t)wn >= sizeof tmp) return -ENAMETOOLONG;

    const NspModuleOps* bops = NULL;
    if (module_backend_acquire_slot(slot, &bops) != 0) return -EIO;

    const char* op = "backend_open";
    uint64_t h = 0;
    int rc = 0;
    if (!bops->backend_open || !bops->backend_read) {
        rc = -ENOSYS;
    } else {
        rc = nsp_fence_backend_open(slot, op, bops->backend_open, sub_path, O_RDONLY, &h);
    }
    int fd = -1;
    if (rc == 0) {
        fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0664);
        if (fd < 0) rc = -errno;
    }
    off_t off = 0;
    char buf[FW_INGEST_CHUNK];
    op = "backend_read";
    while (rc == 0) {
        size_t got = 0;
        rc = nsp_fence_backend_read(slot, op, bops->backend_read, h, buf, sizeof buf, off, &got);
        if (rc != 0) break;
        /* 回传长度超过请求长度属模块违约：缓冲区可能已被写过界，按失败收场 */
        if (got > sizeof buf) {
            rc = -EIO;
            break;
        }
        if (got == 0) break; /* 读到结尾 */
        if (ingest_write_all(fd, buf, got) != 0) {
            rc = -errno;
            break;
        }
        off += (off_t)got;
        if ((uint64_t)off > FW_INGEST_MAX_BYTES) rc = -EFBIG;
    }
    if (h != 0 && bops->backend_release)
        (void)nsp_fence_backend_release(slot, "backend_release", bops->backend_release, h);
    module_backend_release_slot(slot);
    if (rc == NSP_FENCE_FAULT) {
        /* 模块在回调里崩过（围栏已恢复执行流）：这里补归因与熔断记账 */
        module_guard_fault(slot, op, fuse_path);
        rc = -EIO;
    }
    if (fd >= 0) {
        /* close 的写回错误也要收：本地副本不完整时宁可留远端，不留半成品 */
        if (close(fd) != 0 && rc == 0) rc = -errno;
    }
    if (rc != 0) {
        unlink(tmp);
        LOG_WRN("后端落点物化失败：%s（%s rc=%d），本地不留副本", real, op, rc);
        return rc;
    }
    /* 属性收尾走唯一出口（属主跟随父目录、共享存储组位、SELinux 上下文）：
       MediaProvider 以自己 uid 打开这个文件时按这套属性判权限 */
    nsp_new_entry_attrs(tmp, 0664);
    if (rename(tmp, real) != 0) {
        int err = errno;
        unlink(tmp);
        LOG_WRN("后端落点物化改名失败：%s（errno=%d）", real, err);
        return -err;
    }
    LOG_DBG("后端落点已物化：%s bytes=%lld", real, (long long)off);
    return 0;
}
