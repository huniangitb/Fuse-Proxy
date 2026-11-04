/*
 * 隐藏规则命中的对外 errno 选择（纯函数，便于直编测试）。
 *
 * 缺省 ENOENT：语义是「路径不存在」，与内核里文件真不存在时一致。
 * 配置 HIDE_ERRNO 后可以换成 EACCES/EPERM：应用侧语义变成「存在但不许访问」，
 * 对「访问失败就重试」的应用能直接断掉重试循环。
 */
#ifndef NSP_HIDE_ERRNO_H
#define NSP_HIDE_ERRNO_H

#include <errno.h>

/* configured = AppConfig.hide_errno（0 = 未配置） */
static inline int nsp_hide_errno_of(int configured) {
    return configured != 0 ? configured : ENOENT;
}

#endif /* NSP_HIDE_ERRNO_H */
