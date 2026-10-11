/* SPDX-License-Identifier: GPL-3.0-or-later */
/* 版权所有 (C) 2026 huniangitb <3361107168@qq.com> */
#ifndef NSP_CFG_WATCH_H
#define NSP_CFG_WATCH_H

/* ================= 配置目录 watch 对账（daemon 内部件） =================
 * 用途：inotify 不递归，而应用规则写在 `<CONFIG_DIR>/App-rules[-<uid>]/<pkg>.conf`
 * （框架读取即按 nsp_app_rule_dir 合成这一路径）。只监听主规则文件所在目录收不到
 * 这些子目录内的变化——运行中改应用级规则不会生效，要等别的事件偶然触发重读；
 * GLOBAL/类别规则写主文件所以能即时生效，这个不对称正是漏点所在。
 *
 * 本件只做「对账」：把基目录下现存的 App-rules* 子目录都挂上 watch、摘掉已消失的，
 * 并报告是否全部就位（未就位则由调用方以定时重扫兜底）。事件读取与重载策略留在
 * fw_config 的监听线程里。 */

#include <limits.h>
#include <stdbool.h>
#include <sys/inotify.h>

/* 规则文件/目录监听掩码（主规则文件所在目录与 App-rules* 子目录同用）：
   写者落盘一律 tmp+rename（IN_MOVED_TO），另含就地改写/属性变更两种兜底 */
#define NSP_CFG_WATCH_MASK                                                               \
    (IN_CLOSE_WRITE | IN_MODIFY | IN_MOVED_TO | IN_MOVED_FROM | IN_CREATE | IN_DELETE |  \
     IN_DELETE_SELF | IN_ATTRIB)

#define CFG_WATCH_MAX 64

typedef struct {
    int wd; /* <0 = 未挂上（待重试） */
    char dir[PATH_MAX];
} CfgDirWatch;

/* 对账 base_dir 下的 App-rules* 子目录 watch：补新增、摘已删。
   ws/n 为调用方持有的表（n 初值 0，表容量 >= CFG_WATCH_MAX）。
   返回 true = 现存目录全部挂上；false = 有目录没挂上（超限/加失败/目录不可读），
   调用方须以定时重扫兜底。已删目录的内核 watch 自动失效，此处只做表内清理。 */
bool cfg_watch_sync(int ifd, const char* base_dir, CfgDirWatch* ws, int* n);

/* 同上，但对账 base_dir 下**全部**子目录（不做目录名过滤）。
   模块配置目录用：`<modules_dir>/<模块名>/` 下同时放 `<模块名>.so` 与
   `<模块名>.conf`，目录名没有可判的前缀，全部挂上即可。 */
bool cfg_watch_sync_subdirs(int ifd, const char* base_dir, CfgDirWatch* ws, int* n);

#endif /* NSP_CFG_WATCH_H */
