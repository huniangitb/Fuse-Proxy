/* SPDX-License-Identifier: GPL-3.0-or-later */
/* 版权所有 (C) 2026 huniangitb <3361107168@qq.com> */
/* 配置目录 watch 对账实现：语义见 cfg_watch.h */
#include "cfg_watch.h"

#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include "nsp_util.h" /* nsp_is_app_rules_dirname（App-rules 目录名判定唯一出处） */

bool cfg_watch_sync(int ifd, const char* base_dir, CfgDirWatch* ws, int* n) {
    bool ok = true;
    bool seen[CFG_WATCH_MAX] = {false};
    DIR* d = opendir(base_dir);
    if (!d) return false; /* 目录暂不可读：调用方下次重试 */
    struct dirent* de;
    while ((de = readdir(d)) != nullptr) {
        if (de->d_name[0] == '.') continue;
        if (!nsp_is_app_rules_dirname(de->d_name)) continue;
        char full[PATH_MAX];
        if (snprintf(full, sizeof full, "%s/%s", base_dir, de->d_name) >= (int)sizeof full)
            continue;
        struct stat st;
        if (stat(full, &st) != 0 || !S_ISDIR(st.st_mode)) continue;
        int idx = -1;
        for (int i = 0; i < *n; i++) {
            if (strcmp(ws[i].dir, full) == 0) {
                idx = i;
                break;
            }
        }
        if (idx < 0) {
            if (*n >= CFG_WATCH_MAX) {
                ok = false; /* 表满：其余目录下次重试（调用方兜底重扫） */
                continue;
            }
            idx = (*n)++;
            snprintf(ws[idx].dir, sizeof ws[idx].dir, "%s", full);
            ws[idx].wd = -1;
        }
        seen[idx] = true;
        if (ws[idx].wd < 0) {
            int w = inotify_add_watch(ifd, ws[idx].dir, NSP_CFG_WATCH_MASK);
            if (w < 0) {
                ok = false;
                continue;
            }
            ws[idx].wd = w;
        }
    }
    closedir(d);
    /* 摘除已消失的目录（目录已删时内核自动摘 watch，rm 失败属正常）。
       压缩时同步搬运元素本身——不能用「平行 seen 数组 + 原地搬尾部」的写法：
       搬动后 seen[i] 与 ws[i] 不再对应同一目录，会把存活项一起摘掉 */
    int keep = 0;
    for (int i = 0; i < *n; i++) {
        if (!seen[i]) {
            if (ws[i].wd >= 0) inotify_rm_watch(ifd, ws[i].wd);
            continue;
        }
        if (keep != i) ws[keep] = ws[i];
        keep++;
    }
    *n = keep;
    return ok;
}
