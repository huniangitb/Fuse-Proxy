#define _GNU_SOURCE
#include "uid_map.h"
#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/* 快速排序辅助函数 */
static int compare_entries(const void* a, const void* b) {
    uid_t uid_a = ((const UidMapEntry*)a)->uid;
    uid_t uid_b = ((const UidMapEntry*)b)->uid;
    if (uid_a < uid_b) return -1;
    if (uid_a > uid_b) return 1;
    return 0;
}
/* 从 CONFIG_DIR/uid.map 文件加载 UID 映射表并进行排序
 * 返回加载的条目数（不超过 max_entries）。
 * 调用方须保证 entries 指向至少能容纳 max_entries 个条目的内存。
 */
int uid_map_load(UidMapEntry* entries, int max_entries) {
    char path[PATH_MAX];
    snprintf(path, sizeof(path), CONFIG_DIR "/uid.map");
    FILE* fp = fopen(path, "re");
    if (!fp) return 0;
    int count = 0;
    char line[256];
    while (fgets(line, sizeof(line), fp) && count < max_entries) {
        uid_t u;
        char p[128];
        if (sscanf(line, "%d %127s", &u, p) == 2) {
            entries[count].uid = u;
            strncpy(entries[count].pkg, p, 127);
            entries[count].pkg[127] = '\0';
            count++;
        }
    }
    fclose(fp);
    /* 必须在此处执行排序，确保后续 uid_map_lookup 二分查找的正确性 */
    if (count > 0) {
        qsort(entries, (size_t)count, sizeof(UidMapEntry), compare_entries);
    }
    return count;
}
/* 增量写入: 如果 uid 已存在于 uid.map 则更新其包名，否则追加新行。
 * 支持动态扩容：堆分配初始 UID_MAP_INIT_CAPACITY 条，不够时自动翻倍。
 * 返回 0 成功，负值失败（UID_MAP_ERR_*）。
 */
int uid_map_upsert(uid_t uid, const char* pkg) {
    char path[PATH_MAX];
    char tmp_path[PATH_MAX];
    snprintf(path, sizeof(path), CONFIG_DIR "/uid.map");
    snprintf(tmp_path, sizeof(tmp_path), CONFIG_DIR "/uid.map.tmp");

    size_t capacity = UID_MAP_INIT_CAPACITY;
    UidMapEntry* entries = malloc(capacity * sizeof(UidMapEntry));
    if (!entries) {
        LOG_ERR("uid_map_upsert: malloc(%zu) 失败", capacity * sizeof(UidMapEntry));
        return UID_MAP_ERR_IO;
    }

    /* 1. 加载现有映射，如果文件比当前容量大则自动扩容重试 */
    int count = uid_map_load(entries, capacity);
    while (count > 0 && count == (int)capacity) {
        capacity *= 2;
        UidMapEntry* new_entries = realloc(entries, capacity * sizeof(UidMapEntry));
        if (!new_entries) {
            LOG_ERR("uid_map_upsert: realloc(%zu) 失败", capacity * sizeof(UidMapEntry));
            free(entries);
            return UID_MAP_ERR_IO;
        }
        entries = new_entries;
        count = uid_map_load(entries, capacity);
    }

    /* 2. 在现有条目中查找 uid，匹配则更新 */
    bool updated = false;
    for (int i = 0; i < count; i++) {
        if (entries[i].uid == uid) {
            if (strcmp(entries[i].pkg, pkg) == 0) {
                free(entries);
                return 0;
            }
            strncpy(entries[i].pkg, pkg, 127);
            entries[i].pkg[127] = '\0';
            updated = true;
            break;
        }
    }

    /* 3. 未找到则追加新行，容量不够时自动扩容 */
    if (!updated) {
        if ((size_t)count >= capacity) {
            capacity = (capacity < UID_MAP_MAX_ENTRIES) ? UID_MAP_MAX_ENTRIES : capacity * 2;
            UidMapEntry* new_entries = realloc(entries, capacity * sizeof(UidMapEntry));
            if (!new_entries) {
                LOG_ERR("uid_map_upsert: realloc(%zu) 失败", capacity * sizeof(UidMapEntry));
                free(entries);
                return UID_MAP_ERR_IO;
            }
            entries = new_entries;
        }
        entries[count].uid = uid;
        strncpy(entries[count].pkg, pkg, 127);
        entries[count].pkg[127] = '\0';
        count++;
    }

    /* 4. 核心安全优化：先写入临时文件，确保写入动作的鲁棒性 */
    FILE* fp = fopen(tmp_path, "we");
    if (!fp) {
        LOG_ERR("uid_map_upsert: fopen(%s) 失败: %s", tmp_path, strerror(errno));
        free(entries);
        return UID_MAP_ERR_IO;
    }
    for (int j = 0; j < count; j++) {
        if (fprintf(fp, "%d %s\n", entries[j].uid, entries[j].pkg) < 0) {
            LOG_ERR("uid_map_upsert: fprintf 失败: %s", strerror(errno));
            fclose(fp);
            unlink(tmp_path);
            free(entries);
            return UID_MAP_ERR_IO;
        }
    }
    if (fflush(fp) != 0 || fsync(fileno(fp)) != 0) {
        LOG_ERR("uid_map_upsert: fflush/fsync 失败: %s", strerror(errno));
        fclose(fp);
        unlink(tmp_path);
        free(entries);
        return UID_MAP_ERR_IO;
    }
    fclose(fp);
    /* 原子重命名替换，绝无并发脏读风险 */
    if (rename(tmp_path, path) != 0) {
        LOG_ERR("uid_map_upsert: rename(%s -> %s) 失败: %s", tmp_path, path, strerror(errno));
        unlink(tmp_path);
        free(entries);
        return UID_MAP_ERR_RENAME;
    }
    free(entries);
    return 0;
}
/* O(log N) 二分折半快速检索 */
const char* uid_map_lookup(const UidMapEntry* entries, int count, uid_t uid) {
    int low = 0;
    int high = count - 1;
    while (low <= high) {
        int mid = low + (high - low) / 2;
        if (entries[mid].uid == uid) {
            return entries[mid].pkg;
        } else if (entries[mid].uid < uid) {
            low = mid + 1;
        } else {
            high = mid - 1;
        }
    }
    return NULL;
}
