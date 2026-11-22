#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
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
        if (sscanf(line, "%u %127s", &u, p) == 2) {
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
/* 把整张表写成 uid.map：先写 .tmp、fsync、再 rename 原子替换。
 * 调用方持有权威表（内存视图或已合并的本地副本）。 */
static int uid_map_write_all(UidMapEntry* entries, int count) {
    char path[PATH_MAX];
    char tmp_path[PATH_MAX];
    snprintf(path, sizeof(path), CONFIG_DIR "/uid.map");
    snprintf(tmp_path, sizeof(tmp_path), CONFIG_DIR "/uid.map.tmp");
    /* 先写临时文件，确保写入动作的鲁棒性 */
    FILE* fp = fopen(tmp_path, "we");
    if (!fp) {
        LOG_ERR("uid_map: fopen(%s) 失败: %s", tmp_path, strerror(errno));
        return UID_MAP_ERR_IO;
    }
    for (int j = 0; j < count; j++) {
        if (fprintf(fp, "%d %s\n", entries[j].uid, entries[j].pkg) < 0) {
            LOG_ERR("uid_map: fprintf 失败: %s", strerror(errno));
            fclose(fp);
            unlink(tmp_path);
            return UID_MAP_ERR_IO;
        }
    }
    if (fflush(fp) != 0 || fsync(fileno(fp)) != 0) {
        LOG_ERR("uid_map: fflush/fsync 失败: %s", strerror(errno));
        fclose(fp);
        unlink(tmp_path);
        return UID_MAP_ERR_IO;
    }
    fclose(fp);
    /* 原子重命名替换，绝无并发脏读风险 */
    if (rename(tmp_path, path) != 0) {
        LOG_ERR("uid_map: rename(%s -> %s) 失败: %s", tmp_path, path, strerror(errno));
        unlink(tmp_path);
        return UID_MAP_ERR_RENAME;
    }
    return 0;
}
int uid_map_upsert(uid_t uid, const char* pkg) {
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

    int rc = uid_map_write_all(entries, count);
    free(entries);
    return rc;
}

/* 用给定条目整体重写 uid.map（tmp + fsync + rename）。
 * 供后台落盘线程使用：调用方持有权威内存表，磁盘表只用于下次启动冷加载，
 * 因此这里不读旧文件、不合并——整表覆盖，天然不会留下过期条目。
 * entries 不要求有序，内部排序后写出。返回 0 成功，负值失败（UID_MAP_ERR_*）。 */
int uid_map_save(const UidMapEntry* entries, int count) {
    if (!entries || count <= 0) return UID_MAP_ERR_IO;
    UidMapEntry* copy = malloc((size_t)count * sizeof(UidMapEntry));
    if (!copy) {
        LOG_ERR("uid_map_save: malloc(%d) 失败", count);
        return UID_MAP_ERR_IO;
    }
    memcpy(copy, entries, (size_t)count * sizeof(UidMapEntry));
    qsort(copy, (size_t)count, sizeof(UidMapEntry), compare_entries);
    int rc = uid_map_write_all(copy, count);
    free(copy);
    return rc;
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
