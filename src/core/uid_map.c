#define _GNU_SOURCE
#include "uid_map.h"
#include "common.h"
#include <stdio.h>
#include <string.h>

int uid_map_load(UidMapEntry *entries, int max_entries) {
    char path[PATH_MAX];
    snprintf(path, sizeof(path), CONFIG_DIR "/uid.map");
    FILE *fp = fopen(path, "re");
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
    return count;
}

int uid_map_upsert(uid_t uid, const char* pkg) {
    char path[PATH_MAX];
    snprintf(path, sizeof(path), CONFIG_DIR "/uid.map");

    /* 读取现有所有记录 */
    UidMapEntry entries[UID_MAP_MAX_ENTRIES];
    int count = uid_map_load(entries, UID_MAP_MAX_ENTRIES);

    /* 检查 uid 是否已存在 */
    for (int i = 0; i < count; i++) {
        if (entries[i].uid == uid) {
            /* 包名未变则跳过 */
            if (strcmp(entries[i].pkg, pkg) == 0) return 0;
            /* 更新包名 */
            strncpy(entries[i].pkg, pkg, 127);
            entries[i].pkg[127] = '\0';
            /* 全量回写（行长度可能变化，无法原地替换） */
            FILE *fp = fopen(path, "w");
            if (!fp) return -1;
            for (int j = 0; j < count; j++)
                fprintf(fp, "%d %s\n", entries[j].uid, entries[j].pkg);
            fclose(fp);
            return 0;
        }
    }

    /* uid 不存在，追加新行 */
    if (count >= UID_MAP_MAX_ENTRIES) return -1;
    FILE *fp = fopen(path, "a");
    if (!fp) return -1;
    fprintf(fp, "%d %s\n", uid, pkg);
    fclose(fp);
    return 0;
}

const char* uid_map_lookup(const UidMapEntry *entries, int count, uid_t uid) {
    for (int i = 0; i < count; i++) {
        if (entries[i].uid == uid) return entries[i].pkg;
    }
    return NULL;
}
