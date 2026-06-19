#ifndef UID_MAP_H
#define UID_MAP_H

#include <sys/types.h>

#define UID_MAP_MAX_ENTRIES 1024

typedef struct {
    uid_t uid;
    char pkg[128];
} UidMapEntry;

/* 从 CONFIG_DIR/uid.map 文件加载 UID 映射表 */
int uid_map_load(UidMapEntry *entries, int max_entries);

/*
 * 增量写入: 如果 uid 已存在于 uid.map 则更新其包名，否则追加新行。
 * 不会覆写文件中的其他记录。返回 0 成功，-1 失败。
 */
int uid_map_upsert(uid_t uid, const char* pkg);

/* 在映射表中查找 uid 对应的包名，返回包名指针或 NULL */
const char* uid_map_lookup(const UidMapEntry *entries, int count, uid_t uid);

#endif
