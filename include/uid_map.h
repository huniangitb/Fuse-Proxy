#ifndef UID_MAP_H
#define UID_MAP_H

#include <sys/types.h>

#define UID_MAP_MAX_ENTRIES 1024   /* 旧兼容定义：固定数组最大容量，BSS 存活期可用此值 */
#define UID_MAP_INIT_CAPACITY 256  /* uid_map_upsert 初始堆分配大小，支持动态扩容 */

/* uid_map_upsert 错误码 */
#define UID_MAP_ERR_FULL    -1  /* 条目已满(不再使用，保留兼容) */
#define UID_MAP_ERR_IO      -2  /* 文件操作失败 / 内存分配失败 */
#define UID_MAP_ERR_RENAME  -3  /* 原子重命名失败 */

/* 原有平铺结构定义，保持磁盘加载与快照机制的兼容 */
typedef struct {
    uid_t uid;
    char pkg[128];
} UidMapEntry;

/* 从 CONFIG_DIR/uid.map 文件加载 UID 映射表（加载后按 uid 排序，支持二分查询） */
int uid_map_load(UidMapEntry *entries, int max_entries);

/*
 * 增量写入: 如果 uid 已存在于 uid.map 则更新其包名，否则追加新行。
 * 不会覆写文件中的其他记录。返回 0 成功，负值失败（UID_MAP_ERR_*）。
 */
int uid_map_upsert(uid_t uid, const char* pkg);

/*
 * 用给定快照整体重写 uid.map（tmp + fsync + rename，整表覆盖）。
 * 供后台落盘线程使用：内存表才是权威视图，磁盘表只用于下次启动冷加载；
 * 因此这里不读旧文件、不合并，天然不会留下过期条目。
 * 返回 0 成功，负值失败（UID_MAP_ERR_*）。
 */
int uid_map_save(const UidMapEntry *entries, int count);

/* 平铺数组查询：对已排序的 entries 做 O(log N) 折半匹配 */
const char* uid_map_lookup(const UidMapEntry *entries, int count, uid_t uid);

#endif /* UID_MAP_H */