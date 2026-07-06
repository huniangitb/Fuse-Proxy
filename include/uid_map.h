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

/* 二叉搜索树（2-树）节点定义 */
typedef struct UidTreeNode {
    uid_t uid;
    char pkg[128];
    struct UidTreeNode *left;
    struct UidTreeNode *right;
} UidTreeNode;

/* 从 CONFIG_DIR/uid.map 文件加载 UID 映射表 */
int uid_map_load(UidMapEntry *entries, int max_entries);

/*
 * 增量写入: 如果 uid 已存在于 uid.map 则更新其包名，否则追加新行。
 * 不会覆写文件中的其他记录。返回 0 成功，负值失败（UID_MAP_ERR_*）。
 */
int uid_map_upsert(uid_t uid, const char* pkg);

/* 向下兼容的传统平铺查询，内部已自动升级为 O(log N) 的折半匹配 */
const char* uid_map_lookup(const UidMapEntry *entries, int count, uid_t uid);

/* 
 * 二叉搜索树（2-树）专用操作 API 
 * 支持无序数组自动构建高度平衡的搜索树，并提供常数级的检索效率。
 */
UidTreeNode* uid_tree_build_from_array(const UidMapEntry *entries, int count);
const char* uid_tree_search(const UidTreeNode* root, uid_t uid);
void uid_tree_free(UidTreeNode* root);

#endif /* UID_MAP_H */