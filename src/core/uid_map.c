#define _GNU_SOURCE
#include "uid_map.h"
#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* 快速排序辅助函数 */
static int compare_entries(const void* a, const void* b) {
    uid_t uid_a = ((const UidMapEntry*)a)->uid;
    uid_t uid_b = ((const UidMapEntry*)b)->uid;
    if (uid_a < uid_b) return -1;
    if (uid_a > uid_b) return 1;
    return 0;
}
/* 从 CONFIG_DIR/uid.map 文件加载 UID 映射表并进行排序 */
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
    /* 必须在此处执行排序，确保后续 uid_map_lookup 二分查找的正确性 */
    if (count > 0) {
        qsort(entries, (size_t)count, sizeof(UidMapEntry), compare_entries);
    }
    return count;
}
/* 增量写入: 如果 uid 已存在于 uid.map 则更新其包名，否则追加新行 */
int uid_map_upsert(uid_t uid, const char* pkg) {
    char path[PATH_MAX];
    char tmp_path[PATH_MAX];
    snprintf(path, sizeof(path), CONFIG_DIR "/uid.map");
    snprintf(tmp_path, sizeof(tmp_path), CONFIG_DIR "/uid.map.tmp");
    UidMapEntry entries[UID_MAP_MAX_ENTRIES];
    int count = uid_map_load(entries, UID_MAP_MAX_ENTRIES);
    bool updated = false;
    for (int i = 0; i < count; i++) {
        if (entries[i].uid == uid) {
            if (strcmp(entries[i].pkg, pkg) == 0) return 0;
            strncpy(entries[i].pkg, pkg, 127);
            entries[i].pkg[127] = '\0';
            updated = true;
            break;
        }
    }
    if (!updated) {
        if (count >= UID_MAP_MAX_ENTRIES) return -1;
        entries[count].uid = uid;
        strncpy(entries[count].pkg, pkg, 127);
        entries[count].pkg[127] = '\0';
        count++;
    }
    /* 核心安全优化：先写入临时文件，确保写入动作的鲁棒性 */
    FILE *fp = fopen(tmp_path, "we");
    if (!fp) return -1;
    for (int j = 0; j < count; j++) {
        if (fprintf(fp, "%d %s\n", entries[j].uid, entries[j].pkg) < 0) {
            fclose(fp);
            unlink(tmp_path);
            return -1;
        }
    }
    if (fflush(fp) != 0 || fsync(fileno(fp)) != 0) {
        fclose(fp);
        unlink(tmp_path);
        return -1;
    }
    fclose(fp);
    /* 原子重命名替换，绝无并发脏读风险 */
    if (rename(tmp_path, path) != 0) {
        unlink(tmp_path);
        return -1;
    }
    return 0;
}
/* O(log N) 二分折半快速检索 */
const char* uid_map_lookup(const UidMapEntry *entries, int count, uid_t uid) {
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
/* 递归分治：构建数学上完美平衡的二叉搜索树（2-树） */
static UidTreeNode* build_balanced_bst(const UidMapEntry *entries, int start, int end) {
    if (start > end) return NULL;
    int mid = start + (end - start) / 2;
    UidTreeNode* node = malloc(sizeof(UidTreeNode));
    if (!node) return NULL;
    node->uid = entries[mid].uid;
    strncpy(node->pkg, entries[mid].pkg, sizeof(node->pkg) - 1);
    node->pkg[sizeof(node->pkg) - 1] = '\0';
    node->left = build_balanced_bst(entries, start, mid - 1);
    node->right = build_balanced_bst(entries, mid + 1, end);
    return node;
}
/* BST 构建入口 */
UidTreeNode* uid_tree_build_from_array(const UidMapEntry *entries, int count) {
    if (count <= 0 || !entries) return NULL;
    UidMapEntry* temp_arr = malloc(sizeof(UidMapEntry) * (size_t)count);
    if (!temp_arr) return NULL;
    memcpy(temp_arr, entries, sizeof(UidMapEntry) * (size_t)count);
    qsort(temp_arr, (size_t)count, sizeof(UidMapEntry), compare_entries);
    UidTreeNode* root = build_balanced_bst(temp_arr, 0, count - 1);
    free(temp_arr);
    return root;
}
/* 二叉树查找 */
const char* uid_tree_search(const UidTreeNode* root, uid_t uid) {
    const UidTreeNode* curr = root;
    while (curr) {
        if (uid == curr->uid) {
            return curr->pkg;
        } else if (uid < curr->uid) {
            curr = curr->left;
        } else {
            curr = curr->right;
        }
    }
    return NULL;
}
/* 释放二叉树 */
void uid_tree_free(UidTreeNode* root) {
    if (!root) return;
    uid_tree_free(root->left);
    uid_tree_free(root->right);
    free(root);
}