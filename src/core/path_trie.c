#include "path_trie.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* 字典序比较两个路径段（seg 可能非 '\0' 结尾；node->segment 恒 '\0' 结尾）：
   先比较共同前缀字节，前缀相同则短段在前（与 strcmp 的字典序语义一致） */
static int seg_cmp(const char* a, size_t alen, const char* b, size_t blen) {
    size_t m = alen < blen ? alen : blen;
    int c = memcmp(a, b, m);
    if (c != 0) return c;
    return (alen < blen) ? -1 : (alen > blen) ? 1 : 0;
}

/* children 按 segment 字典序有序（trie_insert 维护），二分查找段：O(log n)
   替代原线性扫描 + 每段 strlen，规则量越大收益越明显 */
static const TrieNode* find_child_bin(const TrieNode* node, const char* seg, size_t seg_len) {
    if (!node || !seg) return NULL;
    int lo = 0, hi = node->child_count;
    while (lo < hi) {
        int mid = lo + (hi - lo) / 2;
        const TrieNode* c = node->children[mid];
        int cmp = seg_cmp(seg, seg_len, c->segment, c->seg_len);
        if (cmp < 0)
            hi = mid;
        else if (cmp > 0)
            lo = mid + 1;
        else
            return c;
    }
    return NULL;
}

TrieNode* trie_create_node(const char* segment) {
    TrieNode* node = calloc(1, sizeof(TrieNode));
    if (node && segment) {
        node->segment = strdup(segment);
        node->seg_len = (uint16_t)strlen(segment);
    }
    return node;
}

void trie_free(TrieNode* node) {
    if (!node) return;
    for (int i = 0; i < node->child_count; i++) {
        trie_free(node->children[i]);
    }
    free(node->children);
    free(node->segment);
    free(node->redir_target);
    free(node->ftp_backend);
    free(node);
}

/* 与 trie_lookup 相同的下降与累积语义，额外返回完整匹配到路径末尾的最深节点。
   某段缺失（!child 或 seg_len==0）时返回 NULL，但 out_hidden/out_ro/out_redir
   仍输出已匹配前缀的累积结果（与 trie_lookup 中途 break 语义一致）。
   out_ftp 输出下降过程中最深带 ftp_backend 节点的段名（FTP 最长前缀优先）。 */
const TrieNode* trie_lookup_full(const TrieNode* root, const char* path, bool* out_hidden,
                                 bool* out_ro, char* out_redir, size_t max_len, char* out_ftp,
                                 size_t ftp_max_len) {
    if (!root || !path) return NULL;
    const TrieNode* curr = root;
    const char* p = path;
    while (*p == '/') p++;
    bool hidden = root->is_hidden;
    bool ro = root->is_ro;
    const char* redir_base = root->redir_target;
    const char* redir_suffix = p;
    const char* ftp_bk = root->ftp_backend;
    bool full = true;
    while (p && *p) {
        const char* next = strchr(p, '/');
        size_t seg_len = next ? (size_t)(next - p) : strlen(p);
        if (seg_len == 0) {
            full = false;
            break;
        }
        const TrieNode* child = find_child_bin(curr, p, seg_len);
        if (!child) {
            full = false;
            break;
        }
        curr = child;
        if (curr->is_hidden) hidden = true;
        if (curr->is_ro) ro = true;
        if (curr->redir_target) {
            redir_base = curr->redir_target;
            redir_suffix = next ? next : "";
        }
        if (curr->ftp_backend) ftp_bk = curr->ftp_backend;
        p = next;
        while (p && *p == '/') p++;
    }
    if (out_hidden) *out_hidden = hidden;
    if (out_ro) *out_ro = ro;
    if (out_ftp && ftp_max_len > 0 && ftp_bk) {
        strncpy(out_ftp, ftp_bk, ftp_max_len - 1);
        out_ftp[ftp_max_len - 1] = '\0';
    }
    if (redir_base && out_redir && max_len > 0) {
        size_t blen = strlen(redir_base);
        size_t slen = strlen(redir_suffix);
        if (blen + slen < max_len) {
            snprintf(out_redir, max_len, "%s%s", redir_base, redir_suffix);
        }
    }
    /* 路径完整消耗到末尾（p 为 NULL 或指向 '\0'）才算完整匹配 */
    if (full && p && *p) full = false;
    return full ? curr : NULL;
}

/* 循环条件为 while (p && *p)，杜绝末尾 NULL 指针解引用 */
void trie_insert(TrieNode* root, const char* path, const char* redir_target, bool is_hidden,
                 bool is_ro) {
    if (!path || !root) return;
    TrieNode* curr = root;
    const char* p = path;
    while (*p == '/') p++;
    while (p && *p) {
        const char* next = strchr(p, '/');
        size_t seg_len = next ? (size_t)(next - p) : strlen(p);
        if (seg_len == 0) break;
        TrieNode* child = NULL;
        /* 二分定位插入位置（保持 children 字典序，查找方可二分）；
           段已存在则复用节点（后续仅叠加标志） */
        int lo = 0, hi = curr->child_count;
        while (lo < hi) {
            int mid = lo + (hi - lo) / 2;
            TrieNode* c = curr->children[mid];
            if (seg_cmp(p, seg_len, c->segment, c->seg_len) > 0)
                lo = mid + 1;
            else
                hi = mid;
        }
        if (lo < curr->child_count && curr->children[lo] &&
            seg_cmp(p, seg_len, curr->children[lo]->segment, curr->children[lo]->seg_len) == 0) {
            child = curr->children[lo];
        } else {
            child = trie_create_node(NULL);
            if (!child) return;
            child->segment = malloc(seg_len + 1);
            if (!child->segment) {
                free(child);
                return;
            }
            memcpy(child->segment, p, seg_len);
            child->segment[seg_len] = '\0';
            child->seg_len = (uint16_t)seg_len;
            TrieNode** new_children =
                realloc(curr->children, sizeof(TrieNode*) * (curr->child_count + 1));
            if (!new_children) {
                free(child->segment);
                free(child);
                return;
            }
            curr->children = new_children;
            memmove(&curr->children[lo + 1], &curr->children[lo],
                    sizeof(TrieNode*) * (size_t)(curr->child_count - lo));
            curr->children[lo] = child;
            curr->child_count++;
        }
        curr = child;
        p = next;
        while (p && *p == '/') p++;
    }
    if (is_hidden) curr->is_hidden = true;
    if (is_ro) curr->is_ro = true;
    if (redir_target) {
        free(curr->redir_target);
        curr->redir_target = strdup(redir_target);
    }
}

/* FTP 虚拟前缀插入：沿 prefix 逐段下降（缺段则创建），终点节点记录后端段名。
   最长前缀优先由 trie_lookup_full 下降过程中取最深 ftp_backend 保证；
   prefix 为 "/" 或空时设置在根节点（兜底任意路径命中）。 */
void trie_insert_ftp(TrieNode* root, const char* prefix, const char* backend) {
    if (!root || !prefix || !backend || !backend[0]) return;
    TrieNode* curr = root;
    const char* p = prefix;
    while (*p == '/') p++;
    while (p && *p) {
        const char* next = strchr(p, '/');
        size_t seg_len = next ? (size_t)(next - p) : strlen(p);
        if (seg_len == 0) break;
        TrieNode* child = NULL;
        int lo = 0, hi = curr->child_count;
        while (lo < hi) {
            int mid = lo + (hi - lo) / 2;
            TrieNode* c = curr->children[mid];
            if (seg_cmp(p, seg_len, c->segment, c->seg_len) > 0)
                lo = mid + 1;
            else
                hi = mid;
        }
        if (lo < curr->child_count && curr->children[lo] &&
            seg_cmp(p, seg_len, curr->children[lo]->segment, curr->children[lo]->seg_len) == 0) {
            child = curr->children[lo];
        } else {
            child = trie_create_node(NULL);
            if (!child) return;
            child->segment = malloc(seg_len + 1);
            if (!child->segment) {
                free(child);
                return;
            }
            memcpy(child->segment, p, seg_len);
            child->segment[seg_len] = '\0';
            child->seg_len = (uint16_t)seg_len;
            TrieNode** new_children =
                realloc(curr->children, sizeof(TrieNode*) * (curr->child_count + 1));
            if (!new_children) {
                free(child->segment);
                free(child);
                return;
            }
            curr->children = new_children;
            memmove(&curr->children[lo + 1], &curr->children[lo],
                    sizeof(TrieNode*) * (size_t)(curr->child_count - lo));
            curr->children[lo] = child;
            curr->child_count++;
        }
        curr = child;
        p = next;
        while (p && *p == '/') p++;
    }
    free(curr->ftp_backend);
    curr->ftp_backend = strdup(backend);
}

bool trie_lookup(const TrieNode* root, const char* path, bool* out_hidden, bool* out_ro,
                 char* out_redir, size_t max_len) {
    if (!root || !path) return false;
    const TrieNode* curr = root;
    const char* p = path;
    while (*p == '/') p++;
    bool hidden = root->is_hidden;
    bool ro = root->is_ro;
    const char* redir_base = root->redir_target;
    const char* redir_suffix = p;
    while (p && *p) {
        const char* next = strchr(p, '/');
        size_t seg_len = next ? (size_t)(next - p) : strlen(p);
        if (seg_len == 0) break;
        const TrieNode* child = find_child_bin(curr, p, seg_len);
        if (!child) break;
        curr = child;
        if (curr->is_hidden) hidden = true;
        if (curr->is_ro) ro = true;
        if (curr->redir_target) {
            redir_base = curr->redir_target;
            redir_suffix = next ? next : "";
        }
        p = next;
        while (p && *p == '/') p++;
    }
    if (out_hidden) *out_hidden = hidden;
    if (out_ro) *out_ro = ro;
    if (redir_base && out_redir && max_len > 0) {
        size_t blen = strlen(redir_base);
        size_t slen = strlen(redir_suffix);
        if (blen + slen < max_len) {
            snprintf(out_redir, max_len, "%s%s", redir_base, redir_suffix);
        }
    }
    /* matched 语义：命中至少一条真实规则（含祖先继承的 redirect），
       而非仅"路径途经了无规则的中间节点"——后者会误判 /Android/data/<未配置包> */
    return (hidden || ro || redir_base != NULL);
}

/* 该路径是否**本身**是某条 REDIRECT 的虚拟前缀（即它会被重定向）。
   函数名沿用历史（`trie_is_redirect_target`），与"重定向的真实目标"无关：
   真实目标是普通路径，照常列举与访问。
   注：树在根到该节点的下降途中只要某段不存在即返回 false（非祖先语义，
   祖先判定见 trie_is_ancestor）。 */
bool trie_is_redirect_target(const TrieNode* root, const char* path) {
    if (!root || !path) return false;
    const TrieNode* curr = root;
    const char* p = path;
    while (*p == '/') p++;
    while (p && *p) {
        const char* next = strchr(p, '/');
        size_t seg_len = next ? (size_t)(next - p) : strlen(p);
        if (seg_len == 0) break;
        const TrieNode* child = find_child_bin(curr, p, seg_len);
        if (!child) return false;
        curr = child;
        p = next;
        while (p && *p == '/') p++;
    }
    return (curr->redir_target != NULL);
}

/* 节点子树（含自身）是否存在规则（hidden/ro/redir/ftp）——header 已声明为公开接口 */
bool trie_node_has_rules(const TrieNode* node) {
    if (!node) return false;
    if (node->is_hidden || node->is_ro || node->redir_target || node->ftp_backend) return true;
    for (int i = 0; i < node->child_count; i++) {
        if (trie_node_has_rules(node->children[i])) return true;
    }
    return false;
}

/* 在 node 的直接子节点中查找 segment 匹配的节点（children 有序，二分查找） */
const TrieNode* trie_find_child(const TrieNode* node, const char* seg, size_t seg_len) {
    return find_child_bin(node, seg, seg_len);
}

/* 严格下降：path 每段都存在才返回最深节点；否则 NULL。
   out_hidden/out_ro 输出根→最深已匹配段的累积标志（与 trie_lookup 中途
   break 的累积语义一致，供 readdir 目录级缓存按段增量判定）。 */
const TrieNode* trie_walk_to(const TrieNode* root, const char* path, bool* out_hidden,
                             bool* out_ro) {
    if (!root || !path) return NULL;
    const TrieNode* curr = root;
    const char* p = path;
    while (*p == '/') p++;
    bool hidden = root->is_hidden;
    bool ro = root->is_ro;
    while (p && *p) {
        const char* next = strchr(p, '/');
        size_t seg_len = next ? (size_t)(next - p) : strlen(p);
        if (seg_len == 0) break;
        const TrieNode* child = trie_find_child(curr, p, seg_len);
        if (!child) break; /* 某段缺失：与 trie_lookup 语义一致，停在已匹配段 */
        curr = child;
        if (curr->is_hidden) hidden = true;
        if (curr->is_ro) ro = true;
        p = next;
        while (p && *p == '/') p++;
    }
    if (out_hidden) *out_hidden = hidden;
    if (out_ro) *out_ro = ro;
    /* 路径完整匹配到末尾（无剩余段）才视为命中节点 */
    while (p && *p == '/') p++;
    return (p && *p) ? NULL : curr;
}

bool trie_any_child_has_rules(const TrieNode* node) {
    if (!node) return false;
    for (int i = 0; i < node->child_count; i++) {
        if (trie_node_has_rules(node->children[i])) return true;
    }
    return false;
}

bool trie_is_ancestor(const TrieNode* root, const char* path) {
    if (!root || !path) return false;
    const TrieNode* curr = root;
    const char* p = path;
    while (*p == '/') p++;
    if (*p == '\0') {
        for (int i = 0; i < curr->child_count; i++) {
            if (curr->children[i] && trie_node_has_rules(curr->children[i])) return true;
        }
        return false;
    }
    while (p && *p) {
        const char* next = strchr(p, '/');
        size_t seg_len = next ? (size_t)(next - p) : strlen(p);
        if (seg_len == 0) break;
        const TrieNode* child = find_child_bin(curr, p, seg_len);
        if (!child) return false;
        curr = child;
        p = next;
        while (p && *p == '/') p++;
    }
    for (int i = 0; i < curr->child_count; i++) {
        if (curr->children[i] && trie_node_has_rules(curr->children[i])) return true;
    }
    return false;
}
