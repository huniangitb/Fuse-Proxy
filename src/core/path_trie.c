#include "path_trie.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

TrieNode* trie_create_node(const char* segment) {
    TrieNode* node = calloc(1, sizeof(TrieNode));
    if (node && segment) {
        node->segment = strdup(segment);
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
    free(node);
}

/* 循环条件为 while (p && *p)，杜绝末尾 NULL 指针解引用 */
void trie_insert(TrieNode* root, const char* path, const char* redir_target, bool is_hidden, bool is_ro) {
    if (!path || !root) return;
    TrieNode* curr = root;
    const char* p = path;
    while (*p == '/') p++;
    while (p && *p) {
        const char* next = strchr(p, '/');
        size_t seg_len = next ? (size_t)(next - p) : strlen(p);
        if (seg_len == 0) break;
        TrieNode* child = NULL;
        for (int i = 0; i < curr->child_count; i++) {
            if (curr->children[i] && curr->children[i]->segment &&
                strlen(curr->children[i]->segment) == seg_len &&
                strncmp(curr->children[i]->segment, p, seg_len) == 0) {
                child = curr->children[i];
                break;
            }
        }
        if (!child) {
            child = trie_create_node(NULL);
            if (!child) return;
            child->segment = malloc(seg_len + 1);
            if (!child->segment) {
                free(child);
                return;
            }
            memcpy(child->segment, p, seg_len);
            child->segment[seg_len] = '\0';
            TrieNode** new_children = realloc(curr->children, sizeof(TrieNode*) * (curr->child_count + 1));
            if (!new_children) {
                free(child->segment);
                free(child);
                return;
            }
            curr->children = new_children;
            curr->children[curr->child_count++] = child;
        }
        curr = child;
        p = next;
        while (p && *p == '/') p++;
    }
    if (is_hidden) curr->is_hidden = true;
    if (is_ro)     curr->is_ro = true;
    if (redir_target) {
        free(curr->redir_target);
        curr->redir_target = strdup(redir_target);
    }
}

bool trie_lookup(const TrieNode* root, const char* path, bool* out_hidden, bool* out_ro, char* out_redir, size_t max_len) {
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
        const TrieNode* child = NULL;
        for (int i = 0; i < curr->child_count; i++) {
            if (curr->children[i] && curr->children[i]->segment &&
                strlen(curr->children[i]->segment) == seg_len &&
                strncmp(curr->children[i]->segment, p, seg_len) == 0) {
                child = curr->children[i];
                break;
            }
        }
        if (!child) break;
        curr = child;
        if (curr->is_hidden) hidden = true;
        if (curr->is_ro)     ro = true;
        if (curr->redir_target) {
            redir_base = curr->redir_target;
            redir_suffix = next ? next : "";
        }
        p = next;
        while (p && *p == '/') p++;
    }
    if (out_hidden) *out_hidden = hidden;
    if (out_ro)     *out_ro = ro;
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

bool trie_is_redirect_target(const TrieNode* root, const char* path) {
    if (!root || !path) return false;
    const TrieNode* curr = root;
    const char* p = path;
    while (*p == '/') p++;
    while (p && *p) {
        const char* next = strchr(p, '/');
        size_t seg_len = next ? (size_t)(next - p) : strlen(p);
        if (seg_len == 0) break;
        const TrieNode* child = NULL;
        for (int i = 0; i < curr->child_count; i++) {
            if (curr->children[i] && curr->children[i]->segment &&
                strlen(curr->children[i]->segment) == seg_len &&
                strncmp(curr->children[i]->segment, p, seg_len) == 0) {
                child = curr->children[i];
                break;
            }
        }
        if (!child) return false;
        curr = child;
        p = next;
        while (p && *p == '/') p++;
    }
    return (curr->redir_target != NULL);
}

static bool trie_node_has_rules(const TrieNode* node) {
    if (!node) return false;
    if (node->is_hidden || node->is_ro || node->redir_target) return true;
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
        const TrieNode* child = NULL;
        for (int i = 0; i < curr->child_count; i++) {
            if (curr->children[i] && curr->children[i]->segment &&
                strlen(curr->children[i]->segment) == seg_len &&
                strncmp(curr->children[i]->segment, p, seg_len) == 0) {
                child = curr->children[i];
                break;
            }
        }
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
