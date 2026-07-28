#ifndef PATH_TRIE_H
#define PATH_TRIE_H

#include <stdbool.h>
#include <stddef.h>

/*
 * 路径前缀树（多叉 Trie）。
 *
 * 按路径的 '/' 分段逐层匹配，用于存储纯静态（无通配符 / 无变量）的
 * HIDE / RO / REDIRECT / ALLOW 规则，提供 O(路径段数) 的匹配。
 *
 * 本模块是内聚、零业务依赖的纯数据结构，不引用 AppConfig 或任何配置全局，
 * 可独立单元测试（见 tests/test_trie.c）。
 */
typedef struct TrieNode {
    char *segment;              /* 本节点对应的路径段（不含 '/'） */
    struct TrieNode **children;
    int child_count;
    bool is_hidden;
    bool is_ro;
    char *redir_target;         /* 非 NULL 表示该节点是重定向目标 */
} TrieNode;

/* 创建节点。segment 可为 NULL（根节点）；内部 strdup 拷贝。 */
TrieNode* trie_create_node(const char* segment);

/* 递归释放整棵子树。 */
void trie_free(TrieNode* node);

/* 插入一条路径规则。redir_target 可为 NULL（仅设置 hidden/ro 标记）。 */
void trie_insert(TrieNode* root, const char* path, const char* redir_target, bool is_hidden, bool is_ro);

/*
 * 查询 path 命中的规则。沿路径逐段下降，累积 hidden/ro（含祖先继承），
 * redirect 取最深命中节点的目标并拼接剩余后缀写入 out_redir。
 * 返回是否命中至少一条真实规则（hidden || ro || redirect）。
 * out_hidden / out_ro / out_redir 均可为 NULL。
 */
bool trie_lookup(const TrieNode* root, const char* path, bool* out_hidden, bool* out_ro, char* out_redir, size_t max_len);

/* path 对应节点是否本身就是一个 redirect 目标。 */
bool trie_is_redirect_target(const TrieNode* root, const char* path);

/* path 是否是某条规则的（真）前缀祖先——即其子孙中存在带规则的节点。 */
bool trie_is_ancestor(const TrieNode* root, const char* path);

#endif /* PATH_TRIE_H */
