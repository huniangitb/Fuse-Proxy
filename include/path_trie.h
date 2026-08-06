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

/* 与 trie_lookup 相同的累积语义（hidden/ro 含祖先继承、redir 取最深命中并拼接后缀），
   额外返回**完整匹配**到路径末尾的最深节点（某段缺失返回 NULL）。
   供 br_resolve 一次性取得 trie 判定所需节点，复用 hidden/ro/redir 结果，
   避免 virtual_ancestor / redirect_target 各自再全路径遍历。 */
const TrieNode* trie_lookup_full(const TrieNode* root, const char* path,
                                 bool* out_hidden, bool* out_ro,
                                 char* out_redir, size_t max_len);

/* path 对应节点是否本身就是一个 redirect 目标。 */
bool trie_is_redirect_target(const TrieNode* root, const char* path);

/* path 是否是某条规则的（真）前缀祖先——即其子孙中存在带规则的节点。 */
bool trie_is_ancestor(const TrieNode* root, const char* path);

/* ================= readdir 目录级批量过滤接口 =================
   供规则模块按目录一次下降、逐条目仅查最后一段（避免每条目从根重复遍历）：
   - trie_walk_to：从 root 沿 path 逐段严格下降，路径**完整存在**才返回节点，
     否则返回 NULL（out_hidden/out_ro 仍输出已匹配前缀的累积标志，与 trie_lookup
     中途 break 的语义一致）；
   - trie_find_child：在 node 的直接子节点中按段查找（node 为 NULL 返回 NULL）；
   - trie_node_has_rules / trie_any_child_has_rules：子树/直接子节点子树含规则判定。 */

/* 严格下降：path 每段都存在才返回最深节点；否则 NULL。
   out_hidden/out_ro 输出根→最深已匹配段的累积 hidden/ro（可 NULL）。 */
const TrieNode* trie_walk_to(const TrieNode* root, const char* path, bool* out_hidden, bool* out_ro);

/* 在 node 的直接子节点中查找 segment 匹配的节点；未找到或 node 为 NULL 返回 NULL。 */
const TrieNode* trie_find_child(const TrieNode* node, const char* seg, size_t seg_len);

/* node 子树（含自身）是否存在规则（hidden/ro/redir）。node 为 NULL 返回 false。 */
bool trie_node_has_rules(const TrieNode* node);

/* node 的直接子节点子树中是否存在规则（等价 trie_is_ancestor 的末端判定）。 */
bool trie_any_child_has_rules(const TrieNode* node);

#endif /* PATH_TRIE_H */
