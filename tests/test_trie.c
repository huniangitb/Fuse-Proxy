#include "config_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

static int g_fail = 0;
#define CHECK(cond) do { if (!(cond)) { printf("FAIL line %d: %s\n", __LINE__, #cond); g_fail++; } } while(0)

/* trie_insert / trie_lookup 的边界与功能覆盖 */
static void test_trie_insert_lookup(void) {
    TrieNode* root = trie_create_node(NULL);
    CHECK(root != NULL);

    /* 基本插入与命中 */
    trie_insert(root, "/Android/data/com.foo/files", "/real/foo", false, false);
    bool hidden = false, ro = false;
    char out_redir[256];
    bool found = trie_lookup(root, "/Android/data/com.foo/files", &hidden, &ro, out_redir, sizeof(out_redir));
    CHECK(found == true);
    CHECK(hidden == false);
    CHECK(ro == false);
    CHECK(strcmp(out_redir, "/real/foo") == 0);

    /* 前缀匹配：父节点未设 redir，子节点命中 */
    char out2[256] = {0};
    hidden = false; ro = false;
    found = trie_lookup(root, "/Android/data/com.foo/files/sub", &hidden, &ro, out2, sizeof(out2));
    CHECK(found == true);
    /* 子路径 redir 应继承父节点 redir_base + suffix */
    CHECK(strcmp(out2, "/real/foo/sub") == 0);

    /* 未命中的独立路径 */
    char out3[256] = {0};
    hidden = false; ro = false;
    found = trie_lookup(root, "/Android/data/com.bar/files", &hidden, &ro, out3, sizeof(out3));
    CHECK(found == false);

    /* is_hidden / is_ro 标记 */
    trie_insert(root, "/Android/obb/com.sec", NULL, true, false);
    char out4[256] = {0};
    hidden = false; ro = false;
    found = trie_lookup(root, "/Android/obb/com.sec", &hidden, &ro, out4, sizeof(out4));
    CHECK(found == true);
    CHECK(hidden == true);
    CHECK(ro == false);

    trie_insert(root, "/Android/media", NULL, false, true);
    char out5[256] = {0};
    hidden = false; ro = false;
    found = trie_lookup(root, "/Android/media/song.mp3", &hidden, &ro, out5, sizeof(out5));
    CHECK(found == true);
    CHECK(hidden == false);
    CHECK(ro == true);

    trie_free(root);
}

/* 空路径、根路径、连续斜杠等边界 */
static void test_trie_edge(void) {
    TrieNode* root = trie_create_node(NULL);
    CHECK(root != NULL);

    /* 空 path 应被安全跳过不崩 */
    trie_insert(root, "", "/x", false, false);
    trie_insert(root, nullptr, "/y", false, false);

    /* 根路径插入 */
    trie_insert(root, "/", "/root_target", false, false);
    bool hidden = false, ro = false;
    char out[256] = {0};
    bool found = trie_lookup(root, "/", &hidden, &ro, out, sizeof(out));
    CHECK(found == true);
    CHECK(strcmp(out, "/root_target") == 0);

    /* 连续斜杠应被归一化跳过 */
    trie_insert(root, "//Android///data//", "/norm", false, false);
    hidden = false; ro = false;
    char out2[256] = {0};
    found = trie_lookup(root, "/Android/data", &hidden, &ro, out2, sizeof(out2));
    CHECK(found == true);
    CHECK(strcmp(out2, "/norm") == 0);

    /* nullptr root 或 nullptr path 不崩，返回 false */
    CHECK(trie_lookup(nullptr, "/x", nullptr, nullptr, nullptr, 0) == false);
    CHECK(trie_lookup(root, nullptr, nullptr, nullptr, nullptr, 0) == false);

    trie_free(root);
}

/* trie_is_redirect_target / trie_is_ancestor 的精准判定 */
static void test_trie_predicates(void) {
    TrieNode* root = trie_create_node(NULL);
    CHECK(root != NULL);

    trie_insert(root, "/Android/data/com.foo", "/real_foo", false, false);

    CHECK(trie_is_redirect_target(root, "/Android/data/com.foo") == true);
    /* 自身不算 ancestor，应返回 false（ancestor 指真前缀） */
    CHECK(trie_is_ancestor(root, "/Android/data/com.foo") == false);
    /* 父路径视为 ancestor */
    CHECK(trie_is_ancestor(root, "/Android/data") == true);
    CHECK(trie_is_ancestor(root, "/Android") == true);
    /* 无关路径 */
    CHECK(trie_is_redirect_target(root, "/Android/obb") == false);
    CHECK(trie_is_ancestor(root, "/Android/obb") == false);

    trie_free(root);
}

/* 超长 segment 不溢出（MAX_PATH_LEN=256 限制内） */
static void test_trie_long_segment(void) {
    TrieNode* root = trie_create_node(NULL);
    CHECK(root != NULL);

    /* 构造 200 字符的 segment，在 MAX_PATH_LEN 内 */
    char long_path[256];
    snprintf(long_path, sizeof(long_path), "/Android/data/%200s", "x");
    trie_insert(root, long_path, "/target_long", false, false);
    bool hidden = false, ro = false;
    char out[256] = {0};
    bool found = trie_lookup(root, long_path, &hidden, &ro, out, sizeof(out));
    CHECK(found == true);
    CHECK(strcmp(out, "/target_long") == 0);

    trie_free(root);
}

int main(void) {
    test_trie_insert_lookup();
    test_trie_edge();
    test_trie_predicates();
    test_trie_long_segment();
    if (g_fail) { printf("FAILED %d\n", g_fail); return 1; }
    printf("all passed\n");
    return 0;
}
