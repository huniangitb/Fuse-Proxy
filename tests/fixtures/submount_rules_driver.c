/* Actual mount_manager.c regression: no namespaces, mounts or FUSE I/O.
 * Only external facts/side effects are stubbed; both production callers run.
 * common_parse_user_layer comes from linked production common.c.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#define read_file_dynamic submount_test_read_file_dynamic
#define log_internal submount_test_log_internal
#define kill submount_test_kill
#ifndef MOUNT_MANAGER_SRC
#define MOUNT_MANAGER_SRC "mount_manager.c"
#endif
#include MOUNT_MANAGER_SRC
#undef read_file_dynamic
#undef log_internal
#undef kill

static const char* const test_pkg = "com.test.app";
static AppConfig app, category;
AppConfig g_global_cfg;
InjectMethod g_inject_method = INJECT_METHOD_V1;
static bool app_present, category_present, system_pkg;
static int lock_depth, category_calls, category_user, app_user;
static bool category_system;
static char native_paths[16][256], recorded[16][256];
static int native_count, recorded_count, combined_calls, failures, checks;

static void check(const char* name, bool ok) {
    printf("case=%s ok=%d\n", name, ok);
    checks++;
    failures += !ok;
}
static void reset(void) {
    memset(&app, 0, sizeof app);
    memset(&category, 0, sizeof category);
    memset(&g_global_cfg, 0, sizeof g_global_cfg);
    app_present = category_present = system_pkg = false;
    category_calls = 0;
    category_user = app_user = -1;
    native_count = recorded_count = combined_calls = 0;
    g_mount_cache_count = 0;
}
static bool conflict(const AppConfig* cfg, const AppConfig* cat, const char* path) {
#if SUBMOUNT_LEGACY_HELPER
    (void)cat;
    /* Signature adapter only: do not normalize or alter the old predicate. */
    return submount_conflicts_with_rules_locked(cfg, path, test_pkg);
#else
    return submount_conflicts_with_rules_locked(cfg, cat, path);
#endif
}
static void set_rule(AppConfig* cfg, int type, const char* path) {
    static RedirectRule redirects[3];
    static char* hides[3];
    static char* ros[3];
    int slot = cfg == &app ? 0 : cfg == &category ? 1 : 2;
    if (type < 2) {
        memset(&redirects[slot], 0, sizeof redirects[slot]);
        snprintf(redirects[slot].virtual_prefix, MAX_PATH_LEN, "%s", path);
        redirects[slot].is_allow = type == 1;
        cfg->redir_rules = &redirects[slot];
        cfg->redir_count = 1;
    } else if (type == 2) {
        hides[slot] = (char*)path;
        cfg->hide_rules = &hides[slot];
        cfg->hide_count = 1;
    } else {
        ros[slot] = (char*)path;
        cfg->ro_rules = &ros[slot];
        cfg->ro_count = 1;
    }
}

/* Synthetic mountinfo forces the production mount-state parser fallback. */
char* submount_test_read_file_dynamic(const char* path, size_t* out_size, size_t max_size) {
    (void)path;
    (void)max_size;
    const char* text = "100 99 0:1 / /storage/emulated rw - sdcardfs sdcardfs rw\n";
    if (out_size) *out_size = strlen(text);
    return strdup(text);
}
int submount_test_kill(pid_t pid, int sig) {
    (void)pid;
    if (sig != 0) abort();
    return 0;
}
void submount_test_log_internal(LogLevel level, const char* format, ...) {
    (void)level;
    (void)format;
}
const char* get_active_mnt_src(void) { return "/mnt/test_fuse"; }
const char* get_media_mnt_src(void) { return "/mnt/test_media"; }
const char* fast_strstr(const char* haystack, const char* needle) { return strstr(haystack, needle); }
int ns_probe_target_view(int pid, const char* target, const char* src, bool* mounted, bool* ours) {
    (void)pid; (void)target; (void)src; (void)mounted; (void)ours;
    return -1;
}
bool ns_mount_needs_repair(int pid, const char* path, bool ours) {
    (void)pid; (void)path; (void)ours;
    abort(); /* Synthetic native target must never enter the repair path. */
}
int ns_bind_mount(int pid, const char* src, const char* target) {
    (void)pid; (void)src; (void)target;
    abort();
}
int ns_umount_recursive(int pid, const char* target) {
    (void)pid; (void)target;
    abort();
}
void cleanup_app_mounts(int pid, const char* target, const char* backup, uid_t uid) {
    (void)pid; (void)target; (void)backup; (void)uid;
    abort();
}
int ns_find_native_submounts(int pid, const char* base, char out[][256], int max) {
    (void)pid;
    if (strcmp(base, "/storage/emulated") != 0 || native_count > max) abort();
    memcpy(out, native_paths, (size_t)native_count * sizeof native_paths[0]);
    return native_count;
}
static int record_preserve(const char* target, char paths[][256], int count) {
    if (strcmp(target, "/storage/emulated") != 0 || count < 0 || count > 16 || lock_depth) abort();
    recorded_count = count;
    memcpy(recorded, paths, (size_t)count * sizeof recorded[0]);
    combined_calls++;
    return 0;
}
int ns_combined_mount(int pid, const char* pkg, const char* src, const char* target,
                      const char* backup, char paths[][256], int count, int readiness_ms) {
    (void)pid; (void)pkg; (void)src; (void)backup; (void)readiness_ms;
    return record_preserve(target, paths, count);
}
int ns_combined_mount_async(int pid, const char* pkg, const char* src, const char* target,
                            const char* backup, char paths[][256], int count) {
    (void)pid; (void)pkg; (void)src; (void)backup;
    return record_preserve(target, paths, count);
}
void config_lock_read(void) { if (lock_depth++) abort(); }
void config_unlock_read(void) { if (--lock_depth) abort(); }
AppConfig* find_app_cfg_locked(const char* pkg, int user) {
    (void)pkg;
    if (lock_depth != 1) abort();
    app_user = user;
    return app_present ? &app : nullptr;
}
AppConfig* find_category_cfg_locked(bool is_system, int user) {
    if (lock_depth != 1) abort();
    category_calls++;
    category_system = is_system;
    category_user = user;
    return category_present ? &category : nullptr;
}
bool category_has_rules_locked(bool is_system, int user) {
    AppConfig* cfg = find_category_cfg_locked(is_system, user);
    return cfg && (cfg->redir_count || cfg->hide_count || cfg->ro_count || cfg->sandbox);
}
bool sys_pkg_is_system(const char* pkg) { (void)pkg; return system_pkg; }
void get_target_storage_path(uid_t uid, char* path, size_t size) {
    (void)uid;
    snprintf(path, size, "/storage/emulated");
}
void update_uid_map(uid_t uid, const char* pkg) { (void)uid; (void)pkg; }
void add_tracked(int pid) { (void)pid; }
void mark_injected(int pid) { (void)pid; }
void print_active_rules(const char* pkg, int pid, uid_t uid, const char* trigger) {
    (void)pkg; (void)pid; (void)uid; (void)trigger;
}

static void helper_matrix(void) {
    const int users[] = {0, 10, 999};
    const char* types[] = {"REDIRECT", "ALLOW", "HIDE", "RO"};
    for (int u = 0; u < 3; u++) for (int scope = 0; scope < 3; scope++) for (int t = 0; t < 4; t++) {
        reset();
        AppConfig* cfg = scope == 0 ? &app : scope == 1 ? &category : &g_global_cfg;
        char raw[128], name[128];
        snprintf(raw, sizeof raw, "/%d/Android/data", users[u]);
        snprintf(name, sizeof name, "user%d_scope%d_%s", users[u], scope, types[t]);
        set_rule(cfg, t, "/Android/data/other/files");
        check(name, conflict(&app, &category, raw));
        set_rule(cfg, t, "/");
        snprintf(name, sizeof name, "root_user%d_scope%d_%s", users[u], scope, types[t]);
        check(name, conflict(&app, &category, raw));
    }
    reset();
    set_rule(&app, 2, "/Android/data");
    check("already_relative", conflict(&app, nullptr, "/Android/data"));
    check("rule_parent", conflict(&app, nullptr, "/10/Android/data/pkg/files"));
    check("candidate_user_root", conflict(&app, nullptr, "/10"));
    check("sibling_data2", !conflict(&app, nullptr, "/10/Android/data2"));
    check("numeric_name_not_user", !conflict(&app, nullptr, "/12_34/Android/data"));
    check("numeric_overflow_fail_closed", conflict(&app, nullptr, "/4294967296/Android/data"));
    set_rule(&app, 2, "/Android/123/files");
    check("nested_numeric_component_kept", conflict(&app, nullptr, "/999/Android/123"));
    set_rule(&app, 2, "/123/Android/data");
    check("only_first_user_layer_stripped", conflict(&app, nullptr, "/10/123/Android/data"));
    reset();
    set_rule(&app, 1, "/Download");
    set_rule(&category, 2, "/Download");
    check("allow_does_not_bypass_mediation", conflict(&app, &category, "/0/Download"));
    reset();
    app.sandbox = category.sandbox = g_global_cfg.sandbox = true;
    const char* native[] = {"/0/Android/data", "/10/Android/obb", "/999/Android/media/com.test.app/files", "/Android/data"};
    for (int i = 0; i < 4; i++) check(native[i], !conflict(&app, &category, native[i]));
}

static bool same_preserved_paths(void) {
    if (recorded_count != native_count) return false;
    for (int i = 0; i < native_count; i++) {
        if (strcmp(recorded[i], native_paths[i]) != 0) return false;
    }
    return true;
}

static void caller_matrix(void) {
    const int users[] = {0, 10, 999};
    for (int sync = 0; sync < 2; sync++) for (int u = 0; u < 3; u++) for (int scope = 0; scope < 3; scope++) for (int t = 0; t < 4; t++) for (int root = 0; root < 2; root++) {
        reset();
        app_present = scope == 0;
        category_present = scope == 1;
        set_rule(scope == 0 ? &app : scope == 1 ? &category : &g_global_cfg, t, root ? "/" : "/Android/data");
        snprintf(native_paths[0], 256, "/storage/emulated/%d/Android/data", users[u]);
        snprintf(native_paths[1], 256, "/storage/emulated/%d/Android/data2", users[u]);
        native_count = 2;
        uid_t uid = (uid_t)users[u] * NSP_PER_USER_UID_STRIDE + 10123;
        int rc = sync ? perform_app_mount_sync(test_pkg, 1234, uid, "/unused", 0)
                      : perform_app_mount(test_pkg, 1234, uid, "/unused", "test");
        char name[128];
        snprintf(name, sizeof name, "%s_user%d_scope%d_type%d_root%d_preserve", sync ? "sync" : "async", users[u], scope, t, root);
        check(name, rc == 0 && combined_calls == 1 && recorded_count == (root ? 0 : 1) &&
                    (root || strcmp(recorded[0], native_paths[1]) == 0) && app_user == users[u] && lock_depth == 0);
        if (scope == 1) check("caller_category_identity", category_calls >= 2 && category_user == users[u] && !category_system);
    }
    for (int sync = 0; sync < 2; sync++) for (int mode = 0; mode < 3; mode++) {
        reset();
        app_present = category_present = true;
        /* App rule triggers injection, but only the category touches data. */
        set_rule(&app, 2, "/Unrelated");
        set_rule(&category, 3, "/Android/data");
        system_pkg = mode == 2;
        uid_t uid = mode == 0 ? 10123 : mode == 1 ? 1000 : 10123;
        snprintf(native_paths[0], 256, "/storage/emulated/0/Android/data");
        native_count = 1;
        int rc = sync ? perform_app_mount_sync(test_pkg, 1234, uid, "/unused", 0)
                      : perform_app_mount(test_pkg, 1234, uid, "/unused", "test");
        check("category_even_with_active_app", rc == 0 && combined_calls == 1 && recorded_count == 0 &&
              category_calls == 1 && category_system == (mode != 0) && category_user == 0);
    }
    for (int sync = 0; sync < 2; sync++) for (int u = 0; u < 3; u++) {
        reset();
        app_present = true;
        app.sandbox = true;
        snprintf(native_paths[0], 256, "/storage/emulated/%d/Android/data", users[u]);
        snprintf(native_paths[1], 256, "/storage/emulated/%d/Android/obb", users[u]);
        snprintf(native_paths[2], 256, "/storage/emulated/%d/Android/media/com.test.app", users[u]);
        native_count = 3;
        uid_t uid = (uid_t)users[u] * NSP_PER_USER_UID_STRIDE + 10123;
        int rc = sync ? perform_app_mount_sync(test_pkg, 1234, uid, "/unused", 0)
                      : perform_app_mount(test_pkg, 1234, uid, "/unused", "test");
        check("sandbox_native_passthrough_physical_paths", rc == 0 && combined_calls == 1 && recorded_count == 3 &&
              same_preserved_paths());
    }
}
int main(void) {
    helper_matrix();
    caller_matrix();
    printf("submount_rules checks=%d failures=%d legacy=%d\n", checks, failures, SUBMOUNT_LEGACY_HELPER);
    return failures ? 1 : 0;
}
