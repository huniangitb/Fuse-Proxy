/*
 * events_status_driver.c — 事件通道归属快照的状态机与采集边界
 *
 * nsp_fs_events / nsp_fs_query 是抽象 UDS，内核保证名字唯一：谁先 bind 谁收订阅。
 * 归属现在固定给全局实例，但「此刻谁绑着」必须能被 log_ctl 查出来。本驱动直编
 * src/core/nsp_events_status.c，覆盖纯状态机（不依赖设备）与采集函数的两条边界：
 * 开关关闭时零扫描、开关打开时结果自洽。
 *
 * 判别性：把「名字没人绑」判成 ok（或不给 unknown-owner 分支）会让 B2、B6 失败；
 * 让禁用态也去扫 /proc 会让 B8 失败（daemon_count 变成非零）。
 */
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "nsp_events_status.h"

static int g_fail;

static void check(const char* name, bool ok, const char* detail) {
    printf("case=%-52s ok=%d %s\n", name, ok ? 1 : 0, detail ? detail : "");
    if (!ok) g_fail++;
}

static void expect_state(const char* name, const NspEventsStatus* st, const char* want) {
    const char* got = nsp_events_state(st);
    char detail[128];
    snprintf(detail, sizeof detail, "state=%s want=%s", got ? got : "(null)", want);
    check(name, got && strcmp(got, want) == 0, detail);
}

static bool hint_empty(const NspEventsStatus* st) {
    const char* h = nsp_events_hint(st);
    return h && h[0] == '\0';
}

int main(void) {
    NspEventsStatus st;

    /* B 段：纯状态机 */
    memset(&st, 0, sizeof st);
    st.enabled = false;
    st.events_inode = 123;
    expect_state("B1_disabled_wins_over_socket", &st, "disabled");
    check("B2_disabled_explains_switch", !hint_empty(&st), "");

    memset(&st, 0, sizeof st);
    st.enabled = true;
    expect_state("B3_no_binder_is_missing", &st, "missing");
    check("B4_missing_has_hint", !hint_empty(&st), "");

    memset(&st, 0, sizeof st);
    st.enabled = true;
    st.events_inode = 42;
    st.query_inode = 43;
    expect_state("B5_bound_but_owner_unknown", &st, "unknown-owner");

    st.events_owner_pid = 100;
    st.query_owner_pid = 100;
    st.events_owner = NSP_EVENTS_OWNER_GLOBAL;
    st.query_owner = NSP_EVENTS_OWNER_GLOBAL;
    expect_state("B6_global_owner_is_ok", &st, "ok");
    check("B7_ok_has_no_hint", hint_empty(&st), "");

    st.events_owner = NSP_EVENTS_OWNER_MEDIA;
    expect_state("B8_media_owner_is_reported", &st, "media-owner");
    check("B9_media_owner_has_hint", !hint_empty(&st), "");

    st.events_owner = NSP_EVENTS_OWNER_FOREIGN;
    expect_state("B10_foreign_owner_is_reported", &st, "foreign");
    check("B11_foreign_owner_has_hint", !hint_empty(&st), "");

    /* 开关关闭但状态里还留着旧 inode：仍按「未启用」呈现，不报故障 */
    memset(&st, 0, sizeof st);
    st.enabled = false;
    st.events_inode = 7;
    st.events_owner_pid = 7;
    st.events_owner = NSP_EVENTS_OWNER_MEDIA;
    expect_state("B12_disabled_ignores_stale_socket", &st, "disabled");

    /* B 段：采集边界 */
    memset(&st, 0x5a, sizeof st);
    nsp_events_status_collect(&st, false, "/tmp/nsp-events-status-test");
    bool disabled_clean = !st.enabled && st.daemon_count == 0 && st.global_daemons == 0 &&
                          st.media_daemons == 0 && st.events_inode == 0 &&
                          st.events_owner_pid == 0 && st.query_inode == 0 &&
                          st.query_owner_pid == 0;
    check("B13_disabled_collect_skips_proc_scan", disabled_clean,
          "关闭态不得扫 /proc");
    check("B14_disabled_collect_keeps_status_path",
          strstr(st.last_fail_path, "events_socket.status") != NULL, st.last_fail_path);

    memset(&st, 0, sizeof st);
    nsp_events_status_collect(&st, true, "/tmp/nsp-events-status-test");
    bool consistent = st.daemon_count == st.global_daemons + st.media_daemons &&
                      st.global_daemons >= 0 && st.media_daemons >= 0;
    check("B15_enabled_collect_counts_consistent", consistent, "");
    const char* state = nsp_events_state(&st);
    check("B16_enabled_collect_reports_state", state && strcmp(state, "disabled") != 0,
          state ? state : "(null)");

    /* C 段：命令行分类（纯函数，不依赖设备）。
       判别性：把「整串里有 fuse_daemon」当实例，C3 会变成 GLOBAL，
       C7 会变成 GLOBAL，C9 的计数也会从 2 涨到 4——现场就表现为
       用户敲 pidof fuse_daemon 的当下多出一个「全局实例」。 */
    static const struct {
        const char* cmd;
        NspEventsOwner want;
        const char* name;
    } cmd_cases[] = {
        { "fuse_daemon /mnt/nsp_global --root=/data/media", NSP_EVENTS_OWNER_GLOBAL,
          "C1_global_instance" },
        { "/data/adb/modules/Namespace-Proxy/bin/fuse_daemon /mnt/nsp_media --media-fuse",
          NSP_EVENTS_OWNER_MEDIA, "C2_media_instance_by_abs_path" },
        { "sh -c pidof fuse_daemon", NSP_EVENTS_OWNER_NONE, "C3_shell_mention_is_not_instance" },
        { "injector --passive", NSP_EVENTS_OWNER_NONE, "C4_injector_is_not_instance" },
        { "", NSP_EVENTS_OWNER_NONE, "C5_empty_cmdline" },
        { "fuse_daemon_x /mnt/nsp_global", NSP_EVENTS_OWNER_NONE, "C6_name_prefix_is_not_match" },
        { "fuse_daemon --media-fuse /mnt/nsp_global", NSP_EVENTS_OWNER_MEDIA,
          "C7_flag_any_position" },
    };
    for (size_t i = 0; i < sizeof(cmd_cases) / sizeof(cmd_cases[0]); i++) {
        NspEventsOwner got = nsp_events_classify_cmdline(cmd_cases[i].cmd);
        char detail[96];
        snprintf(detail, sizeof detail, "kind=%d want=%d", (int)got, (int)cmd_cases[i].want);
        check(cmd_cases[i].name, got == cmd_cases[i].want, detail);
    }
    check("C8_null_cmdline_is_none", nsp_events_classify_cmdline(NULL) == NSP_EVENTS_OWNER_NONE,
          "");

    /* 真实实例两条，另加一条「命令行里提到 fuse_daemon」的 shell：
       扫描结果必须仍然只有两条，且类型分布是 1 全局 + 1 媒体。 */
    static const char* with_mentions[] = {
        "fuse_daemon /mnt/nsp_global --root=/data/media --ready-fd=16 -f",
        "/data/adb/modules/Namespace-Proxy/bin/fuse_daemon /mnt/nsp_media --media-fuse",
        "sh -c pidof fuse_daemon",
        "sh -c log_ctl events; pidof fuse_daemon",
    };
    int counted = 0, counted_media = 0;
    for (size_t i = 0; i < sizeof(with_mentions) / sizeof(with_mentions[0]); i++) {
        NspEventsOwner kind = nsp_events_classify_cmdline(with_mentions[i]);
        if (kind == NSP_EVENTS_OWNER_NONE) continue;
        counted++;
        if (kind == NSP_EVENTS_OWNER_MEDIA) counted_media++;
    }
    char count_detail[96];
    snprintf(count_detail, sizeof count_detail, "counted=%d media=%d", counted, counted_media);
    check("C9_mentions_do_not_inflate_count", counted == 2 && counted_media == 1, count_detail);

    if (g_fail) {
        printf("total_failures=%d\n", g_fail);
        return 1;
    }
    printf("all cases passed\n");
    return 0;
}
