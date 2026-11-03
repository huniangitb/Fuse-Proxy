/*
 * crash_tail_driver.c — 崩溃诊断「只读本次启动之后」的判别性用例
 *
 * fuse_crash.log 是 append 打开的长期文件，历次启动的 stderr 都留在里面。诊断若
 * 摊尾部固定字节数，会把上一轮启动的 linker 报错读成「本次崩溃原因」。本驱动直编
 * src/core/crash_tail.c，用合成的大小/起点把窗口语义钉住。
 *
 * 判别性：把窗口换回「尾部固定 cap 字节」（旧行为）会让 A2、A11 失败；把「本次启动
 * 后无新增」当成可读会让 A3 失败；cap 截断不丢残行会让 A4 失败。
 */
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "crash_tail.h"

static int g_fail;

static void check(const char* name, bool ok, const char* detail) {
    printf("case=%-52s ok=%d %s\n", name, ok ? 1 : 0, detail ? detail : "");
    if (!ok) g_fail++;
}

static void expect(const char* name, off_t file_size, off_t run_start, size_t cap,
                   bool want_ok, off_t want_start, size_t want_len, bool want_drop) {
    CrashTailWindow w;
    memset(&w, 0x5a, sizeof w);
    bool ok = crash_tail_window(file_size, run_start, cap, &w);
    char detail[160];
    snprintf(detail, sizeof detail, "ok=%d start=%lld len=%zu drop=%d",
             ok ? 1 : 0, (long long)w.start, w.len, w.drop_first_line ? 1 : 0);
    bool match = ok == want_ok;
    if (match && ok) {
        match = w.start == want_start && w.len == want_len && w.drop_first_line == want_drop;
    }
    check(name, match, detail);
}

int main(void) {
    /* A 段：起点锚定 */
    expect("A1_fresh_file_reads_from_zero", 100, 0, 16384, true, 0, 100, false);
    expect("A2_window_starts_at_run_start", 600, 500, 16384, true, 500, 100, false);
    expect("A3_no_output_since_start", 700, 700, 16384, false, 0, 0, false);
    expect("A4_cap_trims_within_window", 20000, 500, 16384, true, 3616, 16384, true);
    expect("A5_unknown_start_falls_back_to_tail", 1000, -1, 400, true, 600, 400, true);
    expect("A6_unknown_start_small_file", 100, -1, 16384, true, 0, 100, false);
    expect("A7_truncated_file_treated_as_unknown", 200, 500, 16384, true, 0, 200, false);
    expect("A8_zero_cap_not_readable", 100, 0, 0, false, 0, 0, false);
    expect("A9_empty_file_not_readable", 0, 0, 16384, false, 0, 0, false);
    check("A10_null_out_rejected", !crash_tail_window(100, 0, 16384, NULL), "");

    /* A11：任何「起点可信」的组合，读回区域都不许落在 run_start 之前——
       这正是旧实现（尾部固定 cap）会违反的不变式。 */
    int bad = 0;
    const off_t sizes[] = {100, 4096, 16384, 20000, 65536};
    const off_t starts[] = {0, 1, 100, 4096, 16383, 20000, 65536};
    for (size_t i = 0; i < sizeof sizes / sizeof sizes[0]; i++) {
        for (size_t j = 0; j < sizeof starts / sizeof starts[0]; j++) {
            if (starts[j] > sizes[i]) continue;
            CrashTailWindow w;
            if (!crash_tail_window(sizes[i], starts[j], 16384, &w)) continue;
            if (w.start < starts[j]) {
                printf("  violate size=%lld start=%lld -> w.start=%lld\n",
                       (long long)sizes[i], (long long)starts[j], (long long)w.start);
                bad++;
            }
        }
    }
    check("A11_window_never_precedes_run_start", bad == 0, bad ? "see above" : "matrix ok");

    if (g_fail) {
        printf("total_failures=%d\n", g_fail);
        return 1;
    }
    printf("all cases passed\n");
    return 0;
}
