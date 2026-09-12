#define _GNU_SOURCE
/*
 * build_info.c — 构建水印与设备环境采集实现
 *
 * 约束：
 *   - 只读本机文件（/proc/cpuinfo、/proc/meminfo），失败即跳过该行，
 *     永不因环境采集失败影响启动；
 *   - Android 属性经 __system_property_get（bionic libc 直调，无 binder /
 *     popen，不触发 sys_pkg 注释中的挂起风险），非 Android 不编译该路径；
 *   - 输出截断到 255B/行，中文/长 fingerprint 均安全。
 */
#include "build_info.h"
#include "common.h"
#include <stdio.h>
#include <string.h>
#include <sys/utsname.h>

#ifdef TARGET_ANDROID
/* bionic 导出（<sys/system_properties.h> 已废弃告警，手动声明避免拖入废弃头） */
extern int __system_property_get(const char* name, char* value);
#endif

const char* nsp_git_hash(void) {
    return NSP_GIT_HASH;
}

/* 采集行不带 [proc] 前缀：LOG() 路径由 log_frame_packet 按 g_proc_name
 * 自动添加，直推 log_monitor 环形缓冲的调用方自行拼接（见 log_monitor.c，
 * 与 "[log_monitor] 加载监控忽略规则完成" 等既有行格式对齐）。 */
int nsp_collect_build_headers(const char* proc, char out[][NSP_BUILD_LINE_MAX],
                              int max_lines) {
    if (!out || max_lines <= 0) return 0;
    (void)proc;
    int n = 0;
    snprintf(out[n], NSP_BUILD_LINE_MAX,
             "build: git=%s version=%s mode=%s built=%s %s",
             NSP_GIT_HASH, NSP_PROJECT_VERSION, NSP_BUILD_MODE,
             __DATE__, __TIME__);
    n++;
    if (n >= max_lines) return n;
#ifdef TARGET_ANDROID
    snprintf(out[n], NSP_BUILD_LINE_MAX, "build: target=android compiler=%s",
             __VERSION__);
#else
    snprintf(out[n], NSP_BUILD_LINE_MAX, "build: target=gnu compiler=%s",
             __VERSION__);
#endif
    n++;
    return n;
}

/* 首个 "key:" 行的值（去首尾空白），未找到返回 false */
static bool cpuinfo_first(const char* data, const char* key,
                          char* out, size_t out_sz) {
    size_t klen = strlen(key);
    for (const char* p = data; p && *p; ) {
        const char* nl = strchr(p, '\n');
        size_t llen = nl ? (size_t)(nl - p) : strlen(p);
        if (llen > klen && strncmp(p, key, klen) == 0 && p[klen] == ':') {
            const char* v = p + klen + 1;
            while (*v == ' ' || *v == '\t') v++;
            size_t vlen = (p + llen) - v;
            while (vlen > 0 && (v[vlen - 1] == ' ' || v[vlen - 1] == '\t' ||
                                v[vlen - 1] == '\r')) vlen--;
            if (vlen >= out_sz) vlen = out_sz - 1;
            memcpy(out, v, vlen);
            out[vlen] = '\0';
            return out[0] != '\0';
        }
        if (!nl) break;
        p = nl + 1;
    }
    return false;
}

int nsp_collect_env_headers(const char* proc, char out[][NSP_BUILD_LINE_MAX],
                            int max_lines) {
    if (!out || max_lines <= 0) return 0;
    (void)proc;
    int n = 0;

    /* 内核：uname 一次调用（失败则跳过，不阻断） */
    struct utsname u;
    if (uname(&u) == 0 && n < max_lines) {
        snprintf(out[n], NSP_BUILD_LINE_MAX,
                 "env: uname=%s %s %s %s",
                 u.sysname, u.release, u.version, u.machine);
        n++;
    }

    /* CPU：Hardware（ARM SoC 名）/ model name（x86）首见 + processor 计数 */
    FILE* fp = fopen("/proc/cpuinfo", "r");
    if (fp) {
        char data[8192];
        size_t total = fread(data, 1, sizeof data - 1, fp);
        fclose(fp);
        if (total > 0) {
            data[total] = '\0';
            char hw[128] = {0}, model[128] = {0};
            int ncpu = 0;
            cpuinfo_first(data, "Hardware", hw, sizeof hw);
            cpuinfo_first(data, "model name", model, sizeof model);
            for (const char* p = data; (p = strstr(p, "processor")) != NULL; ) {
                /* 仅统计行首 "processor\t:" 形态，避免误数正文 */
                if (p == data || *(p - 1) == '\n') ncpu++;
                p += 9;
            }
            if ((hw[0] || model[0] || ncpu > 0) && n < max_lines) {
                snprintf(out[n], NSP_BUILD_LINE_MAX,
                         "env: cpu: hardware=%s model=%s ncpu=%d",
                         hw[0] ? hw : "-",
                         model[0] ? model : "-", ncpu);
                n++;
            }
        }
    }

    /* 内存：MemTotal / MemAvailable（KB 原值，诊断低端机 OOM 用） */
    fp = fopen("/proc/meminfo", "r");
    if (fp) {
        char line[256];
        long total_kb = -1, avail_kb = -1;
        while (fgets(line, sizeof line, fp)) {
            if (sscanf(line, "MemTotal: %ld kB", &total_kb) == 1) continue;
            if (sscanf(line, "MemAvailable: %ld kB", &avail_kb) == 1) continue;
            if (total_kb >= 0 && avail_kb >= 0) break;
        }
        fclose(fp);
        if (total_kb >= 0 && n < max_lines) {
            if (avail_kb >= 0)
                snprintf(out[n], NSP_BUILD_LINE_MAX,
                         "env: mem: total=%ldkB avail=%ldkB",
                         total_kb, avail_kb);
            else
                snprintf(out[n], NSP_BUILD_LINE_MAX,
                         "env: mem: total=%ldkB", total_kb);
            n++;
        }
    }

#ifdef TARGET_ANDROID
    /* Android 系统版本：bionic 直调，无 binder（多个属性各自独立，单个失败不影响其余） */
    char rel[64] = {0}, sdk[64] = {0}, model[64] = {0};
    char brand[64] = {0}, device[64] = {0}, display[128] = {0}, fpv[128] = {0};
    __system_property_get("ro.build.version.release", rel);
    __system_property_get("ro.build.version.sdk", sdk);
    __system_property_get("ro.product.model", model);
    __system_property_get("ro.product.brand", brand);
    __system_property_get("ro.product.device", device);
    __system_property_get("ro.build.display.id", display);
    __system_property_get("ro.build.fingerprint", fpv);
    if (n < max_lines) {
        snprintf(out[n], NSP_BUILD_LINE_MAX,
                 "env: android release=%s sdk=%s brand=%s model=%s device=%s display=%s",
                 rel[0] ? rel : "-", sdk[0] ? sdk : "-",
                 brand[0] ? brand : "-", model[0] ? model : "-",
                 device[0] ? device : "-", display[0] ? display : "-");
        n++;
    }
    if (fpv[0] && n < max_lines) {
        snprintf(out[n], NSP_BUILD_LINE_MAX, "env: fingerprint=%s", fpv);
        n++;
    }
#endif
    return n;
}

void nsp_log_build_info(const char* proc) {
    char lines[NSP_BUILD_LINES_MAX][NSP_BUILD_LINE_MAX];
    /* 环境/构建水印行量大且稳定：降为 DEBUG，release 默认 INFO 时不落盘 */
    int n = nsp_collect_build_headers(proc, lines, NSP_BUILD_LINES_MAX);
    for (int i = 0; i < n; i++) LOG_DBG("%s", lines[i]);
    n = nsp_collect_env_headers(proc, lines, NSP_BUILD_LINES_MAX);
    for (int i = 0; i < n; i++) LOG_DBG("%s", lines[i]);
}
