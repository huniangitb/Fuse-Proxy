/* ================= 全局替换式挂载方案（注入方法 v2/v3，卸载优先） =================
 * 对应 scripts/global.sh 的 replace/restore/status，injector 内建实现。
 * 目标设备不支持 MS_REC：备份/替换/恢复全部逐节点枚举 mountinfo 后单个
 * MS_BIND（父先子后 bind、最深优先 MNT_DETACH 卸载），确保不遗漏系统
 * 子挂载节点（f2fs 直通 Android/data|obb、嵌套跨用户 fuse 视图）。
 * 多用户网格：installer/androidwritable/user 三族 × 每用户 id 全量处理；
 * 备份仅取一个族（优先级 user > androidwritable > installer），三族共用。
 *
 * 本文件从原 ns_utils.c 拆出（可维护性重构）：mountinfo 枚举与族根工具
 * （ns_read_mountinfo_pid/ns_is_family_root/ns_parse_family_root 等）供 ns_utils.c
 * 的 combined mount Step J preserve 恢复共用，故非 static 导出。
 */
#include "common.h"
#include "fast_search.h"
#include "ns_utils.h"
#include "ns_global_replace.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mount.h>

/* ================= 全局替换式挂载方案（注入方法 v2/v3，卸载优先） =================
 * 对应 scripts/global.sh 的 replace/restore/status，injector 内建实现。
 * 目标设备不支持 MS_REC：备份/替换/恢复全部逐节点枚举 mountinfo 后单个
 * MS_BIND（父先子后 bind、最深优先 MNT_DETACH 卸载），确保不遗漏系统
 * 子挂载节点（f2fs 直通 Android/data|obb、嵌套跨用户 fuse 视图）。
 * 多用户网格：installer/androidwritable/user 三族 × 每用户 id 全量处理；
 * 备份仅取一个族（优先级 user > androidwritable > installer），三族共用。
 */

/* mountinfo 全量读取上限：真实设备（多用户 + 嵌套视图 + f2fs 直通）可达 1900+ 行，
   旧上限 512 会截断族根（行号 1894+）与 nsp_global（1934 行），导致替换静默失败 */
#ifndef NS_MOUNTINFO_MAX
#define NS_MOUNTINFO_MAX 4096
#endif

/* 读取指定进程的 mountinfo（本函数不进入命名空间，仅解析文件） */
int ns_read_mountinfo_pid(int pid, NsMountEntry* out, int max) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mountinfo", pid);
    FILE* fp = fopen(path, "re");
    if (!fp) return -1;
    int count = 0;
    char line[4096];
    while (fgets(line, sizeof(line), fp) && count < max) {
        char mp[PATH_MAX] = {0}, dev[64] = {0};
        if (sscanf(line, "%*d %*d %63s %*s %4095s", dev, mp) != 2) continue;
        const char* sep = fast_strstr(line, " - ");
        char fstype[64] = {0}, src[PATH_MAX] = {0};
        if (sep) {
            if (sscanf(sep + 3, "%63s %4095s", fstype, src) < 1) src[0] = '\0';
        }
        strncpy(out[count].mount_point, mp, PATH_MAX - 1);
        out[count].mount_point[PATH_MAX - 1] = '\0';
        strncpy(out[count].source, src, PATH_MAX - 1);
        out[count].source[PATH_MAX - 1] = '\0';
        strncpy(out[count].fstype, fstype, sizeof(out[count].fstype) - 1);
        out[count].fstype[sizeof(out[count].fstype) - 1] = '\0';
        strncpy(out[count].dev, dev, sizeof(out[count].dev) - 1);
        out[count].dev[sizeof(out[count].dev) - 1] = '\0';
        int d = 0;
        for (char* p = mp; *p; p++)
            if (*p == '/') d++;
        out[count].depth = d;
        count++;
    }
    fclose(fp);
    return count;
}

bool ns_is_digit_char(char c) {
    return c >= '0' && c <= '9';
}

/* 判断是否为 emulated 族根：/mnt/(installer|androidwritable|user)/<数字>/emulated */
bool ns_is_family_root(const char* mp) {
    static const char* const families[] = {"installer", "androidwritable", "user"};
    if (strncmp(mp, "/mnt/", 5) != 0) return false;
    const char* p = mp + 5;
    for (int i = 0; i < 3; i++) {
        size_t flen = strlen(families[i]);
        if (strncmp(p, families[i], flen) == 0 && p[flen] == '/') {
            const char* q = p + flen + 1;
            if (!ns_is_digit_char(*q)) return false;
            while (ns_is_digit_char(*q)) q++;
            return strcmp(q, "/emulated") == 0;
        }
    }
    return false;
}

/* 提取族根的 family 索引（0=installer,1=androidwritable,2=user）与用户 id，失败返回 -1 */
int ns_parse_family_root(const char* mp, int* user_id) {
    static const char* const families[] = {"installer", "androidwritable", "user"};
    if (strncmp(mp, "/mnt/", 5) != 0) return -1;
    const char* p = mp + 5;
    for (int i = 0; i < 3; i++) {
        size_t flen = strlen(families[i]);
        if (strncmp(p, families[i], flen) == 0 && p[flen] == '/') {
            const char* q = p + flen + 1;
            if (!ns_is_digit_char(*q)) return -1;
            int id = 0;
            while (ns_is_digit_char(*q)) {
                id = id * 10 + (*q - '0');
                q++;
            }
            if (strcmp(q, "/emulated") != 0) return -1;
            if (user_id) *user_id = id;
            return i;
        }
    }
    return -1;
}

/* 收集 base 前缀下的挂载点（含/不含自身，含/不含 fuse 类型），不排序 */
int ns_gather_mounts_under(const NsMountEntry* all, int n, const char* base, bool include_self,
                           bool include_fuse, NsMountEntry* out, int max) {
    size_t blen = strlen(base);
    int count = 0;
    for (int i = 0; i < n && count < max; i++) {
        const char* mp = all[i].mount_point;
        if (strncmp(mp, base, blen) != 0) continue;
        if (mp[blen] != '/' && mp[blen] != '\0') continue;
        if (!include_self && strcmp(mp, base) == 0) continue;
        if (!include_fuse && fast_strstr(all[i].fstype, "fuse") != nullptr) continue;
        out[count++] = all[i];
    }
    return count;
}

/* 统计 base 前缀下匹配的挂载点数量（与 ns_gather_mounts_under 同规则，仅计数） */
int ns_count_mounts_under(const NsMountEntry* all, int n, const char* base, bool include_self,
                          bool include_fuse) {
    size_t blen = strlen(base);
    int count = 0;
    for (int i = 0; i < n; i++) {
        const char* mp = all[i].mount_point;
        if (strncmp(mp, base, blen) != 0) continue;
        if (mp[blen] != '/' && mp[blen] != '\0') continue;
        if (!include_self && strcmp(mp, base) == 0) continue;
        if (!include_fuse && fast_strstr(all[i].fstype, "fuse") != nullptr) continue;
        count++;
    }
    return count;
}

/* 按深度降序排序（最深优先，用于卸载顺序） */
void ns_sort_deepest_first(NsMountEntry* arr, int n) {
    for (int i = 0; i < n; i++) {
        for (int j = i + 1; j < n; j++) {
            if (arr[j].depth > arr[i].depth) {
                NsMountEntry t = arr[i];
                arr[i] = arr[j];
                arr[j] = t;
            }
        }
    }
}
/* 按深度升序排序（最浅优先，用于 bind 顺序：父先子后） */
void ns_sort_shallowest_first(NsMountEntry* arr, int n) {
    for (int i = 0; i < n; i++) {
        for (int j = i + 1; j < n; j++) {
            if (arr[j].depth < arr[i].depth) {
                NsMountEntry t = arr[i];
                arr[i] = arr[j];
                arr[j] = t;
            }
        }
    }
}

/* 备份点有效性：0=未挂载(可新建), 1=已挂载且为系统视图备份(有效), -1=已被项目 FUSE 视图污染。
   关键：系统视图备份的 bind 视图，mountinfo source 是 fsname=/dev/fuse（fstype=fuse），
   **这是有效备份的正常特征**，绝不能判为污染；仅当 source/fstype 含 fuse_daemon
   （项目 FUSE 视图，如崩溃恢复二次替换叠上去的代理 bind）时才判为污染 */
int ns_backup_point_state(int pid, const char* path) {
    NsMountEntry* all = malloc(NS_MOUNTINFO_MAX * sizeof(NsMountEntry));
    if (!all) return 0;
    int n = ns_read_mountinfo_pid(pid, all, NS_MOUNTINFO_MAX);
    if (n <= 0) {
        free(all);
        return 0;
    }
    int st = 0;
    for (int i = 0; i < n; i++) {
        if (strcmp(all[i].mount_point, path) != 0) continue;
        if (fast_strstr(all[i].source, "fuse_daemon") != nullptr ||
            fast_strstr(all[i].fstype, "fuse_daemon") != nullptr) {
            st = -1;
            break;
        }
        st = 1;
        break;
    }
    free(all);
    return st;
}

struct GlobalReplaceArgs {
    const char* fuse_src;
    const char* backup_root;
    bool skip_backup;
};

/* 程序生命周期内节点备份一次标志（父进程侧）：首次替换成功后置位，
   后续替换跳过已有备份节点的备份 bind，只补充新增用户；成功 restore 后
   清零（备份树已卸载消费，下一次替换需重新备份）。 */
static bool g_global_backup_done = false;

struct AppRestoreArgs {
    char fuse_src[PATH_MAX];
    char backup_root[PATH_MAX];
    int user_id;
};

/* ==================== 单族根还原（备份树 → 族根） ====================
   把 root（/mnt/<族>/<uid>/emulated）从备份树 btop 还原：
     1. 卸下 root 上当前全部挂载（最深优先，含项目 FUSE bind 与传播子挂载）
     2. mkdir root
     3. 按**父先子后**把备份树各节点 bind 回 root（只 bind 顶层会丢失
        Android/data|obb 等 f2fs 直通子挂载）
     4. 置 MS_SHARED 恢复传播
   bsub/bn：**已按最浅优先排序**的备份树节点（调用方收集）。
   scratch/scratch_cap：收集 root 当前挂载的临时数组。
   返回 0=全部节点绑定成功；-1=有节点失败（root 可能不完整，但备份树仍在，
   可重试——调用方据此保留备份副本）。
   本函数同时服务于全局恢复、替换失败回滚与崩溃恢复，是「从备份树还原一个族根」
   的唯一出口。 */
static int restore_root_from_backup(const char* root, const char* btop, const NsMountEntry* bsub,
                                    int bn, const NsMountEntry* all, int n, NsMountEntry* scratch,
                                    int scratch_cap) {
    int cn = ns_gather_mounts_under(all, n, root, true, true, scratch, scratch_cap);
    if (cn >= scratch_cap) {
        LOG_ERR("还原: 族根 %s 子挂载达到 %d 上限，拒绝静默截断（还原将不完整）", root,
                scratch_cap);
        return -1;
    }
    ns_sort_deepest_first(scratch, cn);
    for (int k = 0; k < cn; k++) {
        for (int t = 0; t < 8; t++) {
            if (umount2(scratch[k].mount_point, MNT_DETACH) == 0) break;
            if (errno == EINVAL) break;
        }
    }
    if (mkdir_recursive((char*)root) != 0 && errno != EEXIST) {
        LOG_WRN("还原: mkdir %s 失败: %s", root, strerror(errno));
        return -1;
    }
    int failed = 0;
    for (int k = 0; k < bn; k++) {
        const char* rel = bsub[k].mount_point + strlen(btop); /* "" 或 "/0/Android/data" */
        char target[PATH_MAX];
        snprintf(target, sizeof(target), "%s%s", root, rel);
        if (mkdir_recursive(target) != 0) {
            LOG_WRN("还原: mkdir %s 失败", target);
            failed++;
            continue;
        }
        if (mount(bsub[k].mount_point, target, nullptr, MS_BIND, nullptr) != 0) {
            LOG_WRN("还原: bind %s -> %s 失败: %s", bsub[k].mount_point, target, strerror(errno));
            failed++;
            continue;
        }
        LOG_DBG("还原: bind %s -> %s", bsub[k].mount_point, target);
    }
    if (mount(nullptr, root, nullptr, MS_SHARED, nullptr) != 0) {
        LOG_WRN("还原: 置 MS_SHARED %s 失败: %s（传播不可用）", root, strerror(errno));
    }
    return failed ? -1 : 0;
}

/* ==================== 替换失败回滚 ====================
   替换步骤先卸族根全部挂载再 bind fuse_src；任一步失败若直接返回，族根就停在
   **裸挂载点**（/mnt/{user,androidwritable,installer}/… 下系统存储视图整体消失，
   且与备份树不再对应）。备份树就在手边，故失败时把**本次已动过的族根**（含失败者
   本身，其挂载已被卸下）逐一根 bind 回去。
   备份树按 uid 存放（backup_root/user_<uid>/emulated），三族是同源视图，故任一族根
   都可用该 uid 的备份还原。
   每次迭代重读 mountinfo：回滚本身在改变挂载表，进入 do_global_replace 时的快照已
   过期（不含替换阶段新加的 bind），用它卸载会漏掉节点。
   返回 0=全部族根回滚成功；-1=有族根无法回滚（备份缺失或 bind 失败，已 loud 告警，
   备份树保留待重试）。 */
static int rollback_replaced_roots(const NsMountEntry* roots, int count, const char* backup_root) {
    if (count <= 0) return 0;
    NsMountEntry* all = malloc(NS_MOUNTINFO_MAX * sizeof(NsMountEntry));
    NsMountEntry* bsub = malloc(128 * sizeof(NsMountEntry));
    NsMountEntry* scratch = malloc(128 * sizeof(NsMountEntry));
    if (!all || !bsub || !scratch) {
        free(all);
        free(bsub);
        free(scratch);
        LOG_ERR("全局替换回滚: 分配内存失败，无法回滚（族根可能停在裸挂载点）");
        return -1;
    }
    bool failed = false;
    for (int i = 0; i < count; i++) {
        const char* root = roots[i].mount_point;
        int n = ns_read_mountinfo_pid(getpid(), all, NS_MOUNTINFO_MAX);
        if (n <= 0) {
            LOG_ERR("全局替换回滚: 读取 mountinfo 失败，族根 %s 无法回滚", root);
            failed = true;
            continue;
        }
        int uid = 0;
        (void)ns_parse_family_root(root, &uid);
        char btop[PATH_MAX];
        snprintf(btop, sizeof(btop), "%s/user_%d/emulated", backup_root, uid);
        if (ns_backup_point_state(getpid(), btop) != 1) {
            LOG_ERR("全局替换回滚: 族根 %s 的备份点 %s 不可用，无法回滚", root, btop);
            failed = true;
            continue;
        }
        int bn = ns_gather_mounts_under(all, n, btop, true, true, bsub, 128);
        if (bn <= 0 || bn >= 128) {
            LOG_ERR("全局替换回滚: 备份点 %s 下挂载数异常(%d)，无法回滚族根 %s", btop, bn, root);
            failed = true;
            continue;
        }
        ns_sort_shallowest_first(bsub, bn);
        if (restore_root_from_backup(root, btop, bsub, bn, all, n, scratch, 128) != 0) {
            LOG_ERR("全局替换回滚: 族根 %s 还原不完整（备份树保留待重试）", root);
            failed = true;
            continue;
        }
        LOG("全局替换回滚: 族根 %s 已从备份 %s 还原", root, btop);
    }
    free(all);
    free(bsub);
    free(scratch);
    return failed ? -1 : 0;
}

/* 在目标命名空间内执行：备份一个族 + 三族全部替换 */
static int do_global_replace(void* raw) {
    struct GlobalReplaceArgs* args = (struct GlobalReplaceArgs*)raw;
    const char* fuse_src = args->fuse_src;
    const char* backup_root = args->backup_root;
    bool skip_backup = args->skip_backup;
    /* NsMountEntry 单条约 8.3KB，栈上声明大数组会叠加超 8MB 栈上限导致 SIGSEGV，
       全部改为堆分配 */
    NsMountEntry* all = malloc(NS_MOUNTINFO_MAX * sizeof(NsMountEntry));
    NsMountEntry* roots = malloc(128 * sizeof(NsMountEntry));
    NsMountEntry* sub = malloc(128 * sizeof(NsMountEntry));
    if (!all || !roots || !sub) {
        free(all);
        free(roots);
        free(sub);
        LOG_ERR("全局替换: 分配内存失败");
        return -1;
    }
    int n = ns_read_mountinfo_pid(getpid(), all, NS_MOUNTINFO_MAX);
    if (n <= 0) {
        free(all);
        free(roots);
        free(sub);
        log_ns_error("[global_replace] read mountinfo failed n=%d errno=%d\n", n, errno);
        LOG_ERR("全局替换: 读取 mountinfo 失败");
        return -1;
    }
    LOG_DBG("全局替换: mountinfo 共 %d 行, fuse_src=%s, backup_root=%s", n, fuse_src, backup_root);

    /* 项目 FUSE 源的 major:minor：bind 视图与源共享 superblock，
       以此判定族根是否已是项目 FUSE 视图（重入场景） */
    char src_dev[64] = {0};
    for (int i = 0; i < n; i++) {
        if (strcmp(all[i].mount_point, fuse_src) == 0) {
            strncpy(src_dev, all[i].dev, sizeof(src_dev) - 1);
            break;
        }
    }
    LOG_DBG("全局替换: fuse_src=%s dev=%s", fuse_src, src_dev[0] ? src_dev : "(未挂载)");

    /* 1. 枚举全部族根（触顶即拒绝：固定缓冲静默截断会导致部分族根不备份/
       不替换仍报成功——真机多用户 × 三族可达 1900+ mountinfo 行） */
    int root_count = 0;
    bool root_truncated = false;
    for (int i = 0; i < n; i++) {
        if (ns_is_family_root(all[i].mount_point)) {
            if (root_count >= 128) {
                root_truncated = true;
                break;
            }
            roots[root_count++] = all[i];
            LOG_DBG("全局替换: 族根[%d] %s dev=%s fstype=%s", root_count - 1, all[i].mount_point,
                    all[i].dev, all[i].fstype);
        }
    }
    if (root_truncated) {
        LOG_ERR("全局替换: 族根超过 128 上限，拒绝静默截断（部分族根将不被替换）");
        free(all);
        free(roots);
        free(sub);
        return -1;
    }
    if (root_count == 0) {
        LOG_WRN("全局替换: 未找到任何 emulated 族根，跳过");
        free(all);
        free(roots);
        free(sub);
        return 0;
    }

    /* 2. 选择备份族：优先级 user(2) > androidwritable(1) > installer(0) */
    int backup_family = -1;
    for (int fam = 2; fam >= 0; fam--) {
        bool exists = false;
        for (int i = 0; i < root_count; i++) {
            int uid = 0;
            if (ns_parse_family_root(roots[i].mount_point, &uid) == fam) {
                exists = true;
                break;
            }
        }
        if (exists) {
            backup_family = fam;
            break;
        }
    }
    if (backup_family < 0) {
        free(all);
        free(roots);
        free(sub);
        LOG_ERR("全局替换: 无法确定备份族");
        return -1;
    }
    static const char* const fam_names[] = {"installer", "androidwritable", "user"};
    LOG("全局替换: 备份族=%s, 共 %d 个族根", fam_names[backup_family], root_count);

    /* 3. 备份：对备份族每个用户，逐节点 bind 到 backup_root/user_<id>/emulated。
       生命周期一次：skip_backup 置位后已有备份点直接跳过，仅新增用户走补充备份 */
    for (int i = 0; i < root_count; i++) {
        int uid = 0;
        if (ns_parse_family_root(roots[i].mount_point, &uid) != backup_family) continue;
        const char* root = roots[i].mount_point;
        char backup_top[PATH_MAX];
        snprintf(backup_top, sizeof(backup_top), "%s/user_%d/emulated", backup_root, uid);
        /* 重入防护：族根已是项目 FUSE 视图（FUSE 崩溃自动恢复后的二次替换），
           备份应已存在；若此时再备份会把代理视图叠在已有系统备份之上，跳过 */
        bool root_is_proxy = (src_dev[0] && strcmp(roots[i].dev, src_dev) == 0) ||
                             fast_strstr(roots[i].fstype, "fuse_daemon") != nullptr ||
                             fast_strstr(roots[i].source, "fuse_daemon") != nullptr;
        if (root_is_proxy) {
            LOG_WRN("全局替换: 族根 %s 已是项目 FUSE 视图，跳过备份（重入）", root);
            continue;
        }
        /* 污染检查：备份顶层已挂载为 fuse 则拒绝 */
        int st = ns_backup_point_state(getpid(), backup_top);
        if (st < 0) {
            LOG_ERR("全局替换: 备份点 %s 已被挂载为 fuse(污染)，拒绝替换", backup_top);
            free(all);
            free(roots);
            free(sub);
            return -1;
        }
        if (st == 1) {
            if (skip_backup)
                LOG_DBG("全局替换: 备份点 %s 生命周期内已备份，跳过", backup_top);
            else
                LOG("全局替换: 备份点 %s 已有有效备份，跳过（避免叠 bind）", backup_top);
            continue;
        }
        if (skip_backup)
            LOG("全局替换: 生命周期内已备份，发现新增用户 %d，补充备份 %s", uid, backup_top);
        /* 收集该族根全部挂载点（含自身与 fuse 子挂载） */
        int sn = ns_gather_mounts_under(all, n, root, true, true, sub, 128);
        if (sn >= 128) {
            LOG_ERR("全局替换: 族根 %s 子挂载达到 128 上限，拒绝静默截断（备份将不完整）", root);
            free(all);
            free(roots);
            free(sub);
            return -1;
        }
        ns_sort_shallowest_first(sub, sn); /* 父先子后 bind */
        for (int k = 0; k < sn; k++) {
            const char* rel = sub[k].mount_point + strlen(root); /* "" 或 "/0/Android/data" */
            char target[PATH_MAX];
            snprintf(target, sizeof(target), "%s%s", backup_top, rel);
            if (mkdir_recursive(target) != 0) {
                log_ns_error("[global_replace] mkdir %s failed errno=%d (%s)\n", target, errno,
                             strerror(errno));
                LOG_ERR("全局替换: mkdir %s 失败: %s", target, strerror(errno));
                free(all);
                free(roots);
                free(sub);
                return -1;
            }
            if (mount(sub[k].mount_point, target, nullptr, MS_BIND, nullptr) != 0) {
                log_ns_error("[global_replace] backup bind %s -> %s failed errno=%d (%s)\n",
                             sub[k].mount_point, target, errno, strerror(errno));
                LOG_ERR("全局替换: 备份 bind %s -> %s 失败: %s", sub[k].mount_point, target,
                        strerror(errno));
                free(all);
                free(roots);
                free(sub);
                return -1;
            }
            LOG_DBG("全局替换: 备份 %s -> %s", sub[k].mount_point, target);
        }
        /* 备份树脱离传播组（MS_PRIVATE|MS_REC）：备份 bind 的源（族根/子挂载）为
           共享挂载，绑定后与源同处一个传播组；随后替换步骤以 MNT_DETACH 卸族根
           顶层时，内核沿传播组杀掉“同位置的子挂载”（顶层存活、备份子节点消失
           → 还原时丢失 0/Android/data）。置私有后备份成为独立快照，卸载传播
           不再命中；此后新起的应用经 ns 克隆看到的备份同样为私有副本 */
        if (mount(nullptr, backup_top, nullptr, MS_PRIVATE | MS_REC, nullptr) != 0) {
            log_ns_error("[global_replace] MS_PRIVATE %s failed errno=%d (%s)\n", backup_top, errno,
                         strerror(errno));
            LOG_ERR("全局替换: 置 MS_PRIVATE %s 失败: %s（备份将被替换卸载传播破坏）", backup_top,
                    strerror(errno));
            free(all);
            free(roots);
            free(sub);
            return -1;
        }
    }

    /* 4. 替换：三族全部族根，最深优先卸载后 bind fuse_src，并置 MS_SHARED 传播。
       事务性：任一族根任一步失败即把**本次已动过的全部族根**（含失败者本身，
       其挂载已被卸下）从备份树 bind 回去——绝不留下裸挂载点。 */
    int moved = 0; /* roots[0..moved) 已被本次替换步骤动过（卸载/替换），失败需回滚 */
    for (int i = 0; i < root_count; i++) {
        const char* root = roots[i].mount_point;
        int sn = ns_gather_mounts_under(all, n, root, true, true, sub, 128);
        if (sn >= 128) {
            LOG_ERR("全局替换: 族根 %s 子挂载达到 128 上限，拒绝静默截断（替换将不完整）", root);
            goto replace_failed;
        }
        /* 即将卸载该族根：此后无论哪一步失败都要把它纳入回滚范围 */
        moved = i + 1;
        ns_sort_deepest_first(sub, sn); /* 最深优先卸载 */
        for (int k = 0; k < sn; k++) {
            for (int t = 0; t < 8; t++) {
                if (umount2(sub[k].mount_point, MNT_DETACH) == 0) break;
                if (errno == EINVAL) break; /* 本就不是挂载点 */
            }
        }
        if (mkdir_recursive((char*)root) != 0) {
            LOG_WRN("全局替换: mkdir %s 失败: %s", root, strerror(errno));
        }
        if (mount(fuse_src, root, nullptr, MS_BIND, nullptr) != 0) {
            log_ns_error("[global_replace] replace bind %s -> %s failed errno=%d (%s)\n", fuse_src,
                         root, errno, strerror(errno));
            LOG_ERR("全局替换: bind %s -> %s 失败: %s", fuse_src, root, strerror(errno));
            goto replace_failed;
        }
        if (mount(nullptr, root, nullptr, MS_SHARED, nullptr) != 0) {
            log_ns_error("[global_replace] MS_SHARED %s failed errno=%d (%s)\n", root, errno,
                         strerror(errno));
            LOG_ERR("全局替换: 置 MS_SHARED %s 失败: %s（传播不可用，替换视为失败）", root,
                    strerror(errno));
            goto replace_failed;
        }
        LOG_DBG("全局替换: %s -> %s", root, fuse_src);
    }
    free(all);
    free(roots);
    free(sub);
    return 0;

replace_failed:
    LOG_ERR("全局替换: 失败，从备份树回滚已动过的 %d 个族根（避免族根停在裸挂载点）", moved);
    if (rollback_replaced_roots(roots, moved, backup_root) != 0)
        LOG_ERR("全局替换: 回滚不完整，系统视图可能仍不完整（备份树保留待重试）");
    free(all);
    free(roots);
    free(sub);
    return -1;
}

int ns_global_replace_system(int mnt_ns_pid, const char* fuse_src, const char* backup_root) {
    if (!fuse_src || !backup_root) return -1;
    /* 生命周期一次：已备份且当前全量已替换时不再进 ns 操作，直接返回 */
    if (g_global_backup_done &&
        ns_global_status(mnt_ns_pid, fuse_src) == NSP_GLOBAL_STATUS_REPLACED) {
        LOG_DBG("全局替换: 生命周期内已备份且状态为已替换，跳过");
        return 0;
    }
    struct GlobalReplaceArgs args = {fuse_src, backup_root, g_global_backup_done};
    int child_err = 0;
    int ret = run_in_mnt_ns_timeout(mnt_ns_pid, do_global_replace, &args, &child_err, 15000);
    if (ret != 0) {
        LOG_ERR("全局替换失败 (ret=%d, err=%d)", ret, child_err);
    } else {
        g_global_backup_done = true;
    }
    return ret;
}

/* 在目标命名空间内执行：从备份恢复三族所有用户视图 */
static int do_global_restore(void* raw) {
    const char* backup_root = (const char*)raw;
    NsMountEntry* all = malloc(NS_MOUNTINFO_MAX * sizeof(NsMountEntry));
    NsMountEntry* bsub = malloc(128 * sizeof(NsMountEntry));
    NsMountEntry* cur = malloc(128 * sizeof(NsMountEntry));
    if (!all || !bsub || !cur) {
        free(all);
        free(bsub);
        free(cur);
        return -1;
    }
    int n = ns_read_mountinfo_pid(getpid(), all, NS_MOUNTINFO_MAX);
    if (n <= 0) {
        free(all);
        free(bsub);
        free(cur);
        return -1;
    }
    bool failed = false; /* 任一 mkdir/mount 失败即置位：保留备份副本并返回非零，
                              调用方（崩溃恢复/关机还原）据此记录错误并重试 */
    /* 枚举备份顶层：backup_root/user_<id>/emulated */
    size_t blen = strlen(backup_root);
    for (int i = 0; i < n; i++) {
        const char* btop = all[i].mount_point;
        if (strncmp(btop, backup_root, blen) != 0 || btop[blen] != '/') continue;
        if (strncmp(btop + blen + 1, "user_", 5) != 0) continue;
        const char* q = btop + blen + 1 + 5;
        if (!ns_is_digit_char(*q)) continue;
        int uid = 0;
        while (ns_is_digit_char(*q)) {
            uid = uid * 10 + (*q - '0');
            q++;
        }
        if (strcmp(q, "/emulated") != 0) continue;
        /* 校验备份点未被 fuse 污染 */
        if (ns_backup_point_state(getpid(), btop) != 1) {
            LOG_WRN("全局恢复: 备份点 %s 无效或已被污染，跳过用户 %d", btop, uid);
            continue;
        }
        /* 收集备份树全部挂载点（父先子后 bind 用） */
        int bn = ns_gather_mounts_under(all, n, btop, true, true, bsub, 128);
        if (bn >= 128) {
            LOG_ERR("全局恢复: 备份点 %s 子挂载达到 128 上限，拒绝静默截断（恢复将不完整）", btop);
            free(all);
            free(bsub);
            free(cur);
            return -1;
        }
        ns_sort_shallowest_first(bsub, bn);
        /* 对三族该用户的族根逐一恢复 */
        for (int fam = 0; fam < 3; fam++) {
            static const char* const fam_names[] = {"installer", "androidwritable", "user"};
            char root[PATH_MAX];
            snprintf(root, sizeof(root), "/mnt/%s/%d/emulated", fam_names[fam], uid);
            /* 卸载当前族根全部挂载 → bind 备份树（父先子后）→ 置 MS_SHARED：
               与替换失败回滚共用同一出口（restore_root_from_backup） */
            if (restore_root_from_backup(root, btop, bsub, bn, all, n, cur, 128) != 0) {
                failed = true;
                continue;
            }
            LOG_DBG("全局恢复: 用户 %d 族 %s 已还原", uid, fam_names[fam]);
        }
        /* 卸载备份点（最深优先）：仅在全部恢复成功时执行——任一节点失败时
           保留备份树作为恢复副本（崩溃恢复/关机还原重试的唯一数据源），
           避免把瞬态挂载失败变成系统视图永久丢失 */
        if (!failed) {
            ns_sort_deepest_first(bsub, bn);
            for (int k = 0; k < bn; k++) {
                for (int t = 0; t < 8; t++) {
                    if (umount2(bsub[k].mount_point, MNT_DETACH) == 0) break;
                    if (errno == EINVAL) break;
                }
            }
        }
    }
    free(all);
    free(bsub);
    free(cur);
    if (failed) {
        LOG_ERR("全局恢复: 部分节点恢复失败，保留备份副本待重试");
        return -1;
    }
    return 0;
}

int ns_global_restore_system(int mnt_ns_pid, const char* backup_root) {
    if (!backup_root) return -1;
    int child_err = 0;
    int ret =
        run_in_mnt_ns_timeout(mnt_ns_pid, do_global_restore, (void*)backup_root, &child_err, 15000);
    if (ret != 0) {
        LOG_ERR("全局恢复失败 (ret=%d, err=%d)", ret, child_err);
    } else {
        /* 备份树已卸载消费：清零一次标志，下一次替换需重新备份 */
        g_global_backup_done = false;
    }
    return ret;
}

/* 在应用命名空间内执行：卸载项目 FUSE 并 bind 回备份（幂等） */
static int do_restore_app_fuse(void* raw) {
    struct AppRestoreArgs* args = (struct AppRestoreArgs*)raw;
    NsMountEntry* all = malloc(NS_MOUNTINFO_MAX * sizeof(NsMountEntry));
    NsMountEntry* sub = NULL; /* 动态分配：按 target/备份树下实际挂载数决定容量 */
    if (!all) {
        free(all);
        free(sub);
        return -1;
    }
    int n = ns_read_mountinfo_pid(getpid(), all, NS_MOUNTINFO_MAX);
    if (n <= 0) {
        free(all);
        free(sub);
        return -1;
    }
    const char* target = NSP_ANDROID_EMULATED_ROOT;
    /* 项目 FUSE 源（fuse_src 挂载点）的 major:minor：bind 视图与源共享 superblock，
       以此识别顶层是否为项目 FUSE（mountinfo source 字段是 devname/fsname，
       非 bind 源路径，不能直接比较字符串） */
    char src_dev[64] = {0};
    for (int i = 0; i < n; i++) {
        if (strcmp(all[i].mount_point, args->fuse_src) == 0) {
            strncpy(src_dev, all[i].dev, sizeof(src_dev) - 1);
            break;
        }
    }
    bool is_project = false;
    for (int i = 0; i < n; i++) {
        if (strcmp(all[i].mount_point, target) != 0) continue;
        /* 同挂载点可有多层叠加挂载（系统视图先挂载、项目视图经共享传播
           后叠加），mountinfo 最后一条才是实际生效的最顶层视图：
           必须遍历全部匹配，不能看到第一条就 break */
        if ((src_dev[0] && strcmp(all[i].dev, src_dev) == 0) ||
            fast_strstr(all[i].fstype, "fuse_daemon") != nullptr ||
            fast_strstr(all[i].source, "fuse_daemon") != nullptr) {
            is_project = true;
        }
        /* 不 break：继续遍历，以最后一条（最顶层）为准 */
    }
    if (!is_project) {
        LOG_DBG("应用还原: %s 顶层非项目 FUSE，跳过", target);
        free(all);
        free(sub);
        return 1; /* 1=跳过（非项目 FUSE），区别于 0=成功还原 */
    }
    /* 先校验备份点有效，再执行任何卸载：备份无效时必须保留当前可用的代理视图，
       避免把应用置于既无代理视图也无系统视图的裸挂载态（后续扫描还会因顶层
       不再是项目 FUSE 而永久跳过该应用） */
    char backup_top[PATH_MAX];
    snprintf(backup_top, sizeof(backup_top), "%s/user_%d/emulated", args->backup_root,
             args->user_id);
    if (ns_backup_point_state(getpid(), backup_top) != 1) {
        LOG_ERR("应用还原: 备份点 %s 无效，放弃还原", backup_top);
        free(all);
        free(sub);
        return -1;
    }
    /* 动态分配 sub：容量取 target 与备份树挂载数的较大值（+余量），
       彻底避免固定上限导致的堆溢出 */
    int cap_target = ns_count_mounts_under(all, n, target, true, true);
    int cap_backup = ns_count_mounts_under(all, n, backup_top, true, true);
    int sub_cap = cap_target > cap_backup ? cap_target : cap_backup;
    if (sub_cap < 16) sub_cap = 16; /* 保底容量 */
    sub = malloc(sub_cap * sizeof(NsMountEntry));
    if (!sub) {
        free(all);
        return -1;
    }
    /* 卸载顶层（含子挂载，最深优先） */
    int sn = ns_gather_mounts_under(all, n, target, true, true, sub, sub_cap);
    ns_sort_deepest_first(sub, sn);
    for (int k = 0; k < sn; k++) {
        for (int t = 0; t < 8; t++) {
            if (umount2(sub[k].mount_point, MNT_DETACH) == 0) break;
            if (errno == EINVAL) break;
        }
    }
    if (mkdir_recursive((char*)target) != 0) {
        LOG_WRN("应用还原: mkdir %s 失败: %s", target, strerror(errno));
    }
    /* 收集备份树全部挂载点（含自身与 f2fs 子挂载），父先子后逐节点 bind 回
       target：仅 bind 顶层会丢失 Android/data|obb 等 f2fs 直通子挂载 */
    int bn = ns_gather_mounts_under(all, n, backup_top, true, true, sub, sub_cap);
    ns_sort_shallowest_first(sub, bn);
    if (bn == 0) {
        LOG_ERR("应用还原: 备份点 %s 下未收集到任何挂载，放弃还原", backup_top);
        free(all);
        free(sub);
        return -1;
    }
    int bind_failed = 0; /* 任一 bind/mkdir 失败计数：返回 -1 让调用方记录错误
                              （mount_manager 不失效缓存、保留重扫资格），避免
                              部分还原被误报成功。注意重试门槛：仅当顶层仍为
                              项目 FUSE 视图时下一次扫描才可再次还原（is_project
                              判定）；顶层 bind 已成功的子节点/f2fs 补充失败时
                              顶层已是系统视图，本 -1 仅作诊断信号 */
    for (int k = 0; k < bn; k++) {
        const char* rel = sub[k].mount_point + strlen(backup_top); /* "" 或 "/0/Android/data" */
        char tgt[PATH_MAX];
        snprintf(tgt, sizeof(tgt), "%s%s", target, rel);
        if (mkdir_recursive(tgt) != 0) {
            LOG_WRN("应用还原: mkdir %s 失败: %s", tgt, strerror(errno));
            bind_failed++;
            continue;
        }
        if (mount(sub[k].mount_point, tgt, nullptr, MS_BIND, nullptr) != 0) {
            LOG_WRN("应用还原: bind %s -> %s 失败: %s", sub[k].mount_point, tgt, strerror(errno));
            bind_failed++;
            continue;
        }
        LOG_DBG("应用还原: bind %s -> %s", sub[k].mount_point, tgt);
    }
    LOG_DBG("应用还原: %s 已从备份 %s 还原（%d 个节点）", target, backup_top, bn);

    /* FUSE BPF passthrough 不可用时需补充 f2fs 直通子挂载：备份树可能不含
       Android/data（备份时源已缺失），此时从真实 f2fs 源 bind 补充。
       仅处理 data（obb 无需处理）；直接复用备份树节点信息判断是否已还原，
       不重读 mountinfo、不额外分配，确保还原路径低延迟。
       注意多用户：/data/media/<uid>/Android/data */
    bool data_in_backup = false;
    for (int k = 0; k < bn; k++) {
        if (fast_strstr(sub[k].mount_point, "/Android/data") != nullptr) {
            data_in_backup = true;
            break;
        }
    }
    if (!data_in_backup) {
        char src[PATH_MAX], dst[PATH_MAX];
        snprintf(src, sizeof src, "/data/media/%d/Android/data", args->user_id);
        snprintf(dst, sizeof dst, "%s/%d/Android/data", target, args->user_id);
        if (access(src, F_OK) != 0) {
            LOG_DBG("应用还原: f2fs 源 %s 不存在，跳过", src);
        } else if (mkdir_recursive(dst) != 0) {
            LOG_WRN("应用还原: mkdir %s 失败: %s", dst, strerror(errno));
            bind_failed++;
        } else if (mount(src, dst, nullptr, MS_BIND, nullptr) != 0) {
            LOG_WRN("应用还原: f2fs bind %s -> %s 失败: %s", src, dst, strerror(errno));
            bind_failed++;
        } else {
            LOG_DBG("应用还原: f2fs 补充 bind %s -> %s", src, dst);
        }
    }
    free(all);
    free(sub);
    if (bind_failed > 0) {
        LOG_ERR("应用还原: %d 个节点 bind 失败，视图可能不完整（仅诊断信号：顶层若已"
                "切换为系统视图，下一次扫描将跳过，不再重试；仅当顶层仍为项目 FUSE 时才可重试）",
                bind_failed);
        return -1;
    }
    return 0;
}

int ns_restore_app_fuse(int app_pid, const char* fuse_src, const char* backup_root, int user_id) {
    /* fuse_src（全局 FUSE 挂载源）仅用于精确 dev 匹配，允许为空：
       为空时 do_restore_app_fuse 回退到 fstype/source 特征判断目标顶层
       是否为项目 FUSE——还原不要求全局 FUSE 实例存在 */
    if (!backup_root) return -1;
    struct AppRestoreArgs args;
    memset(&args, 0, sizeof(args));
    strncpy(args.fuse_src, fuse_src ? fuse_src : "", sizeof(args.fuse_src) - 1);
    strncpy(args.backup_root, backup_root, sizeof(args.backup_root) - 1);
    args.user_id = user_id;
    int child_err = 0;
    int ret = run_in_mnt_ns_timeout(app_pid, do_restore_app_fuse, &args, &child_err, 5000);
    if (ret == 0) {
        LOG_DBG("应用还原成功 (pid=%d)", app_pid);
    } else if (ret == 1) {
        LOG_DBG("应用还原跳过 (pid=%d) 顶层非项目 FUSE", app_pid);
    } else {
        LOG_ERR("应用还原失败 (pid=%d, ret=%d, err=%d)", app_pid, ret, child_err);
    }
    return ret;
}

/* 查询全局替换状态（读 /proc/<pid>/mountinfo，无需进入命名空间） */
int ns_global_status(int mnt_ns_pid, const char* fuse_src) {
    NsMountEntry* all = malloc(NS_MOUNTINFO_MAX * sizeof(NsMountEntry));
    if (!all) return NSP_GLOBAL_STATUS_UNKNOWN;
    int n = ns_read_mountinfo_pid(mnt_ns_pid, all, NS_MOUNTINFO_MAX);
    if (n <= 0) {
        free(all);
        return NSP_GLOBAL_STATUS_UNKNOWN;
    }
    /* 项目 FUSE 源的 major:minor：bind 视图与源共享 superblock，
       mountinfo source 字段是 devname/fsname 而非 bind 源路径，需以 dev 判定 */
    char src_dev[64] = {0};
    for (int i = 0; i < n; i++) {
        if (strcmp(all[i].mount_point, fuse_src) == 0) {
            strncpy(src_dev, all[i].dev, sizeof(src_dev) - 1);
            break;
        }
    }
    int total = 0, replaced = 0;
    for (int i = 0; i < n; i++) {
        if (!ns_is_family_root(all[i].mount_point)) continue;
        total++;
        bool is_proxy = (src_dev[0] && strcmp(all[i].dev, src_dev) == 0);
        if (!is_proxy && fast_strstr(all[i].fstype, "fuse_daemon") != nullptr)
            is_proxy = true; /* 兜底：fstype 含 fuse_daemon 视为项目视图 */
        if (is_proxy) replaced++;
    }
    free(all);
    if (total == 0) return NSP_GLOBAL_STATUS_UNKNOWN;
    if (replaced == total) return NSP_GLOBAL_STATUS_REPLACED;
    if (replaced == 0) return NSP_GLOBAL_STATUS_NORMAL;
    return NSP_GLOBAL_STATUS_MIXED;
}

int ns_collect_mounts_under(int pid, const char* base_path, int include_self, int include_fuse,
                            char mount_points[][PATH_MAX], int max_count) {
    if (!base_path || max_count <= 0) return 0;
    NsMountEntry* all = malloc(NS_MOUNTINFO_MAX * sizeof(NsMountEntry));
    NsMountEntry* sub = malloc(NS_MOUNTINFO_MAX * sizeof(NsMountEntry));
    if (!all || !sub) {
        free(all);
        free(sub);
        return 0;
    }
    int n = ns_read_mountinfo_pid(pid, all, NS_MOUNTINFO_MAX);
    if (n <= 0) {
        free(all);
        free(sub);
        return 0;
    }
    int count =
        ns_gather_mounts_under(all, n, base_path, include_self != 0, include_fuse != 0, sub, 512);
    ns_sort_deepest_first(sub, count);
    if (count > max_count) count = max_count;
    for (int i = 0; i < count; i++) {
        strncpy(mount_points[i], sub[i].mount_point, PATH_MAX - 1);
        mount_points[i][PATH_MAX - 1] = '\0';
    }
    free(all);
    free(sub);
    return count;
}
