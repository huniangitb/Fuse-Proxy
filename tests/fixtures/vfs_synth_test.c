/* 虚拟条目判定与合成属性的判别性用例：直编 src/daemon/vfs_synth.c，
   不起 daemon、不挂载。失败条数即退出码来源。 */
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "vfs_synth.h"

static int failed = 0;

static void check(int cond, const char* desc) {
    if (cond) {
        printf("  [OK] %s\n", desc);
    } else {
        printf("  [FAIL] %s\n", desc);
        failed++;
    }
}

static void case_synth_dir_without_real_child(void) {
    struct stat parent;
    memset(&parent, 0, sizeof parent);
    parent.st_mode = S_IFDIR | 0770;
    parent.st_nlink = 41;
    parent.st_size = 4123;
    parent.st_uid = 1023;
    parent.st_gid = 1023;
    parent.st_mtime = 1791723202;
    parent.st_atime = 1791723202;
    parent.st_ctime = 1791723202;

    struct stat st;
    nsp_synth_stat_fill(&st, 4242, S_IFDIR | 0755, nullptr, &parent);
    check(S_ISDIR(st.st_mode), "父目录兜底：合成条目是目录");
    check(st.st_nlink >= 2, "父目录兜底：st_nlink >= 2");
    check(st.st_size > 0, "父目录兜底：st_size > 0");
    check(st.st_mtim.tv_sec > 0, "父目录兜底：st_mtim > 0（不再是 1970-01-01）");
    check((st.st_mode & 07777) == 0770, "父目录兜底：权限位继承父目录");
    check(st.st_uid == 1023 && st.st_gid == 1023, "父目录兜底：属主继承父目录");
    check(st.st_ino == 4242, "父目录兜底：ino 用调用方分配值");
}

static void case_synth_dir_with_real_child(void) {
    struct stat child;
    memset(&child, 0, sizeof child);
    child.st_mode = S_IFDIR | 0751;
    child.st_nlink = 3;
    child.st_size = 3440;
    child.st_uid = 10337;
    child.st_gid = 10337;
    child.st_mtime = 1793648614;

    struct stat parent;
    memset(&parent, 0, sizeof parent);
    parent.st_mode = S_IFDIR | 0770;
    parent.st_mtime = 1;

    struct stat st;
    nsp_synth_stat_fill(&st, 7, S_IFDIR | 0755, &child, &parent);
    check(S_ISDIR(st.st_mode), "真实子项：合成条目是目录");
    check(st.st_nlink == 3 && st.st_size == 3440, "真实子项：nlink/size 取真实子项");
    check(st.st_mtim.tv_sec == 1793648614, "真实子项：时间戳取真实子项");
    check((st.st_mode & 07777) == 0751 && st.st_uid == 10337, "真实子项：权限与属主取真实子项");
}

static void case_synth_dir_without_any_source(void) {
    struct stat st;
    nsp_synth_stat_fill(&st, 9, S_IFDIR | 0755, nullptr, nullptr);
    check(S_ISDIR(st.st_mode) && st.st_nlink >= 2 && st.st_size > 0,
          "无任何来源：仍保证是目录、nlink>=2、size>0");
    check(st.st_mtim.tv_sec == 0, "无任何来源：时间留 0（没有可继承的值）");
}

static void case_synth_file_entry(void) {
    struct stat parent;
    memset(&parent, 0, sizeof parent);
    parent.st_mode = S_IFDIR | 0770;
    parent.st_mtime = 1791723202;

    struct stat st;
    nsp_synth_stat_fill(&st, 11, S_IFREG | 0644, nullptr, &parent);
    check(S_ISREG(st.st_mode), "文件条目：类型位不被目录兜底改写");
    check(st.st_nlink == 1, "文件条目：st_nlink == 1");
}

static void case_own_pkg_paths(void) {
    check(is_virtual_own_pkg_dir("/Android/obb/com.example", "com.example"),
          "/Android/obb/<pkg> 命中（真实目录可不存在的合成条目）");
    check(is_virtual_own_pkg_dir("/Android/data/com.example", "com.example"),
          "/Android/data/<pkg> 命中");
    check(is_virtual_own_pkg_dir("/0/Android/obb/com.example", "com.example"),
          "带用户层 /0/Android/obb/<pkg> 命中");
    check(is_virtual_own_pkg_dir("/Android/obb/com.example/", "com.example"),
          "尾斜杠不影响命中");
    check(!is_virtual_own_pkg_dir("/Android/obb/com.other", "com.example"),
          "别的包名不命中");
    check(!is_virtual_own_pkg_dir("/Android/obb/com.example/sub", "com.example"),
          "<pkg> 之下的子路径不命中");
    check(!is_virtual_own_pkg_dir("/Android/media/com.example", "com.example"),
          "/Android/media/<pkg> 不是沙盒合成的容器");
    check(!is_virtual_own_pkg_dir("/Android/obb", "com.example"),
          "容器本身不命中");
    check(!is_virtual_own_pkg_dir("/Android/obb/com.example", ""),
          "空包名不命中");
}

static void case_skel_and_user_layer(void) {
    check(is_android_skel_dir("/Android") && is_android_skel_dir("/0/Android/"),
          "骨架目录判定含用户层");
    check(is_android_skel_dir("/Android/data") && is_android_skel_dir("/Android/obb"),
          "骨架目录判定覆盖 data/obb");
    check(!is_android_skel_dir("/Android/media"),
          "/Android/media 是条件骨架（整树镜像口径才合成），不进无条件骨架判定");
    check(sub_path_is_android_media_container("/Android/media") &&
              sub_path_is_android_media_container("/0/Android/media/"),
          "media 容器判定：根层命中，带用户层与尾斜杠同样命中");
    check(!sub_path_is_android_media_container("/Android/media/com.example") &&
              !sub_path_is_android_media_container("/Android/mediax") &&
              !sub_path_is_android_media_container("/DCIM/files/Lua/Android/media"),
          "media 容器判定：容器内条目、同前缀目录、嵌套同名目录都不命中");
    check(strcmp(sub_path_strip_user_layer("/0/Android"), "/Android") == 0,
          "剥用户层：/0/Android -> /Android");
    check(strcmp(sub_path_strip_user_layer("/Android"), "/Android") == 0,
          "无用户层原样返回");
    check(sub_path_is_android_container("/0/Android/obb"),
          "带用户层的 /0/Android/obb 是容器");
}

/* 最近存在祖先：虚拟目录链上「直接父目录也不存在」是常态，属性只能从更上级借。
   判别性要求：返回的是父目录而不是入参自身（入参正是 lstat 失败的那个）。 */
static void case_nearest_ancestor(void) {
    char tmpl[] = "/tmp/nsp_synth_XXXXXX";
    char* dir = mkdtemp(tmpl);
    if (!dir) {
        check(0, "mkdtemp 建立临时目录");
        return;
    }
    struct stat base;
    if (lstat(dir, &base) != 0) {
        check(0, "临时目录可 stat");
        (void)rmdir(dir);
        return;
    }

    char path[PATH_MAX];
    struct stat out;
    snprintf(path, sizeof path, "%s/miss_a/miss_b/file", dir);
    memset(&out, 0, sizeof out);
    check(nsp_stat_nearest_ancestor(path, &out), "多级缺失子路径：找到最近存在祖先");
    check(out.st_ino == base.st_ino, "最近祖先就是临时目录本身");

    snprintf(path, sizeof path, "%s/miss_a/miss_b/", dir);
    memset(&out, 0, sizeof out);
    check(nsp_stat_nearest_ancestor(path, &out) && out.st_ino == base.st_ino,
          "尾部斜杠不影响上溯");

    snprintf(path, sizeof path, "%s", dir);
    memset(&out, 0, sizeof out);
    struct stat parent;
    if (lstat("/tmp", &parent) == 0) {
        check(nsp_stat_nearest_ancestor(path, &out) && out.st_ino == parent.st_ino,
              "入参自身存在时返回其父目录，不返回自身");
    }

    memset(&out, 0, sizeof out);
    check(!nsp_stat_nearest_ancestor("/", &out), "根目录没有更上级可借");
    check(!nsp_stat_nearest_ancestor(nullptr, &out), "空路径返回 false");
    (void)rmdir(dir);
}

/* 只有存储根下的 /Android 有 data/obb 合成语义：嵌套同名目录命中的话，
   readdir 会补出没有 getattr 兜底的 data/obb（stat ENOENT → 客户端画成文件）。 */
static void case_storage_android_only(void) {
    check(sub_path_is_storage_android_dir("/Android"), "存储根 /Android 命中");
    check(sub_path_is_storage_android_dir("/0/Android/"), "带用户层、尾斜杠仍命中");
    check(!sub_path_is_storage_android_dir("/Android/data"),
          "/Android/data 不是 /Android 本身");
    check(!sub_path_is_storage_android_dir("/Download/Android"),
          "存储根下一层的同名目录不命中");
    check(!sub_path_is_storage_android_dir("/DCIM/files/Lua/Android"),
          "深层嵌套同名 Android 目录不命中");
    check(!sub_path_is_storage_android_dir("/AndroidX"), "仅前缀相同不算命中");
    check(!sub_path_is_android_container("/DCIM/files/Lua/Android/data"),
          "嵌套 Android/data 不是沙盒容器");
    check(!sub_path_is_android_container("/DCIM/files/Lua/Android/obb"),
          "嵌套 Android/obb 不是沙盒容器");
    check(!is_virtual_own_pkg_dir("/DCIM/files/Lua/Android/data/com.example", "com.example"),
          "嵌套容器下不合成当前包名目录");
    check(!is_android_skel_dir("/DCIM/files/Lua/Android"),
          "嵌套 Android 不是骨架目录");
}

/* 合成列举登记：own_pkg 兜底只认「readdir 真的发出过这一条」。
   判别性要求：未列举必须不放行（直接 statx 一个不存在的 own_pkg 路径要 ENOENT），
   列举窗口内放行（列表里看得见就点得开），窗口过期、换 uid、换容器即失效。 */
static uint64_t g_fake_ms;

static uint64_t fake_clock(void) {
    return g_fake_ms;
}

static void case_listed_registry(void) {
    nsp_listed_set_clock_for_test(fake_clock);
    nsp_listed_clear();
    g_fake_ms = 1000;

    check(!nsp_listed_own_pkg(10000, "/Android/obb/com.example", "com.example"),
          "未列举：own_pkg 兜底不放行");
    nsp_listed_mark_own_pkg(10000, "/Android/obb", "com.example");
    check(nsp_listed_own_pkg(10000, "/Android/obb/com.example", "com.example"),
          "列举过：容器下的 own_pkg 路径放行");
    check(nsp_listed_own_pkg(10000, "/0/Android/obb/com.example/", "com.example"),
          "带用户层与尾斜杠的同一路径仍放行");
    check(!nsp_listed_own_pkg(10001, "/Android/obb/com.example", "com.example"),
          "别的 uid 不共享登记");
    check(!nsp_listed_own_pkg(10000, "/Android/data/com.example", "com.example"),
          "obb 的登记不放到 data 容器");
    check(!nsp_listed_own_pkg(10000, "/Android/obb/com.other", "com.other"),
          "未列举的另一个包名不放行");
    check(!nsp_listed_own_pkg(10000, "/Android/obb", "com.example"),
          "容器本身不是 own_pkg 条目");

    g_fake_ms = 1000 + 30001;
    check(!nsp_listed_own_pkg(10000, "/Android/obb/com.example", "com.example"),
          "超过窗口：登记失效（按未列举处理）");

    g_fake_ms = 1000;
    nsp_listed_mark_own_pkg(10000, "/Android/data", "com.example");
    check(nsp_listed_own_pkg(10000, "/Android/data/com.example", "com.example"),
          "data 容器的登记只对 data 生效");

    nsp_listed_mark_own_pkg(20000, "/Download/Android/obb", "com.example");
    check(!nsp_listed_own_pkg(20000, "/Download/Android/obb/com.example", "com.example"),
          "非存储根容器不产生登记");

    nsp_listed_clear();
    check(!nsp_listed_own_pkg(10000, "/Android/data/com.example", "com.example"),
          "clear 之后一律不放行");
    nsp_listed_set_clock_for_test(nullptr);
}

int main(void) {
    case_synth_dir_without_real_child();
    case_synth_dir_with_real_child();
    case_synth_dir_without_any_source();
    case_synth_file_entry();
    case_own_pkg_paths();
    case_skel_and_user_layer();
    case_storage_android_only();
    case_nearest_ancestor();
    case_listed_registry();
    if (failed) printf("失败 %d 条\n", failed);
    return failed ? 1 : 0;
}
