/* 虚拟条目判定与合成属性的判别性用例：直编 src/daemon/vfs_synth.c，
   不起 daemon、不挂载。失败条数即退出码来源。 */
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

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
    check(!is_android_skel_dir("/Android/media"), "/Android/media 不是骨架");
    check(strcmp(sub_path_strip_user_layer("/0/Android"), "/Android") == 0,
          "剥用户层：/0/Android -> /Android");
    check(strcmp(sub_path_strip_user_layer("/Android"), "/Android") == 0,
          "无用户层原样返回");
    check(sub_path_is_android_container("/0/Android/obb"),
          "带用户层的 /0/Android/obb 是容器");
}

int main(void) {
    case_synth_dir_without_real_child();
    case_synth_dir_with_real_child();
    case_synth_dir_without_any_source();
    case_synth_file_entry();
    case_own_pkg_paths();
    case_skel_and_user_layer();
    if (failed) printf("失败 %d 条\n", failed);
    return failed ? 1 : 0;
}
