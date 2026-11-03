#ifndef NSP_VFS_SYNTH_H
#define NSP_VFS_SYNTH_H

#include <stdbool.h>
#include <sys/stat.h>
#include <sys/types.h>

/* 路径段判定：全部接受带用户层的形态（/0/Android 与 /Android 同结论）。
   骨架判定不能假设路径已剥用户层——无用户层的挂载下同一路径必须得到同一结论。 */
const char* sub_path_strip_user_layer(const char* sub_path);
bool sub_path_tail_is(const char* sub_path, const char* name);
/* 存储根下的 /Android 本身（/Android、/0/Android，尾斜杠可有）。只有这一层有
   data/obb 骨架合成的语义：嵌套同名目录（…/files/Lua/Android）没有 getattr/
   opendir 的骨架兜底，合成出来的条目 stat 会 ENOENT，客户端把它画成文件。 */
bool sub_path_is_storage_android_dir(const char* sub_path);
/* 存储根下的 /Android/data|obb（同样只认根层，嵌套同名目录不算）。 */
bool sub_path_is_android_container(const char* sub_path);
bool is_android_skel_dir(const char* sub_path);

/* 沙盒合成的「容器/当前包名」目录：/Android/data/<pkg> 或 /Android/obb/<pkg>。
   真实目录可以不存在，readdir 由 fill_own_pkg 合成这一条；getattr/access/opendir
   必须同口径把它当目录，否则列表里看得见、stat 却 ENOENT，客户端把它画成文件。 */
bool is_virtual_own_pkg_dir(const char* sub_path, const char* pkg);

/* 合成条目的属性：类型位由调用方给（目录/普通文件），ino 由调用方分配。
   时间戳与属主优先取同名真实子项（real_child），取不到继承父目录（parent）；
   两者都为空时只保证类型位与 w 位，时间留 0。目录恒给 nlink>=2、size>0，
   否则客户端把条目画成「无大小、1970-01-01」。 */
void nsp_synth_stat_fill(struct stat* st, ino_t ino, mode_t type_mode,
                         const struct stat* real_child, const struct stat* parent);

/* 最近的存在祖先：从 real_path 的父目录逐级上溯，第一个 lstat 成功的上级写入 out
   并返回 true（到 "/" 仍失败返回 false）。
   虚拟目录链（重定向落点不存在时的多级合成）上「直接父目录也缺失」是常态，
   只继承一层会让时间戳留 0，客户端把条目画成 1970-01-01；调用方在直接父目录
   lstat 失败时应改用本函数继续上溯。 */
bool nsp_stat_nearest_ancestor(const char* real_path, struct stat* out);

#endif /* NSP_VFS_SYNTH_H */
