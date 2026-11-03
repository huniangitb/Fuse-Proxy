#include "crash_tail.h"

bool crash_tail_window(off_t file_size, off_t run_start, size_t cap, CrashTailWindow* out) {
    if (!out) return false;
    out->start = 0;
    out->len = 0;
    out->drop_first_line = false;
    if (cap == 0 || file_size <= 0) return false;

    off_t from;
    if (run_start < 0 || run_start > file_size) {
        /* 起点不可信：启动时的 stat 失败，或文件被截断/轮转。读尾部即可，
           起点可能落在行中间，交给 drop_first_line 处理。 */
        from = (file_size > (off_t)cap) ? file_size - (off_t)cap : 0;
        out->drop_first_line = (from > 0);
    } else {
        from = run_start;
        /* 本次启动后的输出超过 cap：只留最后 cap 字节，起点必然落在行中间 */
        if (file_size - from > (off_t)cap) {
            from = file_size - (off_t)cap;
            out->drop_first_line = true;
        }
    }
    if (from >= file_size) return false; /* 本次启动后没有任何新增 */
    out->start = from;
    out->len = (size_t)(file_size - from);
    return true;
}