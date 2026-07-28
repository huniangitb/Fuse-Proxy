#ifndef CRASH_DUMP_H
#define CRASH_DUMP_H

#include <stdarg.h>

void safe_printf(int fd, const char* fmt, ...);
void install_crash_handlers();

#endif