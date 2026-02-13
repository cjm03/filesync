#include "log.h"
// #include <__stdarg_va_list.h>
#include <stdio.h>
#include <stdarg.h>

static void vlog(const char* prefix, const char* fmt, va_list args) {
    fprintf(stderr, "%s", prefix);
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
}

void LogInfo(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vlog("[INFO] ", fmt, args);
    va_end(args);
}

void LogError(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vlog("[ERROR] ", fmt, args);
    va_end(args);
}
