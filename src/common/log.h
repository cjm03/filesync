#ifndef LOG_H
#define LOG_H

/*
    Write a formatted message to stderr with [INFO] prepended
    ex: LogInfo("Value was: %d", value)
*/
void LogInfo(const char* fmt, ...);

/*
    Write a formatted message to stderr with [ERROR] prepended
    ex: LogInfo("something failed: %s", failure)
*/
void LogError(const char* fmt, ...);

#endif // LOG_H
