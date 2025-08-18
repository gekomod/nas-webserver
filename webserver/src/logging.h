#ifndef LOGGING_H
#define LOGGING_H

#include "config.h"
#include <stdio.h>
#include <time.h>
#include <sys/stat.h>

typedef enum {
    LOG_ACCESS,
    LOG_ERROR,
    LOG_SECURITY
} LogType;

void init_logging(const Config* config);
void log_message(LogType type, const char* format, ...);
void rotate_logs(const Config* config);
void close_logs();

#endif