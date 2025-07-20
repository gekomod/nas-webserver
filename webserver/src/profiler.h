#ifndef PROFILER_H
#define PROFILER_H

#include <time.h>
#include <stdio.h>

#ifdef __MACH__
#include <mach/mach.h>
#include <mach/clock.h>
#endif

typedef struct {
    struct timespec start_time;
    const char* tag;
} Profiler;

void profiler_start(Profiler* p, const char* tag);
void profiler_end(Profiler* p);

#define LOG(level, format, ...) \
    fprintf(stderr, "[%s] %s:%d: " format "\n", level, __FILE__, __LINE__, ##__VA_ARGS__)

#ifdef ENABLE_PROFILING
#define PROFILE_BLOCK(tag) \
    Profiler _profiler_##tag; \
    profiler_start(&_profiler_##tag, #tag); \
    for(;0;profiler_end(&_profiler_##tag))

#define PROFILE_FUNCTION() PROFILE_BLOCK(__func__)
#else
#define PROFILE_BLOCK(tag)
#define PROFILE_FUNCTION()
#endif

#endif
