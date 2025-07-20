#include "profiler.h"
#include <stdio.h>
#include <time.h>
#include <unistd.h>  // Dodane dla POSIX

#ifndef CLOCK_MONOTONIC
#define CLOCK_MONOTONIC 1
#endif

void profiler_start(Profiler* p, const char* tag) {
    p->tag = tag;
#ifdef __MACH__  // Dla macOS
    clock_serv_t cclock;
    mach_timespec_t mts;
    host_get_clock_service(mach_host_self(), SYSTEM_CLOCK, &cclock);
    clock_get_time(cclock, &mts);
    mach_port_deallocate(mach_task_self(), cclock);
    p->start_time.tv_sec = mts.tv_sec;
    p->start_time.tv_nsec = mts.tv_nsec;
#else
    clock_gettime(CLOCK_MONOTONIC, &p->start_time);
#endif
}

void profiler_end(Profiler* p) {
    struct timespec end_time;
#ifdef __MACH__  // Dla macOS
    clock_serv_t cclock;
    mach_timespec_t mts;
    host_get_clock_service(mach_host_self(), SYSTEM_CLOCK, &cclock);
    clock_get_time(cclock, &mts);
    mach_port_deallocate(mach_task_self(), cclock);
    end_time.tv_sec = mts.tv_sec;
    end_time.tv_nsec = mts.tv_nsec;
#else
    clock_gettime(CLOCK_MONOTONIC, &end_time);
#endif
    
    double elapsed = (end_time.tv_sec - p->start_time.tv_sec) + 
                   (end_time.tv_nsec - p->start_time.tv_nsec) * 1e-9;
    
    printf("[PROFILER] %-20s %.6f s\n", p->tag, elapsed);
}
