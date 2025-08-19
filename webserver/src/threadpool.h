#ifndef THREADPOOL_H
#define THREADPOOL_H

#include <pthread.h>
#include <stdbool.h>

#define MAX_THREADS 64
#define MAX_QUEUE 65536

// Shutdown types
#define GRACEFUL_SHUTDOWN 1
#define IMMEDIATE_SHUTDOWN 2

typedef struct {
    void (*function)(void *);
    void *argument;
} Task;

typedef struct ThreadPool {
    pthread_mutex_t lock;
    pthread_cond_t notify;
    pthread_t *threads;
    Task *queue;
    
    int thread_count;
    int queue_size;
    int head;
    int tail;
    int count;
    int shutdown;
    int started;
} ThreadPool;

typedef enum {
    threadpool_invalid        = -1,
    threadpool_lock_failure   = -2,
    threadpool_queue_full     = -3,
    threadpool_shutdown       = -4,
    threadpool_thread_failure = -5
} threadpool_error_t;

typedef enum {
    threadpool_graceful = 1
} threadpool_destroy_flags_t;

ThreadPool* threadpool_create(int thread_count, int queue_size);
int threadpool_add(ThreadPool* pool, void (*function)(void*), void* argument);
int threadpool_destroy(ThreadPool* pool, int flags);
void threadpool_free(ThreadPool* pool);

// Simple helper function
static inline bool threadpool_add_task(ThreadPool* pool, void (*function)(void*), void* argument) {
    return threadpool_add(pool, function, argument) == 0;
}

#endif // THREADPOOL_H