#ifndef THREADPOOL_H
#define THREADPOOL_H

#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>

typedef struct {
    void (*function)(void *);
    void *argument;
} Task;

typedef struct {
    Task *queue;
    int queue_size;
    int head;
    int tail;
    int count;
    pthread_mutex_t lock;
    pthread_cond_t notify;
    pthread_t *threads;
    int thread_count;
    bool shutdown;
} ThreadPool;

ThreadPool* threadpool_create(int thread_count, int queue_size);
bool threadpool_add_task(ThreadPool *pool, void (*function)(void *), void *argument);
void threadpool_destroy(ThreadPool *pool);

#endif // THREADPOOL_H