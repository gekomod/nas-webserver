#include "threadpool.h"
#include <stdio.h>
#include <errno.h>

static void* threadpool_worker(void *arg) {
    ThreadPool *pool = (ThreadPool *)arg;
    Task task;

    while (true) {
        pthread_mutex_lock(&(pool->lock));

        while (pool->count == 0 && !pool->shutdown) {
            pthread_cond_wait(&(pool->notify), &(pool->lock));
        }

        if (pool->shutdown) {
            pthread_mutex_unlock(&(pool->lock));
            pthread_exit(NULL);
        }

        task.function = pool->queue[pool->head].function;
        task.argument = pool->queue[pool->head].argument;

        pool->head = (pool->head + 1) % pool->queue_size;
        pool->count--;

        pthread_mutex_unlock(&(pool->lock));

        (*(task.function))(task.argument);
    }

    return NULL;
}

ThreadPool* threadpool_create(int thread_count, int queue_size) {
    ThreadPool *pool = (ThreadPool *)malloc(sizeof(ThreadPool));
    if (!pool) return NULL;

    // Ograniczenie liczby wątków i rozmiaru kolejki
    if (thread_count <= 0 || thread_count > 1000 || 
        queue_size <= 0 || queue_size > 100000) {
        return NULL;
    }

    pool->queue = (Task *)malloc(sizeof(Task) * queue_size);
    if (!pool->queue) {
        free(pool);
        return NULL;
    }

    pool->threads = (pthread_t *)malloc(sizeof(pthread_t) * thread_count);
    if (!pool->threads) {
        free(pool->queue);
        free(pool);
        return NULL;
    }

    pool->thread_count = thread_count;
    pool->queue_size = queue_size;
    pool->head = pool->tail = pool->count = 0;
    pool->shutdown = false;

    if (pthread_mutex_init(&(pool->lock), NULL) != 0 ||
        pthread_cond_init(&(pool->notify), NULL) != 0) {
        free(pool->threads);
        free(pool->queue);
        free(pool);
        return NULL;
    }

    for (int i = 0; i < thread_count; i++) {
        if (pthread_create(&(pool->threads[i]), NULL, threadpool_worker, (void *)pool) != 0) {
            threadpool_destroy(pool);
            return NULL;
        }
    }

    return pool;
}

bool threadpool_add_task(ThreadPool *pool, void (*function)(void *), void *argument) {
    if (!pool || !function) return false;

    pthread_mutex_lock(&(pool->lock));

    if (pool->count == pool->queue_size) {
        pthread_mutex_unlock(&(pool->lock));
        return false;
    }

    if (pool->shutdown) {
        pthread_mutex_unlock(&(pool->lock));
        return false;
    }

    pool->queue[pool->tail].function = function;
    pool->queue[pool->tail].argument = argument;
    pool->tail = (pool->tail + 1) % pool->queue_size;
    pool->count++;

    pthread_cond_signal(&(pool->notify));
    pthread_mutex_unlock(&(pool->lock));

    return true;
}

void threadpool_destroy(ThreadPool *pool) {
    if (!pool) return;

    pthread_mutex_lock(&(pool->lock));
    pool->shutdown = true;
    pthread_mutex_unlock(&(pool->lock));

    pthread_cond_broadcast(&(pool->notify));

    for (int i = 0; i < pool->thread_count; i++) {
        pthread_join(pool->threads[i], NULL);
    }

    free(pool->threads);
    free(pool->queue);
    free(pool);
}