#include "threadpool.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

static void* threadpool_worker(void* threadpool) {
    ThreadPool* pool = (ThreadPool*)threadpool;
    
    while (1) {
        pthread_mutex_lock(&(pool->lock));
        
        // Wait for tasks or shutdown
        while ((pool->count == 0) && (!pool->shutdown)) {
            pthread_cond_wait(&(pool->notify), &(pool->lock));
        }
        
        // Check for shutdown conditions
        if (pool->shutdown == IMMEDIATE_SHUTDOWN) {
            break;
        }
        
        if ((pool->shutdown == GRACEFUL_SHUTDOWN) && (pool->count == 0)) {
            break;
        }
        
        // Get task from queue
        Task task = pool->queue[pool->head];
        pool->head = (pool->head + 1) % pool->queue_size;
        pool->count--;
        
        pthread_mutex_unlock(&(pool->lock));
        
        // Execute the task
        if (task.function && task.argument) {
            (*(task.function))(task.argument);
        }
    }
    
    pool->started--;
    pthread_mutex_unlock(&(pool->lock));
    pthread_exit(NULL);
    return NULL;
}

ThreadPool* threadpool_create(int thread_count, int queue_size) {
    if (thread_count <= 0 || thread_count > MAX_THREADS || 
        queue_size <= 0 || queue_size > MAX_QUEUE) {
        return NULL;
    }
    
    ThreadPool* pool = (ThreadPool*)malloc(sizeof(ThreadPool));
    if (!pool) {
        return NULL;
    }
    
    // Initialize structure
    pool->thread_count = 0;
    pool->queue_size = queue_size;
    pool->head = 0;
    pool->tail = 0;
    pool->count = 0;
    pool->shutdown = 0;
    pool->started = 0;
    
    // Allocate threads and queue
    pool->threads = (pthread_t*)malloc(sizeof(pthread_t) * thread_count);
    pool->queue = (Task*)malloc(sizeof(Task) * queue_size);
    
    if (!pool->threads || !pool->queue) {
        if (pool->threads) free(pool->threads);
        if (pool->queue) free(pool->queue);
        free(pool);
        return NULL;
    }
    
    // Initialize mutex and condition variable
    if (pthread_mutex_init(&(pool->lock), NULL) != 0) {
        free(pool->threads);
        free(pool->queue);
        free(pool);
        return NULL;
    }
    
    if (pthread_cond_init(&(pool->notify), NULL) != 0) {
        pthread_mutex_destroy(&(pool->lock));
        free(pool->threads);
        free(pool->queue);
        free(pool);
        return NULL;
    }
    
    // Create worker threads
    for (int i = 0; i < thread_count; i++) {
        if (pthread_create(&(pool->threads[i]), NULL, threadpool_worker, (void*)pool) != 0) {
            // Destroy pool if thread creation fails
            pool->shutdown = IMMEDIATE_SHUTDOWN;
            pthread_cond_broadcast(&(pool->notify));
            
            for (int j = 0; j < i; j++) {
                pthread_join(pool->threads[j], NULL);
            }
            
            pthread_mutex_destroy(&(pool->lock));
            pthread_cond_destroy(&(pool->notify));
            free(pool->threads);
            free(pool->queue);
            free(pool);
            return NULL;
        }
        pool->thread_count++;
        pool->started++;
    }
    
    return pool;
}

int threadpool_add(ThreadPool* pool, void (*function)(void*), void* argument) {
    if (!pool || !function) {
        return threadpool_invalid;
    }
    
    if (pthread_mutex_lock(&(pool->lock)) != 0) {
        return threadpool_lock_failure;
    }
    
    int next = (pool->tail + 1) % pool->queue_size;
    int err = 0;
    
    do {
        // Check if queue is full
        if (pool->count == pool->queue_size) {
            err = threadpool_queue_full;
            break;
        }
        
        // Check if pool is shutting down
        if (pool->shutdown) {
            err = threadpool_shutdown;
            break;
        }
        
        // Add task to queue
        pool->queue[pool->tail].function = function;
        pool->queue[pool->tail].argument = argument;
        pool->tail = next;
        pool->count++;
        
        // Signal waiting thread
        if (pthread_cond_signal(&(pool->notify)) != 0) {
            err = threadpool_lock_failure;
            break;
        }
    } while (0);
    
    if (pthread_mutex_unlock(&pool->lock) != 0) {
        err = threadpool_lock_failure;
    }
    
    return err;
}

int threadpool_destroy(ThreadPool* pool, int flags) {
    if (!pool) {
        return threadpool_invalid;
    }
    
    if (pthread_mutex_lock(&(pool->lock)) != 0) {
        return threadpool_lock_failure;
    }
    
    int err = 0;
    
    do {
        // Already shutting down
        if (pool->shutdown) {
            err = threadpool_shutdown;
            break;
        }
        
        pool->shutdown = (flags & threadpool_graceful) ? 
            GRACEFUL_SHUTDOWN : IMMEDIATE_SHUTDOWN;
        
        // Wake up all worker threads
        if (pthread_cond_broadcast(&(pool->notify)) != 0) {
            err = threadpool_lock_failure;
            break;
        }
        
        if (pthread_mutex_unlock(&(pool->lock)) != 0) {
            err = threadpool_lock_failure;
            break;
        }
        
        // Join all worker threads
        for (int i = 0; i < pool->thread_count; i++) {
            if (pthread_join(pool->threads[i], NULL) != 0) {
                err = threadpool_thread_failure;
            }
        }
    } while (0);
    
    // Cleanup if no error occurred
    if (!err) {
        threadpool_free(pool);
    }
    
    return err;
}

void threadpool_free(ThreadPool* pool) {
    if (!pool || pool->started > 0) {
        return;
    }
    
    // Free allocated resources
    if (pool->threads) {
        free(pool->threads);
    }
    
    if (pool->queue) {
        free(pool->queue);
    }
    
    // Destroy synchronization primitives
    pthread_mutex_destroy(&(pool->lock));
    pthread_cond_destroy(&(pool->notify));
    
    free(pool);
}