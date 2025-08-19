#include "threadpool.h"
#include <stdio.h>
#include <errno.h>
#include <string.h>

// DODAJ globalny mutex dla debugowania
static pthread_mutex_t debug_mutex = PTHREAD_MUTEX_INITIALIZER;

static void* threadpool_worker(void *arg) {
    ThreadPool *pool = (ThreadPool *)arg;
    
    pthread_mutex_lock(&debug_mutex);
    printf("DEBUG: Thread %lu started\n", (unsigned long)pthread_self());
    pthread_mutex_unlock(&debug_mutex);
    
    while (true) {
        pthread_mutex_lock(&(pool->lock));
        
        // WAIT for tasks OR shutdown
        while (pool->count == 0 && !pool->shutdown) {
            pthread_cond_wait(&(pool->notify), &(pool->lock));
        }
        
        // EXIT if shutdown and no tasks
        if (pool->shutdown) {
            pthread_mutex_unlock(&(pool->lock));
            
            pthread_mutex_lock(&debug_mutex);
            printf("DEBUG: Thread %lu exiting (shutdown)\n", (unsigned long)pthread_self());
            pthread_mutex_unlock(&debug_mutex);
            
            break;
        }
        
        // GET task from queue
        Task task;
        task.function = pool->queue[pool->head].function;
        task.argument = pool->queue[pool->head].argument;
        
        pool->head = (pool->head + 1) % pool->queue_size;
        pool->count--;
        
        pthread_mutex_unlock(&(pool->lock));
        
        // EXECUTE task (AFTER unlocking mutex!)
        if (task.function && task.argument) {
            pthread_mutex_lock(&debug_mutex);
            printf("DEBUG: Thread %lu executing task\n", (unsigned long)pthread_self());
            pthread_mutex_unlock(&debug_mutex);
            
            task.function(task.argument);
        }
    }
    
    pthread_exit(NULL);
}

ThreadPool* threadpool_create(int thread_count, int queue_size) {
    pthread_mutex_lock(&debug_mutex);
    printf("DEBUG: Creating threadpool with %d threads, %d queue\n", thread_count, queue_size);
    pthread_mutex_unlock(&debug_mutex);
    
    if (thread_count <= 0 || thread_count > 1000 || 
        queue_size <= 0 || queue_size > 100000) {
        return NULL;
    }
    
    ThreadPool *pool = (ThreadPool *)malloc(sizeof(ThreadPool));
    if (!pool) return NULL;
    memset(pool, 0, sizeof(ThreadPool));
    
    pool->queue = (Task *)malloc(sizeof(Task) * queue_size);
    if (!pool->queue) {
        free(pool);
        return NULL;
    }
    memset(pool->queue, 0, sizeof(Task) * queue_size);
    
    pool->threads = (pthread_t *)malloc(sizeof(pthread_t) * thread_count);
    if (!pool->threads) {
        free(pool->queue);
        free(pool);
        return NULL;
    }
    memset(pool->threads, 0, sizeof(pthread_t) * thread_count);
    
    pool->thread_count = thread_count;
    pool->queue_size = queue_size;
    pool->head = 0;
    pool->tail = 0;
    pool->count = 0;
    pool->shutdown = 0;
    
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
        if (pthread_create(&(pool->threads[i]), NULL, threadpool_worker, (void *)pool) != 0) {
            // SHUTDOWN on error
            pool->shutdown = 1;
            pthread_cond_broadcast(&(pool->notify));
            
            // Wait for already created threads
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
    }
    
    pthread_mutex_lock(&debug_mutex);
    printf("DEBUG: Threadpool created successfully\n");
    pthread_mutex_unlock(&debug_mutex);
    
    return pool;
}

bool threadpool_add_task(ThreadPool *pool, void (*function)(void *), void *argument) {
    if (!pool || !function) return false;
    
    pthread_mutex_lock(&(pool->lock));
    
    if (pool->shutdown) {
        pthread_mutex_unlock(&(pool->lock));
        return false;
    }
    
    if (pool->count == pool->queue_size) {
        pthread_mutex_unlock(&(pool->lock));
        return false;
    }
    
    // Add task to queue
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
    
    pthread_mutex_lock(&debug_mutex);
    printf("DEBUG: Destroying threadpool\n");
    pthread_mutex_unlock(&debug_mutex);
    
    pthread_mutex_lock(&(pool->lock));
    pool->shutdown = 1;
    pthread_mutex_unlock(&(pool->lock));
    
    // Wake up all threads
    pthread_cond_broadcast(&(pool->notify));
    
    // Wait for all threads
    for (int i = 0; i < pool->thread_count; i++) {
        pthread_join(pool->threads[i], NULL);
    }
    
    // Cleanup
    pthread_mutex_destroy(&(pool->lock));
    pthread_cond_destroy(&(pool->notify));
    free(pool->threads);
    free(pool->queue);
    free(pool);
    
    pthread_mutex_lock(&debug_mutex);
    printf("DEBUG: Threadpool destroyed\n");
    pthread_mutex_unlock(&debug_mutex);
}