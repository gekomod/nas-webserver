#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <pthread.h>
#include "config.h"

#define BENCHMARK_PORT 8081
#define NUM_REQUESTS 10000
#define NUM_THREADS 10
#define TIMEOUT_SEC 5

typedef struct {
    int thread_id;
    int requests_completed;
    int requests_failed;
    double total_time;
} ThreadStats;

typedef struct {
    const char* host;
    int port;
    const char* path;
    int num_requests;
    int thread_id;  // DODANE: brakujący member
    ThreadStats* stats;
} BenchmarkArgs;

double get_current_time() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec + tv.tv_usec / 1000000.0;
}

int create_connection(const char* host, int port) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed");
        return -1;
    }

    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    
    if (inet_pton(AF_INET, host, &serv_addr.sin_addr) <= 0) {
        perror("Invalid address");
        close(sockfd);
        return -1;
    }

    // Set timeout
    struct timeval timeout;
    timeout.tv_sec = TIMEOUT_SEC;
    timeout.tv_usec = 0;
    
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0 ||
        setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("Setsockopt failed");
        close(sockfd);
        return -1;
    }

    if (connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection failed");
        close(sockfd);
        return -1;
    }

    return sockfd;
}

int send_http_request(int sockfd, const char* path) {
    char request[1024];
    snprintf(request, sizeof(request),
        "GET %s HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Connection: close\r\n"
        "User-Agent: Benchmark/1.0\r\n"
        "\r\n", path);

    if (send(sockfd, request, strlen(request), 0) < 0) {
        return -1;
    }

    // Read response (just to complete the request)
    char buffer[4096];
    ssize_t bytes_read;
    while ((bytes_read = recv(sockfd, buffer, sizeof(buffer) - 1, 0)) > 0) {
        // Just consume the response
    }

    return bytes_read >= 0 ? 0 : -1;
}

void* benchmark_thread(void* arg) {
    BenchmarkArgs* args = (BenchmarkArgs*)arg;
    ThreadStats* stats = &args->stats[args->thread_id];
    
    stats->thread_id = args->thread_id;
    stats->requests_completed = 0;
    stats->requests_failed = 0;
    stats->total_time = 0.0;

    for (int i = 0; i < args->num_requests; i++) {
        double start_time = get_current_time();
        
        int sockfd = create_connection(args->host, args->port);
        if (sockfd < 0) {
            stats->requests_failed++;
            continue;
        }

        int result = send_http_request(sockfd, args->path);
        close(sockfd);

        double end_time = get_current_time();
        double request_time = end_time - start_time;

        if (result == 0) {
            stats->requests_completed++;
            stats->total_time += request_time;
        } else {
            stats->requests_failed++;
        }

        // Small delay to avoid overwhelming the server
        usleep(1000); // 1ms
    }

    return NULL;
}

void run_benchmark(const char* host, int port, const char* path, 
                  int num_threads, int requests_per_thread) {
    printf("Starting benchmark...\n");
    printf("Target: %s:%d%s\n", host, port, path);
    printf("Threads: %d, Requests per thread: %d\n", num_threads, requests_per_thread);
    printf("Total requests: %d\n\n", num_threads * requests_per_thread);

    pthread_t threads[num_threads];
    ThreadStats stats[num_threads];
    BenchmarkArgs args[num_threads];

    double overall_start = get_current_time();

    // Create threads
    for (int i = 0; i < num_threads; i++) {
        args[i].host = host;
        args[i].port = port;
        args[i].path = path;
        args[i].num_requests = requests_per_thread;
        args[i].thread_id = i;  // POPRAWIONE: ustawienie thread_id
        args[i].stats = stats;

        if (pthread_create(&threads[i], NULL, benchmark_thread, &args[i]) != 0) {
            perror("Failed to create thread");
            return;
        }
    }

    // Wait for threads to complete
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    double overall_end = get_current_time();
    double total_time = overall_end - overall_start;

    // Aggregate results
    int total_completed = 0;
    int total_failed = 0;
    double total_request_time = 0.0;

    for (int i = 0; i < num_threads; i++) {
        total_completed += stats[i].requests_completed;
        total_failed += stats[i].requests_failed;
        total_request_time += stats[i].total_time;
    }

    int total_requests = total_completed + total_failed;
    double avg_request_time = total_completed > 0 ? total_request_time / total_completed : 0;
    double requests_per_second = total_completed / total_time;

    printf("\n=== BENCHMARK RESULTS ===\n");
    printf("Total time: %.2f seconds\n", total_time);
    printf("Total requests: %d\n", total_requests);
    printf("Completed: %d\n", total_completed);
    printf("Failed: %d (%.1f%%)\n", total_failed, 
           total_requests > 0 ? (total_failed * 100.0 / total_requests) : 0);
    printf("Requests per second: %.2f\n", requests_per_second);
    printf("Average request time: %.3f ms\n", avg_request_time * 1000);
    printf("Throughput: %.2f MB/s\n", 
           (total_completed * 1024.0) / (total_time * 1024 * 1024)); // Approximate

    // Print per-thread statistics
    printf("\nPer-thread statistics:\n");
    for (int i = 0; i < num_threads; i++) {
        printf("Thread %d: %d completed, %d failed, avg time: %.3f ms\n",
               i, stats[i].requests_completed, stats[i].requests_failed,
               stats[i].requests_completed > 0 ? 
               (stats[i].total_time / stats[i].requests_completed * 1000) : 0);
    }
}

void test_different_endpoints(const char* host, int port) {
    const char* endpoints[] = {
        "/",
        "/index.html",
        "/api/status",
        "/api/echo",
        "/static/css/style.css",  // assuming this exists
        "/nonexistent"  // test 404 handling
    };
    
    int num_endpoints = sizeof(endpoints) / sizeof(endpoints[0]);
    
    for (int i = 0; i < num_endpoints; i++) {
        printf("\nTesting endpoint: %s\n", endpoints[i]);
        printf("====================%s\n", "====================");
        
        run_benchmark(host, port, endpoints[i], 5, 200);
        
        // Small delay between tests
        sleep(1);
    }
}

void load_test(const char* host, int port) {
    printf("\n=== LOAD TEST ===\n");
    printf("Testing with increasing load...\n");
    
    int thread_counts[] = {1, 5, 10, 20, 50};
    int num_tests = sizeof(thread_counts) / sizeof(thread_counts[0]);
    
    for (int i = 0; i < num_tests; i++) {
        printf("\nLoad test with %d threads:\n", thread_counts[i]);
        printf("-------------------------\n");
        
        run_benchmark(host, port, "/api/status", thread_counts[i], 100);
        
        // Wait between tests to let server recover
        sleep(2);
    }
}

int main(int argc, char* argv[]) {
    const char* host = "127.0.0.1";
    int port = BENCHMARK_PORT;
    int num_threads = NUM_THREADS;
    int requests_per_thread = NUM_REQUESTS / NUM_THREADS;
    
    // Parse command line arguments
    if (argc > 1) host = argv[1];
    if (argc > 2) port = atoi(argv[2]);
    if (argc > 3) num_threads = atoi(argv[3]);
    if (argc > 4) requests_per_thread = atoi(argv[4]);
    
    printf("NAS Web Server Benchmark Tool\n");
    printf("=============================\n");
    
    // Basic benchmark
    run_benchmark(host, port, "/api/status", num_threads, requests_per_thread);
    
    // Test different endpoints
    test_different_endpoints(host, port);
    
    // Load test
    load_test(host, port);
    
    return 0;
}
