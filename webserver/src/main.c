#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <poll.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "config.h"
#include "router.h"
#include "error.h"
#include "profiler.h"
#include "http2.c"
#include "threadpool.h"
#include "logging.h"
#include <netinet/tcp.h>

#ifndef SO_REUSEPORT
#define SO_REUSEPORT 15
#endif

#define BUFFER_SIZE 8192
#define MAX_BACKLOG 4096

// Globalne zmienne do zarządzania połączeniami
static int active_connections = 0;
static int total_connections = 0;
static int failed_connections = 0;
static pthread_mutex_t conn_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t conn_cond = PTHREAD_COND_INITIALIZER;
static volatile int server_running = 1;

typedef struct {
    int socket;
    SSL *ssl;
    Config *config;
} ConnectionArgs;

// Handler dla SIGINT i SIGTERM
void signal_handler(int sig) {
    printf("\nReceived signal %d, shutting down...\n", sig);
    server_running = 0;
}

void set_socket_timeout(int socket, int seconds) {
    struct timeval timeout;
    timeout.tv_sec = seconds;
    timeout.tv_usec = 0;
    
    if (setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("setsockopt SO_RCVTIMEO failed");
    }
    if (setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("setsockopt SO_SNDTIMEO failed");
    }
}

void set_nonblocking(int socket) {
    int flags = fcntl(socket, F_GETFL, 0);
    if (flags == -1) {
        perror("fcntl F_GETFL");
        return;
    }
    if (fcntl(socket, F_SETFL, flags | O_NONBLOCK) == -1) {
        perror("fcntl F_SETFL");
    }
}

void set_blocking(int socket) {
    int flags = fcntl(socket, F_GETFL, 0);
    if (flags == -1) {
        perror("fcntl F_GETFL");
        return;
    }
    if (fcntl(socket, F_SETFL, flags & ~O_NONBLOCK) == -1) {
        perror("fcntl F_SETFL");
    }
}

int read_with_timeout(int socket, char* buffer, size_t size, int timeout_seconds) {
    struct pollfd fds;
    fds.fd = socket;
    fds.events = POLLIN;
    
    int ret = poll(&fds, 1, timeout_seconds * 1000);
    if (ret < 0) {
        return -1; // Błąd
    }
    if (ret == 0) {
        return -2; // Timeout
    }
    
    return read(socket, buffer, size);
}

int try_accept_connection(int max_connections) {
    pthread_mutex_lock(&conn_mutex);
    
    while (active_connections >= max_connections && server_running) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += 1; // Czekaj max 1 sekundę
        
        int ret = pthread_cond_timedwait(&conn_cond, &conn_mutex, &ts);
        if (ret == ETIMEDOUT) {
            pthread_mutex_unlock(&conn_mutex);
            return -1; // Przeciążenie
        }
    }
    
    if (!server_running) {
        pthread_mutex_unlock(&conn_mutex);
        return -2; // Serwer zamykany
    }
    
    active_connections++;
    total_connections++;
    pthread_mutex_unlock(&conn_mutex);
    return 0;
}

void decrement_connections() {
    pthread_mutex_lock(&conn_mutex);
    if (active_connections > 0) {
        active_connections--;
        pthread_cond_signal(&conn_cond);
    }
    pthread_mutex_unlock(&conn_mutex);
}

SSL_CTX* create_context() {
    const SSL_METHOD* method = TLS_server_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

void configure_context(SSL_CTX* ctx, const char* cert_path, const char* key_path) {
    SSL_CTX_set_ecdh_auto(ctx, 1);
    if (SSL_CTX_use_certificate_file(ctx, cert_path, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    // Ustaw timeouty dla SSL
    SSL_CTX_set_timeout(ctx, 30);
}

void handle_http2_connection(int socket, SSL *ssl, const Config *config) {
    HTTP2Connection *conn = http2_init_connection(socket, ssl, config);
    if (!conn) {
        close(socket);
        return;
    }

    uint8_t buf[4096];
    ssize_t rv;
    
    while ((rv = SSL_read(ssl, buf, sizeof(buf))) > 0) {
        if (nghttp2_session_mem_recv(conn->session, buf, rv) < 0) {
            break;
        }
        if (nghttp2_session_send(conn->session) < 0) {
            break;
        }
    }
    
    http2_cleanup_connection(conn);
}

static int next_proto_cb(SSL *ssl, const unsigned char **data,
                        unsigned int *len, void *arg) {
    (void)ssl;
    (void)arg;
    static const unsigned char protos[] = {2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.' ,'1'};
    *data = protos;
    *len = sizeof(protos);
    return SSL_TLSEXT_ERR_OK;
}

void configure_http2_context(SSL_CTX *ctx) {
    const unsigned char alpn_protos[] = {2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.' ,'1'};
    SSL_CTX_set_alpn_protos(ctx, alpn_protos, sizeof(alpn_protos));
    SSL_CTX_set_next_protos_advertised_cb(ctx, next_proto_cb, NULL);
}

void safe_write(int fd, const void* buf, size_t count) {
    ssize_t bytes_written;
    size_t total_written = 0;
    const char* ptr = buf;
    
    while (total_written < count) {
        bytes_written = write(fd, ptr + total_written, count - total_written);
        if (bytes_written < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // Socket buffer pełny, spróbuj ponownie po krótkim czasie
                usleep(1000);
                continue;
            }
            perror("write failed");
            break;
        }
        total_written += bytes_written;
    }
}

void handle_connection_wrapper(void *arg) {
    ConnectionArgs *conn_args = (ConnectionArgs *)arg;
    int socket = conn_args->socket;
    SSL *ssl = conn_args->ssl;
    Config *config = conn_args->config;
    
    // Ustaw timeout dla tego połączenia
    set_socket_timeout(socket, config->connection_timeout);
    
    char buffer[BUFFER_SIZE] = {0};
    
    // Użyj poll do sprawdzenia czy są dane do czytania
    struct pollfd fds;
    fds.fd = socket;
    fds.events = POLLIN;
    
    int poll_result = poll(&fds, 1, config->connection_timeout * 1000);
    
    if (poll_result > 0 && (fds.revents & POLLIN)) {
        // Są dane do czytania
        ssize_t bytes_read;
        
        if (config->enable_https && ssl) {
            bytes_read = SSL_read(ssl, buffer, BUFFER_SIZE - 1);
        } else {
            bytes_read = read(socket, buffer, BUFFER_SIZE - 1);
        }
        
        if (bytes_read > 0) {
            buffer[bytes_read] = '\0';
            
            HTTPRequest request = parse_request(buffer);
            request.ssl = ssl;
            
            HTTPResponse response = handle_request(&request, config);
            
            size_t response_size = 0;
            char* http_response = build_response(&response, &response_size, config);
            
            if (http_response) {
                ssize_t bytes_written;
                if (config->enable_https && ssl) {
                    bytes_written = SSL_write(ssl, http_response, response_size);
                } else {
                    bytes_written = write(socket, http_response, response_size);
                }
                
                if (bytes_written != (ssize_t)response_size) {
                    log_message(LOG_ERROR, "Failed to send complete response");
                }
                
                free(http_response);
            }
            
            free_response(&response);
        } else if (bytes_read == 0) {
            // Klient zamknął połączenie
            log_message(LOG_ACCESS, "Client closed connection");
        } else {
            // Błąd czytania
            log_message(LOG_ERROR, "Error reading from socket: %s", strerror(errno));
            pthread_mutex_lock(&conn_mutex);
            failed_connections++;
            pthread_mutex_unlock(&conn_mutex);
        }
    } else if (poll_result == 0) {
        // Timeout
        log_message(LOG_ERROR, "Connection timeout");
        pthread_mutex_lock(&conn_mutex);
        failed_connections++;
        pthread_mutex_unlock(&conn_mutex);
    } else {
        // Błąd poll
        log_message(LOG_ERROR, "Poll error: %s", strerror(errno));
        pthread_mutex_lock(&conn_mutex);
        failed_connections++;
        pthread_mutex_unlock(&conn_mutex);
    }
    
    // Cleanup
    if (config->enable_https && ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    close(socket);
    free(conn_args);
    
    // Zmniejsz licznik aktywnych połączeń
    decrement_connections();
}

// Funkcja do logowania statystyk co minutę
void* stats_logger(void* arg) {
    (void)arg;
    
    while (server_running) {
        sleep(60); // Loguj co minutę
        
        pthread_mutex_lock(&conn_mutex);
        printf("\n=== STATYSTYKI POŁĄCZEŃ ===\n");
        printf("Czas: %s", ctime(&(time_t){time(NULL)}));
        printf("Aktywne połączenia: %d\n", active_connections);
        printf("Łącznie połączeń: %d\n", total_connections);
        printf("Nieudane połączenia: %d\n", failed_connections);
        printf("============================\n\n");
        pthread_mutex_unlock(&conn_mutex);
    }
    
    return NULL;
}

int main() {
    PROFILE_FUNCTION();
    
    // Ustaw handler sygnałów
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN); // Ignoruj SIGPIPE
    
    Config config = load_config();
    
    // Inicjalizacja logowania
    init_logging(&config);
    log_message(LOG_ACCESS, "Server starting on port %d", config.port);
    
    init_cache();
    server_start_time = time(NULL);

    // Rejestracja endpointów
    register_endpoint("/apis/statusa", api_status);
    register_endpoint("/apis/echo", api_echo);
    register_endpoint("/apis/healths", api_health);
    register_endpoint("/apis/heartbeat", api_heartbeat);
    register_endpoint("/apis/ping", api_ping);
    register_endpoint("/apis/auth/check", api_auth_check);
    register_endpoint("/apis/system/boot-time", api_system_boot_time);
    register_endpoint("/apis/system-health", api_system_health);

    init_api_routes();

    // TWORZENIE THREADPOOL
    ThreadPool* pool = NULL;
    if (config.threadpool_enabled) {
        pool = threadpool_create(config.max_threads, config.max_connections);
        if (!pool) {
            fprintf(stderr, "Failed to create thread pool, continuing without threadpool\n");
            config.threadpool_enabled = 0;
        } else {
            printf("ThreadPool created with %d threads and %d queue size\n", 
                   config.max_threads, config.max_connections);
        }
    }

    // Uruchom wątek do logowania statystyk
    pthread_t stats_thread;
    pthread_create(&stats_thread, NULL, stats_logger, NULL);

    SSL_CTX* ctx = NULL;
    if (config.enable_https) {
        ctx = create_context();
        if (!ctx) {
            fprintf(stderr, "Error creating SSL context\n");
            exit(EXIT_FAILURE);
        }

        struct stat st;
        if (stat(config.ssl_cert_path, &st) != 0) {
            fprintf(stderr, "SSL certificate file not found: %s\n", config.ssl_cert_path);
            config.enable_https = 0;
        } else if (stat(config.ssl_key_path, &st) != 0) {
            fprintf(stderr, "SSL key file not found: %s\n", config.ssl_key_path);
            config.enable_https = 0;
        } else {
            configure_context(ctx, config.ssl_cert_path, config.ssl_key_path);
            if (config.http2_enabled) {
                configure_http2_context(ctx);
            }
        }
    }

    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Ustaw opcje socketu
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("setsockopt SO_REUSEADDR");
        exit(EXIT_FAILURE);
    }
    
    // Zwiększ rozmiar kolejki
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("setsockopt SO_REUSEPORT");
        // Nie wychodź, to opcjonalne
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(config.port);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, MAX_BACKLOG) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    printf("Server running on port %d (%s)\n", config.port, 
           config.enable_https ? "HTTPS" : "HTTP");
    printf("Max threads: %d, Max connections: %d\n", 
           config.max_threads, config.max_connections);

    while (server_running) {
        PROFILE_BLOCK(RequestHandling);
        
        // Użyj poll do sprawdzenia czy są nowe połączenia z timeoutem
        struct pollfd pfd;
        pfd.fd = server_fd;
        pfd.events = POLLIN;
        
        int poll_result = poll(&pfd, 1, 1000); // 1 sekunda timeout
        
        if (poll_result < 0) {
            if (errno == EINTR) continue;
            perror("poll");
            continue;
        }

        if (poll_result == 0) continue; // Timeout, sprawdź czy serwer nadal działa
        
		if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
			if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
			perror("accept");
			continue;
		}
		
		int flag = 1;
		if (setsockopt(new_socket, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag)) < 0) {
			perror("setsockopt TCP_NODELAY");
		}

		set_socket_timeout(new_socket, config.connection_timeout);
        // Sprawdź czy możemy przyjąć połączenie
        int accept_result = try_accept_connection(config.max_connections);
        if (accept_result != 0) {
            if (accept_result == -1) {
                // Serwer przeciążony - odeślij 503 Service Unavailable
                const char* busy_msg = "HTTP/1.1 503 Service Unavailable\r\n"
                                       "Content-Length: 0\r\n"
                                       "Connection: close\r\n\r\n";
                send(new_socket, busy_msg, strlen(busy_msg), 0);
            }
            close(new_socket);
            continue;
        }

        // Ustaw timeout na 30 sekund dla tego socketu
        set_socket_timeout(new_socket, config.connection_timeout);

        SSL* ssl = NULL;
        if (config.enable_https && ctx) {
            ssl = SSL_new(ctx);
            SSL_set_fd(ssl, new_socket);
            
            // Ustaw timeout dla SSL
            SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
            
            if (SSL_accept(ssl) <= 0) {
                ERR_print_errors_fp(stderr);
                SSL_free(ssl);
                close(new_socket);
                decrement_connections();
                continue;
            }

            if (config.http2_enabled) {
                const unsigned char* alpn = NULL;
                unsigned int alpn_len;
                SSL_get0_alpn_selected(ssl, &alpn, &alpn_len);
                
                if (alpn_len == 2 && memcmp("h2", alpn, 2) == 0) {
                    handle_http2_connection(new_socket, ssl, &config);
                    decrement_connections();
                    continue;
                }
            }
        }

        if (config.threadpool_enabled && pool) {
            ConnectionArgs *conn_args = malloc(sizeof(ConnectionArgs));
            if (!conn_args) {
                perror("malloc failed for connection args");
                if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); }
                close(new_socket);
                decrement_connections();
                continue;
            }
            
            conn_args->socket = new_socket;
            conn_args->ssl = ssl;
            conn_args->config = &config;
            
            int add_result = threadpool_add(pool, handle_connection_wrapper, conn_args);
            if (add_result != 0) {
                fprintf(stderr, "Failed to add task to thread pool: %d\n", add_result);
                if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); }
                close(new_socket);
                free(conn_args);
                decrement_connections();
                
                pthread_mutex_lock(&conn_mutex);
                failed_connections++;
                pthread_mutex_unlock(&conn_mutex);
            }
        } else {
            // Obsługa bez threadpool
            char buffer[BUFFER_SIZE] = {0};
            ssize_t bytes_read = read(new_socket, buffer, BUFFER_SIZE - 1);
            
            if (bytes_read > 0) {
                buffer[bytes_read] = '\0';

                HTTPRequest request = parse_request(buffer);
                request.ssl = ssl;

                HTTPResponse response = handle_request(&request, &config);

                size_t response_size = 0;
                char* http_response = build_response(&response, &response_size, &config);

                if (http_response) {
                    if (config.enable_https && ssl) {
                        SSL_write(ssl, http_response, response_size);
                    } else {
                        safe_write(new_socket, http_response, response_size);
                    }
                    free(http_response);
                }

                free_response(&response);
            } else {
                pthread_mutex_lock(&conn_mutex);
                failed_connections++;
                pthread_mutex_unlock(&conn_mutex);
            }
            
            if (config.enable_https && ssl) {
                SSL_shutdown(ssl);
                SSL_free(ssl);
            }
            close(new_socket);
            decrement_connections();
        }
    }

    printf("\nShutting down server...\n");
    log_message(LOG_ACCESS, "Server shutting down");

    // Zatrzymaj wątek statystyk
    server_running = 0;
    pthread_join(stats_thread, NULL);

    // SPRZĄTANIE PRZY WYJŚCIU
    if (config.threadpool_enabled && pool) {
        printf("Waiting for threadpool to finish...\n");
        threadpool_destroy(pool, 1);  // Graceful shutdown
    }
    
    if (config.enable_https && ctx) {
        SSL_CTX_free(ctx);
    }
    
    close(server_fd);
    free_cache();
    close_logs();
    
    printf("Server stopped.\n");
    return 0;
}
