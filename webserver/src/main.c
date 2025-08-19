#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/stat.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "config.h"
#include "router.h"
#include "error.h"
#include "profiler.h"
#include "http2.c"
#include "threadpool.h"

#ifndef SO_REUSEPORT
#define SO_REUSEPORT 15
#endif

#define BUFFER_SIZE 8192

typedef struct {
    int socket;
    SSL *ssl;
    Config *config;
} ConnectionArgs;

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
    // ALPN protocols
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
    
    char buffer[BUFFER_SIZE] = {0};
    ssize_t bytes_read = read(socket, buffer, BUFFER_SIZE - 1);
    
    if (bytes_read > 0) {
        buffer[bytes_read] = '\0';
        
        HTTPRequest request = parse_request(buffer);
        request.ssl = ssl;
        
        HTTPResponse response = handle_request(&request, config);
        
        size_t response_size = 0;
        char* http_response = build_response(&response, &response_size, config);
        
        if (http_response) {
            if (config->enable_https && ssl) {
                SSL_write(ssl, http_response, response_size);
            } else {
                safe_write(socket, http_response, response_size);
            }
            free(http_response);
        }
        
        free_response(&response);
    }
    
    // Cleanup
    if (config->enable_https && ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    close(socket);
    free(conn_args);
}

int main() {
    PROFILE_FUNCTION();
    Config config = load_config();
    init_cache();

    register_endpoint("/api/status", api_status);
    register_endpoint("/api/echo", api_echo);  // Poprawione: api_echo zamiast api_status

    // TWORZENIE THREADPOOL (na początku main)
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
            exit(EXIT_FAILURE);
        }
        if (stat(config.ssl_key_path, &st) != 0) {
            fprintf(stderr, "SSL key file not found: %s\n", config.ssl_key_path);
            exit(EXIT_FAILURE);
        }

        configure_context(ctx, config.ssl_cert_path, config.ssl_key_path);
    }

    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(config.port);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 10) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    printf("Server running on port %d (%s)\n", config.port, 
           config.enable_https ? "HTTPS" : "HTTP");

    while (1) {
        PROFILE_BLOCK(RequestHandling);
        if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
            perror("accept");
            continue;
        }

        SSL* ssl = NULL;
        if (config.enable_https) {
            ssl = SSL_new(ctx);
            SSL_set_fd(ssl, new_socket);
            if (SSL_accept(ssl) <= 0) {
                ERR_print_errors_fp(stderr);
                close(new_socket);
                SSL_free(ssl);
                continue;
            }

            if (config.http2_enabled) {
                const unsigned char* alpn = NULL;
                unsigned int alpn_len;
                SSL_get0_alpn_selected(ssl, &alpn, &alpn_len);
                
                if (alpn_len == 2 && memcmp("h2", alpn, 2) == 0) {
                    handle_http2_connection(new_socket, ssl, &config);
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
                continue;
            }
            
            conn_args->socket = new_socket;
            conn_args->ssl = ssl;
            conn_args->config = &config;
            
            if (threadpool_add(pool, handle_connection_wrapper, conn_args) != 0) {
                fprintf(stderr, "Failed to add task to thread pool\n");
                if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); }
                close(new_socket);
                free(conn_args);
            }
        } else {
            // OBSŁUGA BEZ THREADPOOL (oryginalny kod)
            char buffer[BUFFER_SIZE] = {0};
            ssize_t bytes_read = read(new_socket, buffer, BUFFER_SIZE - 1);
            
            if (bytes_read <= 0) {
                if (bytes_read == 0) {
                    printf("Connection closed by client\n");
                } else {
                    perror("read error");
                }
                if (config.enable_https && ssl) {
                    SSL_shutdown(ssl);
                    SSL_free(ssl);
                }
                close(new_socket);
                continue;
            }

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
            if (config.enable_https && ssl) {
                SSL_shutdown(ssl);
                SSL_free(ssl);
            }
            close(new_socket);
        }
    }

    // SPRZĄTANIE PRZY WYJŚCIU
    if (config.threadpool_enabled && pool) {
        threadpool_destroy(pool, 1);  // Graceful shutdown
    }
    
    if (config.enable_https) {
        SSL_CTX_free(ctx);
    }
    free_cache();
    return 0;
}