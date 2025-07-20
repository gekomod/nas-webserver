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

#ifndef SO_REUSEPORT
#define SO_REUSEPORT 15
#endif

#define BUFFER_SIZE 8192

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

int main() {
    PROFILE_FUNCTION();
    Config config = load_config();
    init_cache();

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
    char buffer[BUFFER_SIZE] = {0};

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
        }

        ssize_t bytes_read = read(new_socket, buffer, BUFFER_SIZE - 1);
        if (bytes_read <= 0) {
            if (bytes_read == 0) {
                printf("Connection closed by client\n");
            } else {
                perror("read error");
            }
            if (config.enable_https) {
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
            if (config.enable_https) {
                SSL_write(ssl, http_response, response_size);
            } else {
                write(new_socket, http_response, response_size);
            }
            free(http_response);
        } else {
            HTTPResponse error = error_response(500, "Internal Server Error");
            char* error_resp = build_response(&error, &response_size, &config);
            if (error_resp) {
                if (config.enable_https) {
                    SSL_write(ssl, error_resp, response_size);
                } else {
                    write(new_socket, error_resp, response_size);
                }
                free(error_resp);
            }
            free_response(&error);
        }

        free_response(&response);
        if (config.enable_https) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
        }
        close(new_socket);
    }

    if (config.enable_https) {
        SSL_CTX_free(ctx);
    }
    free_cache();
    return 0;
}
