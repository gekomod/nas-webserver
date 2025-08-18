#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/stat.h>
#include "config.h"

void safe_strcpy(char* dest, const char* src, size_t dest_size) {
    if (!dest || !src || dest_size == 0) return;
    
    size_t src_len = strlen(src);
    size_t copy_len = src_len < dest_size ? src_len : dest_size - 1;
    
    memcpy(dest, src, copy_len);
    dest[copy_len] = '\0';
}

Config load_config() {
    Config config = {
        // Default values
        .port = 80,
        .frontend_path = "/opt/nas-panel/dist",
        .api_prefix = "/api",
        .enable_https = 0,
        .ssl_cert_path = "",
        .ssl_key_path = "",
        .cache_enabled = 1,
        .cache_max_size = 100 * 1024 * 1024, // 100MB
        .cache_ttl = 3600,
        .gzip_enabled = 1,
        .gzip_min_size = 1024,
        .cors_enabled = 1,
        .hsts_enabled = 0,
        .hsts_max_age = 31536000,
        .log_level = "info",
        .log_file = "/var/log/nas-web.log",
        .log_max_size = 10 * 1024 * 1024,
        .log_backup_count = 5,
        .max_threads = 10,
        .max_connections = 100,
        .connection_timeout = 30,
        .http2_enabled = 0,
        .http2_cert_path = "",
        .http2_key_path = "",
        .http2_max_streams = 100,
        .http2_window_size = 65536,
        .access_log_path = "/var/log/nas-web/access.log",
        .error_log_path = "/var/log/nas-web/error.log",
        .security_log_path = "/var/log/nas-web/security.log"
    };

    FILE *config_file = fopen("/etc/nas-web/nas-web.conf", "r");
    if (!config_file) {
        printf("Using default configuration\n");
        return config;
    }
    char line[256];
    while (fgets(line, sizeof(line), config_file)) {
        // Skip comments and empty lines
        if (line[0] == '#' || line[0] == '\n') continue;
        
        char key[50], value[200];
        if (sscanf(line, "%[^=]=%s", key, value) == 2) {
            if (strcmp(key, "PORT") == 0) {
                int port = atoi(value);
                if (port > 0 && port <= 65535) config.port = port;
            }
            else if (strcmp(key, "FRONTEND_PATH") == 0) {
                safe_strcpy(config.frontend_path, value, sizeof(config.frontend_path)-1);
            }
            else if (strcmp(key, "API_PREFIX") == 0) {
                safe_strcpy(config.api_prefix, value, sizeof(config.api_prefix)-1);
            }
            else if (strcmp(key, "ENABLE_HTTPS") == 0) {
                config.enable_https = (strcasecmp(value, "true") == 0);
            }
            else if (strcmp(key, "SSL_CERT_PATH") == 0) {
                safe_strcpy(config.ssl_cert_path, value, sizeof(config.ssl_cert_path)-1);
            }
            else if (strcmp(key, "SSL_KEY_PATH") == 0) {
                safe_strcpy(config.ssl_key_path, value, sizeof(config.ssl_key_path)-1);
            }
            else if (strcmp(key, "CACHE_ENABLED") == 0) {
                config.cache_enabled = (strcasecmp(value, "true") == 0);
            }
            else if (strcmp(key, "CACHE_MAX_SIZE") == 0) {
                size_t size = atoi(value);
                if (size > 0) config.cache_max_size = size * 1024 * 1024; // Convert MB to bytes
            }
            else if (strcmp(key, "CACHE_TTL") == 0) {
                int ttl = atoi(value);
                if (ttl > 0) config.cache_ttl = ttl;
            }
            else if (strcmp(key, "GZIP_ENABLED") == 0) {
                config.gzip_enabled = (strcasecmp(value, "true") == 0);
            }
            else if (strcmp(key, "GZIP_MIN_SIZE") == 0) {
                size_t min_size = atoi(value);
                if (min_size > 0) config.gzip_min_size = min_size;
            }
            else if (strcmp(key, "CORS_ENABLED") == 0) {
                config.cors_enabled = (strcasecmp(value, "true") == 0);
            }
            else if (strcmp(key, "HSTS_ENABLED") == 0) {
                config.hsts_enabled = (strcasecmp(value, "true") == 0);
            }
            else if (strcmp(key, "HSTS_MAX_AGE") == 0) {
                int max_age = atoi(value);
                if (max_age > 0) config.hsts_max_age = max_age;
            }
            else if (strcmp(key, "LOG_LEVEL") == 0) {
                if (strcasecmp(value, "debug") == 0 || strcasecmp(value, "info") == 0 ||
		    strcasecmp(value, "warning") == 0 || strcasecmp(value, "error") == 0) {
		    safe_strcpy(config.log_level, value, sizeof(config.log_level)-1);
                }
            }
            else if (strcmp(key, "LOG_FILE") == 0) {
                strncpy(config.log_file, value, sizeof(config.log_file)-1);
            }
            else if (strcmp(key, "LOG_MAX_SIZE") == 0) {
                size_t max_size = atoi(value);
                if (max_size > 0) config.log_max_size = max_size * 1024 * 1024; // Convert MB to bytes
            }
            else if (strcmp(key, "LOG_BACKUP_COUNT") == 0) {
                int count = atoi(value);
                if (count > 0) config.log_backup_count = count;
            }
            else if (strcmp(key, "MAX_THREADS") == 0) {
                int threads = atoi(value);
                if (threads > 0) config.max_threads = threads;
            }
            else if (strcmp(key, "MAX_CONNECTIONS") == 0) {
                int connections = atoi(value);
                if (connections > 0) config.max_connections = connections;
            }
            else if (strcmp(key, "CONNECTION_TIMEOUT") == 0) {
                int timeout = atoi(value);
                if (timeout > 0) config.connection_timeout = timeout;
            }
        }
    }

    fclose(config_file);

    // Validate paths
    struct stat st;
    if (config.enable_https) {
        if (stat(config.ssl_cert_path, &st) != 0) {
            fprintf(stderr, "SSL certificate file not found: %s\n", config.ssl_cert_path);
            config.enable_https = 0;
        }
        if (stat(config.ssl_key_path, &st) != 0) {
            fprintf(stderr, "SSL key file not found: %s\n", config.ssl_key_path);
            config.enable_https = 0;
        }
    }

    // Check port 80 permissions
    if (config.port == 80 && geteuid() != 0) {
        fprintf(stderr, "Warning: Port 80 requires root privileges. Falling back to port 8080.\n");
        config.port = 8080;
    }

    return config;
}
