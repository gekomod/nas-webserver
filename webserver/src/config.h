#ifndef CONFIG_H
#define CONFIG_H

typedef struct {
    // Basic Configuration
    int port;
    char frontend_path[256];
    char api_prefix[50];
    
    // HTTPS Configuration
    int enable_https;
    char ssl_cert_path[256];
    char ssl_key_path[256];
    
    // Cache Configuration
    int cache_enabled;
    size_t cache_max_size;
    int cache_ttl;
    
    // Compression
    int gzip_enabled;
    size_t gzip_min_size;
    
    // Security Headers
    int cors_enabled;
    int hsts_enabled;
    int hsts_max_age;
    
    // Logging
    char log_level[10];
    char log_file[256];
    size_t log_max_size;
    int log_backup_count;
    
    // Performance
    int max_threads;
    int max_connections;
    int connection_timeout;

    // HTTP/2 Configuration
    int http2_enabled;
    char http2_cert_path[256];
    char http2_key_path[256];
    unsigned int http2_max_streams;
    unsigned int http2_window_size;

    // Miscellaneous
    char access_log_path[256];
    char error_log_path[256];
    char security_log_path[256];
} Config;

Config load_config();

#endif // CONFIG_H
