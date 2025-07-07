#ifndef CONFIG_H
#define CONFIG_H

typedef struct {
    int port;
    char frontend_path[256];
    char api_prefix[50];
} Config;

Config load_config();

#endif
