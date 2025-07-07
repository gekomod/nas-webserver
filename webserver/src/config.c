#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"

Config load_config() {
    Config config;
    // Domyślne wartości
    config.port = 8080;
    strcpy(config.frontend_path, "../qnap-like-dashboard/backend/dist");
    strcpy(config.api_prefix, "/api");
    
    FILE *env_file = fopen("/etc/nas-web/nas-web.conf", "r");
    if (env_file == NULL) {
        printf("Brak pliku .conf, używam domyślnych wartości\n");
        return config;
    }
    
    char line[256];
    while (fgets(line, sizeof(line), env_file)) {
        // Pomijaj komentarze
        if (line[0] == '#') continue;
        
        char key[50], value[200];
        if (sscanf(line, "%[^=]=%s", key, value) == 2) {
            if (strcmp(key, "PORT") == 0) {
                config.port = atoi(value);
            } else if (strcmp(key, "FRONTEND_PATH") == 0) {
                strcpy(config.frontend_path, value);
            } else if (strcmp(key, "API_PREFIX") == 0) {
                strcpy(config.api_prefix, value);
            }
        }
    }
    
    fclose(env_file);
    return config;
}
