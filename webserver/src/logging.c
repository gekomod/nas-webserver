#include <stdlib.h>
#include "logging.h"
#include "config.h"
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <sys/stat.h>
#include <errno.h>
#include <limits.h>

static FILE* access_log = NULL;
static FILE* error_log = NULL;
static FILE* security_log = NULL;
static Config current_config;

// Helper function to safely create paths
static int create_log_path(char* path, size_t size, const char* base, int suffix) {
    if (suffix == 0) {
        return snprintf(path, size, "%s", base);
    } else {
        return snprintf(path, size, "%s.%d", base, suffix);
    }
}

void init_logging(const Config* config) {
    // Create log directories if they don't exist
    char access_dir[PATH_MAX], error_dir[PATH_MAX], security_dir[PATH_MAX];
    char* a_dir = dirname(strncpy(access_dir, config->access_log_path, sizeof(access_dir)));
    char* e_dir = dirname(strncpy(error_dir, config->error_log_path, sizeof(error_dir)));
    char* s_dir = dirname(strncpy(security_dir, config->security_log_path, sizeof(security_dir)));
    
    if (mkdir(a_dir, 0755) == -1 && errno != EEXIST) {
        perror("Failed to create access log directory");
        exit(EXIT_FAILURE);
    }
    
    if (mkdir(e_dir, 0755) == -1 && errno != EEXIST) {
        perror("Failed to create error log directory");
        exit(EXIT_FAILURE);
    }
    
    if (mkdir(s_dir, 0755) == -1 && errno != EEXIST) {
        perror("Failed to create security log directory");
        exit(EXIT_FAILURE);
    }
    
    // Open log files
    if (!(access_log = fopen(config->access_log_path, "a"))) {
        perror("Failed to open access log");
        exit(EXIT_FAILURE);
    }
    
    if (!(error_log = fopen(config->error_log_path, "a"))) {
        perror("Failed to open error log");
        fclose(access_log);
        exit(EXIT_FAILURE);
    }
    
    if (!(security_log = fopen(config->security_log_path, "a"))) {
        perror("Failed to open security log");
        fclose(access_log);
        fclose(error_log);
        exit(EXIT_FAILURE);
    }
    
    memcpy(&current_config, config, sizeof(Config));
}

void log_message(LogType type, const char* format, ...) {
    va_list args;
    va_start(args, format);
    
    time_t now = time(NULL);
    char timestamp[20];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));
    
    FILE* log_file = NULL;
    const char* type_str = "";
    
    switch (type) {
        case LOG_ACCESS:
            log_file = access_log;
            type_str = "ACCESS";
            break;
        case LOG_ERROR:
            log_file = error_log;
            type_str = "ERROR";
            break;
        case LOG_SECURITY:
            log_file = security_log;
            type_str = "SECURITY";
            break;
    }
    
    if (log_file) {
        fprintf(log_file, "[%s] [%s] ", timestamp, type_str);
        vfprintf(log_file, format, args);
        fprintf(log_file, "\n");
        fflush(log_file);
    }
    
    va_end(args);
    
    // Rotate logs if they're too large
    rotate_logs(&current_config);
}

void rotate_logs(const Config* config) {
    struct stat st;
    const char* logs[] = {config->access_log_path, config->error_log_path, config->security_log_path};
    
    for (int i = 0; i < 3; i++) {
        if (stat(logs[i], &st) == 0 && (size_t)st.st_size > config->log_max_size) {
            // Use PATH_MAX for safety
            char old_log[PATH_MAX];
            char oldest_log[PATH_MAX];
            
            // Create paths safely
            if (create_log_path(old_log, sizeof(old_log), logs[i], 1) >= (int)sizeof(old_log)) {
                continue; // Skip if path would be truncated
            }
            
            if (create_log_path(oldest_log, sizeof(oldest_log), logs[i], config->log_backup_count) >= (int)sizeof(oldest_log)) {
                continue;
            }
            
            // Remove oldest backup if it exists
            remove(oldest_log);
            
            // Rotate existing backups
            for (int j = config->log_backup_count - 1; j >= 1; j--) {
                char src[PATH_MAX], dest[PATH_MAX];
                
                if (create_log_path(src, sizeof(src), logs[i], j) >= (int)sizeof(src) ||
                    create_log_path(dest, sizeof(dest), logs[i], j + 1) >= (int)sizeof(dest)) {
                    continue;
                }
                
                if (access(src, F_OK) == 0) {
                    rename(src, dest);
                }
            }
            
            // Move current log to backup-1
            rename(logs[i], old_log);
        }
    }
    
    // Reopen log files
    close_logs();
    init_logging(config);
}

void close_logs() {
    if (access_log) {
        fclose(access_log);
        access_log = NULL;
    }
    if (error_log) {
        fclose(error_log);
        error_log = NULL;
    }
    if (security_log) {
        fclose(security_log);
        security_log = NULL;
    }
}