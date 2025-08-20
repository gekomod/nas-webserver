#include "monitoring.h"
#include "../src/config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

#define MAX_EVENTS 10000
#define LOG_RETENTION_DAYS 30

static SecurityEvent security_events[MAX_EVENTS];
static int event_count = 0;
static pthread_mutex_t event_mutex = PTHREAD_MUTEX_INITIALIZER;
static Config app_config;

void monitoring_init(const Config* config) {
    if (!config) return;
    
    memcpy(&app_config, config, sizeof(Config));
    event_count = 0;
}

void log_security_event(SecurityLevel level, const char* event_type, 
                       const char* source_ip, const char* details, 
                       int user_id, int response_code) {
    if (!event_type || !source_ip || !details) return;
    
    pthread_mutex_lock(&event_mutex);
    
    if (event_count < MAX_EVENTS) {
        SecurityEvent* event = &security_events[event_count++];
        
        event->timestamp = time(NULL);
        event->level = level;
        event->user_id = user_id;
        event->response_code = response_code;
        
        strncpy(event->event_type, event_type, sizeof(event->event_type)-1);
        event->event_type[sizeof(event->event_type)-1] = '\0';
        
        strncpy(event->source_ip, source_ip, sizeof(event->source_ip)-1);
        event->source_ip[sizeof(event->source_ip)-1] = '\0';
        
        strncpy(event->details, details, sizeof(event->details)-1);
        event->details[sizeof(event->details)-1] = '\0';
        
        // Logowanie do pliku
        FILE* log_file = fopen(app_config.security_log_path, "a");
        if (log_file) {
            const char* level_str = "UNKNOWN";
            switch(level) {
                case SECURITY_CRITICAL: level_str = "CRITICAL"; break;
                case SECURITY_HIGH: level_str = "HIGH"; break;
                case SECURITY_MEDIUM: level_str = "MEDIUM"; break;
                case SECURITY_LOW: level_str = "LOW"; break;
                case SECURITY_INFO: level_str = "INFO"; break;
            }
            
            char time_buf[26];
            ctime_r(&event->timestamp, time_buf);
            time_buf[24] = '\0'; // Usuń newline
            
            fprintf(log_file, "[%s] %s - %s - %s - User: %d - %s\n",
                    level_str, event_type, source_ip, details, user_id, time_buf);
            fclose(log_file);
        }
    }
    
    pthread_mutex_unlock(&event_mutex);
}

int detect_sql_injection(const char* input) {
    if (!input) return 0;
    
    const char* patterns[] = {
        "' OR '1'='1", "--", ";", "/*", "*/", "UNION", "SELECT", "DROP", 
        "INSERT", "DELETE", "UPDATE", "EXEC", "XP_", "CHAR(", "WAITFOR", 
        "BENCHMARK", "SLEEP(", NULL
    };
    
    for (int i = 0; patterns[i] != NULL; i++) {
        if (strstr(input, patterns[i]) != NULL) {
            return 1;
        }
    }
    return 0;
}

int detect_xss_attempt(const char* input) {
    if (!input) return 0;
    
    const char* patterns[] = {
        "<script", "javascript:", "onload=", "onerror=", "onclick=",
        "alert(", "document.cookie", "eval(", "fromCharCode", 
        "innerHTML", "outerHTML", NULL
    };
    
    for (int i = 0; patterns[i] != NULL; i++) {
        if (strstr(input, patterns[i]) != NULL) {
            return 1;
        }
    }
    return 0;
}

int detect_path_traversal(const char* path) {
    if (!path) return 0;
    
    return strstr(path, "../") != NULL || 
           strstr(path, "..\\") != NULL ||
           strstr(path, "~/") != NULL;
}

int detect_brute_force(const char* ip_address) {
    if (!ip_address) return 0;
    
    time_t now = time(NULL);
    time_t window_start = now - 300; // 5 minut window
    int attempt_count = 0;
    
    pthread_mutex_lock(&event_mutex);
    
    for (int i = 0; i < event_count; i++) {
        if (security_events[i].timestamp >= window_start &&
            strcmp(security_events[i].source_ip, ip_address) == 0 &&
            strstr(security_events[i].event_type, "AUTH_FAILURE") != NULL) {
            attempt_count++;
        }
    }
    
    pthread_mutex_unlock(&event_mutex);
    
    return attempt_count > 10; // Więcej niż 10 prób w 5 minut
}

void monitoring_audit_file_access(const char* filename, const char* operation) {
    if (!filename || !operation) return;
    
    char details[512];
    snprintf(details, sizeof(details), "File %s: %s", operation, filename);
    
    log_security_event(SECURITY_INFO, "FILE_ACCESS", "localhost", 
                      details, getuid(), 200);
}

void monitoring_audit_api_call(const char* endpoint, const char* method) {
    if (!endpoint || !method) return;
    
    char details[512];
    snprintf(details, sizeof(details), "API %s %s", method, endpoint);
    
    log_security_event(SECURITY_INFO, "API_CALL", "localhost", 
                      details, 0, 200);
}

void monitoring_cleanup_old_logs(void) {
    time_t cutoff = time(NULL) - (LOG_RETENTION_DAYS * 24 * 3600);
    
    pthread_mutex_lock(&event_mutex);
    
    int write_index = 0;
    for (int i = 0; i < event_count; i++) {
        if (security_events[i].timestamp >= cutoff) {
            security_events[write_index++] = security_events[i];
        }
    }
    
    event_count = write_index;
    pthread_mutex_unlock(&event_mutex);
}
