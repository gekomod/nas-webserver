#ifndef MONITORING_H
#define MONITORING_H

#include <time.h>
#include "../src/config.h"

typedef enum {
    SECURITY_CRITICAL = 0,
    SECURITY_HIGH,
    SECURITY_MEDIUM, 
    SECURITY_LOW,
    SECURITY_INFO
} SecurityLevel;

typedef struct {
    time_t timestamp;
    SecurityLevel level;
    char source_ip[46];
    char event_type[50];
    char details[512];
    int user_id;
    int response_code;
} SecurityEvent;

void monitoring_init(const Config* config);
void log_security_event(SecurityLevel level, const char* event_type, 
                       const char* source_ip, const char* details, 
                       int user_id, int response_code);
void monitoring_check_suspicious_activity(void);
void monitoring_audit_file_access(const char* filename, const char* operation);
void monitoring_audit_api_call(const char* endpoint, const char* method);
void monitoring_cleanup_old_logs(void);

// Detekcja patternów ataków
int detect_sql_injection(const char* input);
int detect_xss_attempt(const char* input);
int detect_path_traversal(const char* path);
int detect_brute_force(const char* ip_address);

#endif
