#ifndef ISOLATION_H
#define ISOLATION_H

#include <sys/types.h>

typedef struct {
    uid_t user_id;
    gid_t group_id;
    char* chroot_path;
    char* working_directory;
    int no_new_privileges;
    int capabilities;
} IsolationConfig;

// Flagi capabilities
#define CAP_NET_BIND_SERVICE  (1 << 0)
#define CAP_DAC_OVERRIDE      (1 << 1)

void isolation_init(const IsolationConfig* config);
void isolation_drop_privileges(void);
void isolation_enter_chroot(void);
void isolation_limit_capabilities(int capabilities);
void isolation_set_resource_limits(void);
int isolation_secure_directory(const char* path);

#endif
