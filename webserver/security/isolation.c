#include "isolation.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <grp.h>
#include <pwd.h>
#include <string.h>
#include <errno.h>

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifdef HAVE_LIBCAP
#include <sys/capability.h>
#endif

static IsolationConfig current_config;

void isolation_init(const IsolationConfig* config) {
    if (!config) return;
    
    memcpy(&current_config, config, sizeof(IsolationConfig));

    isolation_set_resource_limits();

    if (config->working_directory && config->working_directory[0] != '\0') {
        if (chdir(config->working_directory) != 0) {
            perror("Failed to change working directory");
            exit(EXIT_FAILURE);
        }
    }

    if (config->chroot_path && config->chroot_path[0] != '\0') {
        isolation_enter_chroot();
    }
    
#ifdef HAVE_LIBCAP
    isolation_limit_capabilities(config->capabilities);
#endif
}

void isolation_drop_privileges(void) {
    if (getuid() == 0) {
        if (setgid(current_config.group_id) != 0) {
            perror("Failed to setgid");
            exit(EXIT_FAILURE);
        }

        if (setuid(current_config.user_id) != 0) {
            perror("Failed to setuid");
            exit(EXIT_FAILURE);
        }

        #if defined(_GNU_SOURCE)
        if (setgroups(0, NULL) != 0) {
            perror("Failed to drop supplementary groups");
        }
        #endif
    }
}

void isolation_enter_chroot(void) {
    #if defined(_BSD_SOURCE) || defined(_GNU_SOURCE)
    if (chroot(current_config.chroot_path) != 0) {
        perror("Failed to chroot");
        exit(EXIT_FAILURE);
    }
    #else
    fprintf(stderr, "Warning: chroot not supported on this system\n");
    #endif
}

void isolation_limit_capabilities(int capabilities) {
    // Implementacja tylko jeśli libcap jest dostępne
    #ifdef HAVE_LIBCAP
    cap_t caps = cap_init();
    
    if (!caps) {
        perror("Failed to initialize capabilities");
        return;
    }

    cap_value_t cap_list[] = {CAP_NET_BIND_SERVICE};
    
    if (capabilities & CAP_NET_BIND_SERVICE) {
        cap_set_flag(caps, CAP_EFFECTIVE, 1, cap_list, CAP_SET);
        cap_set_flag(caps, CAP_PERMITTED, 1, cap_list, CAP_SET);
    }
    
    if (cap_set_proc(caps) != 0) {
        perror("Failed to set capabilities");
    }
    
    cap_free(caps);
    #else
    // Fallback: logowanie ostrzeżenia
    fprintf(stderr, "Warning: libcap not available, capabilities limited\n");
    #endif
}

void isolation_set_resource_limits(void) {
    struct rlimit limits;
    
    // Limit liczby procesów
    limits.rlim_cur = 64;
    limits.rlim_max = 128;
    if (setrlimit(RLIMIT_NPROC, &limits) != 0) {
        perror("Warning: Failed to set process limit");
    }
    
    // Limit otwartych plików
    limits.rlim_cur = 1024;
    limits.rlim_max = 2048;
    if (setrlimit(RLIMIT_NOFILE, &limits) != 0) {
        perror("Warning: Failed to set file limit");
    }
    
    // Limit stack size
    limits.rlim_cur = 8 * 1024 * 1024; // 8MB
    limits.rlim_max = 16 * 1024 * 1024; // 16MB
    if (setrlimit(RLIMIT_STACK, &limits) != 0) {
        perror("Warning: Failed to set stack limit");
    }
    
    // Limit core dump size (zapobiega dumpom pamięci)
    limits.rlim_cur = 0;
    limits.rlim_max = 0;
    if (setrlimit(RLIMIT_CORE, &limits) != 0) {
        perror("Warning: Failed to set core limit");
    }
}

int isolation_secure_directory(const char* path) {
    if (!path) return -1;
    
    struct stat st;
    
    if (stat(path, &st) != 0) {
        return -1;
    }
    
    if (st.st_mode & S_IWOTH) {
        return chmod(path, st.st_mode & ~S_IWOTH);
    }
    
    return 0;
}
