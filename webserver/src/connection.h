 #ifndef CONNECTION_H
#define CONNECTION_H

#include <pthread.h>
#include <stdio.h>

// Globalne zmienne do zarządzania połączeniami
extern int active_connections;
extern int total_connections;
extern int failed_connections;
extern pthread_mutex_t conn_mutex;
extern pthread_cond_t conn_cond;

// Funkcje do zarządzania połączeniami
int try_accept_connection(int max_connections);
void decrement_connections();
void log_connection_stats();

#endif // CONNECTION_H
