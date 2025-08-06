#include <nghttp2/nghttp2.h>
#include "router.h"
#include "config.h"

typedef struct {
    nghttp2_session *session;
    SSL *ssl;
    int socket;
    const Config *config;
} HTTP2Connection;

static ssize_t send_callback(nghttp2_session *session, const uint8_t *data,
                           size_t length, int flags, void *user_data) {
    HTTP2Connection *conn = (HTTP2Connection *)user_data;
    (void)session;  // Mark as unused
    (void)flags;    // Mark as unused
    
    int rv = SSL_write(conn->ssl, data, length);
    if (rv < 0) {
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    return rv;
}

static int on_frame_recv_callback(nghttp2_session *session,
                                const nghttp2_frame *frame,
                                void *user_data) {
    (void)session;  // Mark as unused
    (void)frame;    // Mark as unused
    (void)user_data; // Mark as unused
    
    // Handle received frames here
    return 0;
}

HTTP2Connection* http2_init_connection(int socket, SSL *ssl, const Config *config) {
    HTTP2Connection *conn = malloc(sizeof(HTTP2Connection));
    if (!conn) return NULL;
    
    nghttp2_session_callbacks *callbacks;
    nghttp2_session_callbacks_new(&callbacks);
    
    nghttp2_session_callbacks_set_send_callback(callbacks, send_callback);
    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, on_frame_recv_callback);
    
    nghttp2_session_server_new(&conn->session, callbacks, conn);
    nghttp2_session_callbacks_del(callbacks);
    
    conn->ssl = ssl;
    conn->socket = socket;
    conn->config = config;
    
    // HTTP/2 settings
    nghttp2_settings_entry iv[] = {
        {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, config->http2_max_streams},
        {NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, config->http2_window_size},
        {NGHTTP2_SETTINGS_ENABLE_PUSH, 0} // Disable server push
    };
    
    nghttp2_submit_settings(conn->session, NGHTTP2_FLAG_NONE, iv, sizeof(iv)/sizeof(iv[0]));
    return conn;
}

void http2_cleanup_connection(HTTP2Connection *conn) {
    if (conn) {
        if (conn->session) {
            nghttp2_session_del(conn->session);
        }
        free(conn);
    }
}