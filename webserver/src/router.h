#ifndef ROUTER_H
#define ROUTER_H

#include "config.h"
#include <strings.h>
#include <stdlib.h>

// Function declarations
void normalize_path(char* path);
const char* get_mime_type(const char* filename);

typedef struct {
    char method[10];
    char path[256];
    char protocol[32];
    char headers[1024];
    char body[4096];
} HTTPRequest;

typedef struct {
    int status_code;
    char content_type[64];
    char* content;       // Dynamic allocation
    size_t content_size; // Track content size
    unsigned char is_binary;
} HTTPResponse;

HTTPRequest parse_request(const char* raw_request);
HTTPResponse handle_request(const HTTPRequest* request, const Config* config);
char* build_response(const HTTPResponse* response, size_t* response_size);
char* read_file_content(const char* path, size_t* out_size);
void url_decode(char* str);
void free_response(HTTPResponse* response); // Single declaration
int hex_to_int(char c);

HTTPResponse api_status(void);
HTTPResponse api_echo(const HTTPRequest* request);

#endif // ROUTER_H
