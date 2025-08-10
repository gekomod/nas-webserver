#ifndef ROUTER_H
#define ROUTER_H

#include "config.h"
#include <strings.h>
#include <stdlib.h>
#include <openssl/ssl.h>

typedef struct HTTPResponse HTTPResponse;
typedef struct HTTPRequest HTTPRequest;

typedef struct HTTPRequest {
    char method[10];
    char path[256];
    char protocol[32];
    char headers[1024];
    char body[4096];
    SSL* ssl;
} HTTPRequest;

typedef struct HTTPResponse {
    int status_code;
    char content_type[64];
    char* content;
    size_t content_size;
    unsigned char is_binary;
    unsigned char is_wasm;
    unsigned char skip_compression;
    char headers[1024];
} HTTPResponse;

typedef HTTPResponse (*MiddlewareFunc)(HTTPRequest*);
typedef HTTPResponse (*ApiHandler)(HTTPRequest*);


typedef struct {
    char* path;
    ApiHandler handler;
} ApiEndpoint;

typedef struct {
    char* path;
    char* content;
    size_t size;
    time_t last_modified;
} FileCache;

void normalize_path(char* path);
const char* get_mime_type(const char* filename);
char* my_strdup(const char* s);
char* compress_gzip(const char* data, size_t size, size_t* compressed_size);
void add_header(HTTPResponse* response, const char* name, const char* value);
void enable_cors(HTTPResponse* response);

HTTPRequest parse_request(const char* raw_request);
HTTPResponse handle_request(const HTTPRequest* request, const Config* config);
HTTPResponse handle_wasm_file(const char* file_path);
char* build_response(const HTTPResponse* response, size_t* response_size, const Config* config);
char* read_file_content(const char* path, size_t* out_size);
void url_decode(char* str);
void free_response(HTTPResponse* response);
void register_middleware(MiddlewareFunc func);
void register_endpoint(const char* path, ApiHandler handler);
void init_cache();
void free_cache();
extern int endpoint_count;

HTTPResponse api_status(HTTPRequest* request); 
HTTPResponse api_echo(HTTPRequest* request);

#endif
