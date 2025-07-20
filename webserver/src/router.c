#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <ctype.h>
#include <strings.h>
#include <zlib.h>
#include <openssl/ssl.h>
#include "router.h"
#include "error.h"
#include "profiler.h"

#define MAX_CACHE_SIZE 100
#define MAX_MIDDLEWARES 10
#define MAX_ENDPOINTS 20
#define DEFAULT_MIME_TYPE "application/octet-stream"

static FileCache file_cache[MAX_CACHE_SIZE];
static MiddlewareFunc middlewares[MAX_MIDDLEWARES];
static ApiEndpoint api_endpoints[MAX_ENDPOINTS];
static int middleware_count = 0;
static int endpoint_count = 0;
static int cache_initialized = 0;

/* ========== FUNKCJE POMOCNICZE ========== */

int hex_to_int(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return 0;
}

char* my_strdup(const char* s) {
    if (!s) return NULL;
    size_t len = strlen(s) + 1;
    char* new = malloc(len);
    if (new) memcpy(new, s, len);
    return new;
}

void init_cache() {
    if (!cache_initialized) {
        memset(file_cache, 0, sizeof(file_cache));
        cache_initialized = 1;
    }
}

void free_cache() {
    for (int i = 0; i < MAX_CACHE_SIZE; i++) {
        if (file_cache[i].path) {
            free(file_cache[i].path);
            if (file_cache[i].content) {
                free(file_cache[i].content);
            }
        }
    }
    cache_initialized = 0;
}

FileCache* get_cached_file(const char* path) {
    if (!cache_initialized) return NULL;
    
    struct stat st;
    if (stat(path, &st) != 0) return NULL;
    
    for (int i = 0; i < MAX_CACHE_SIZE; i++) {
        if (file_cache[i].path && strcmp(file_cache[i].path, path) == 0) {
            if (file_cache[i].last_modified >= st.st_mtime) {
                return &file_cache[i];
            }
            break;
        }
    }
    return NULL;
}

void cache_file(const char* path, const char* content, size_t size) {
    if (!cache_initialized) return;
    
    int slot = 0;
    time_t oldest = time(NULL);
    for (int i = 0; i < MAX_CACHE_SIZE; i++) {
        if (!file_cache[i].path) {
            slot = i;
            break;
        }
        if (file_cache[i].last_modified < oldest) {
            oldest = file_cache[i].last_modified;
            slot = i;
        }
    }
    
    if (file_cache[slot].path) {
        free(file_cache[slot].path);
        if (file_cache[slot].content) {
            free(file_cache[slot].content);
        }
    }
    
    file_cache[slot].path = my_strdup(path);
    file_cache[slot].content = malloc(size);
    if (file_cache[slot].content) {
        memcpy(file_cache[slot].content, content, size);
    }
    file_cache[slot].size = size;
    file_cache[slot].last_modified = time(NULL);
}

void register_middleware(MiddlewareFunc func) {
    if (middleware_count < MAX_MIDDLEWARES) {
        middlewares[middleware_count++] = func;
    }
}

void register_endpoint(const char* path, ApiHandler handler) {
    if (endpoint_count < MAX_ENDPOINTS) {
        api_endpoints[endpoint_count].path = my_strdup(path);
        api_endpoints[endpoint_count].handler = handler;
        endpoint_count++;
    }
}

/* ========== FUNKCJE GŁÓWNE ========== */

HTTPRequest parse_request(const char* raw_request) {
    HTTPRequest req = {0};
    char* line = strtok((char*)raw_request, "\n");
    
    if (line) {
        sscanf(line, "%9s %255s %31s", req.method, req.path, req.protocol);
    }
    
    char* headers_end = strstr(raw_request, "\r\n\r\n");
    if (headers_end) {
        size_t headers_len = headers_end - raw_request;
        strncpy(req.headers, raw_request, headers_len < sizeof(req.headers) ? headers_len : sizeof(req.headers)-1);
    }
    
    char* body_start = strstr(raw_request, "\r\n\r\n");
    if (body_start) {
        body_start += 4;
        strncpy(req.body, body_start, sizeof(req.body)-1);
    }
    
    return req;
}

char* read_file_content(const char* path, size_t* out_size) {
    printf("DEBUG: Reading file: %s\n", path);
    
    FileCache* cached = get_cached_file(path);
    if (cached) {
        if (out_size) *out_size = cached->size;
        printf("DEBUG: Serving from cache: %s (%zu bytes)\n", path, cached->size);
        return my_strdup(cached->content);
    }
    
    FILE* file = fopen(path, "rb");
    if (!file) {
        perror("fopen failed");
        return NULL;
    }

    if (fseek(file, 0, SEEK_END) != 0) {
        perror("fseek failed");
        fclose(file);
        return NULL;
    }
    
    long length = ftell(file);
    if (length < 0) {
        perror("ftell failed");
        fclose(file);
        return NULL;
    }
    
    rewind(file);

    char* buffer = malloc(length + 1);
    if (!buffer) {
        perror("malloc failed");
        fclose(file);
        return NULL;
    }

    size_t read = fread(buffer, 1, length, file);
    if (ferror(file)) {
        perror("fread failed");
        free(buffer);
        fclose(file);
        return NULL;
    }

    fclose(file);

    if (out_size) {
        *out_size = read;
    }
    
    cache_file(path, buffer, read);
    printf("DEBUG: Read %zu bytes from %s\n", read, path);
    
    return buffer;
}

void normalize_path(char* path) {
    char* src = path;
    char* dst = path;
    
    while (*src) {
        if (*src == '/' && *(src+1) == '/') {
            src++;
            continue;
        }
        *dst++ = *src++;
    }
    *dst = '\0';
}

void url_decode(char* str) {
    char* src = str;
    char* dst = str;
    
    while (*src) {
        if (*src == '%' && isxdigit(src[1]) && isxdigit(src[2])) {
            *dst = (char)((hex_to_int(src[1]) << 4) | hex_to_int(src[2]));
            src += 3;
        } else {
            *dst = *src++;
        }
        dst++;
    }
    *dst = '\0';
}

const char* get_mime_type(const char* filename) {
    const char* ext = strrchr(filename, '.');
    if (!ext) return DEFAULT_MIME_TYPE;
    
    ext++;
    
    if (strcasecmp(ext, "html") == 0) return "text/html";
    if (strcasecmp(ext, "js") == 0) return "application/javascript";
    if (strcasecmp(ext, "css") == 0) return "text/css";
    if (strcasecmp(ext, "json") == 0) return "application/json";
    if (strcasecmp(ext, "png") == 0) return "image/png";
    if (strcasecmp(ext, "jpg") == 0 || strcasecmp(ext, "jpeg") == 0) return "image/jpeg";
    if (strcasecmp(ext, "gif") == 0) return "image/gif";
    if (strcasecmp(ext, "svg") == 0) return "image/svg+xml";
    if (strcasecmp(ext, "ico") == 0) return "image/x-icon";
    if (strcasecmp(ext, "woff") == 0) return "font/woff";
    if (strcasecmp(ext, "woff2") == 0) return "font/woff2";
    if (strcasecmp(ext, "ttf") == 0) return "font/ttf";
    if (strcasecmp(ext, "wasm") == 0) return "application/wasm";
    if (strcasecmp(ext, "txt") == 0) return "text/plain";
    if (strcasecmp(ext, "xml") == 0) return "application/xml";
    
    return DEFAULT_MIME_TYPE;
}

char* compress_gzip(const char* data, size_t size, size_t* compressed_size) {
    z_stream zs;
    memset(&zs, 0, sizeof(zs));

    if (deflateInit2(&zs, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15 | 16, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
        return NULL;
    }

    zs.next_in = (Bytef*)data;
    zs.avail_in = size;

    size_t max_size = deflateBound(&zs, size);
    char* out = malloc(max_size);
    if (!out) return NULL;

    zs.next_out = (Bytef*)out;
    zs.avail_out = max_size;

    if (deflate(&zs, Z_FINISH) != Z_STREAM_END) {
        free(out);
        deflateEnd(&zs);
        return NULL;
    }

    *compressed_size = zs.total_out;
    deflateEnd(&zs);
    return out;
}

void add_header(HTTPResponse* response, const char* name, const char* value) {
    char header[256];
    snprintf(header, sizeof(header), "%s: %s\r\n", name, value);
    strncat(response->headers, header, sizeof(response->headers) - strlen(response->headers) - 1);
}

void enable_cors(HTTPResponse* response) {
    add_header(response, "Access-Control-Allow-Origin", "*");
    add_header(response, "Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    add_header(response, "Access-Control-Allow-Headers", "Content-Type");
}

HTTPResponse api_status(void) {
    HTTPResponse response = {0};
    response.status_code = 200;
    strcpy(response.content_type, "application/json");
    const char* content = "{\"status\":\"running\",\"version\":\"1.0\",\"endpoints\":[\"/api/status\",\"/api/echo\"]}";
    response.content = my_strdup(content);
    response.content_size = strlen(content);
    enable_cors(&response);
    return response;
}

HTTPResponse api_echo(const HTTPRequest* request) {
    HTTPResponse response = {0};
    response.status_code = 200;
    strcpy(response.content_type, "application/json");
    
    size_t needed = snprintf(NULL, 0, "{\"method\":\"%s\",\"path\":\"%s\",\"body\":\"%s\"}",
                           request->method, request->path, request->body) + 1;
    response.content = malloc(needed);
    if (response.content) {
        snprintf(response.content, needed, "{\"method\":\"%s\",\"path\":\"%s\",\"body\":\"%s\"}",
                request->method, request->path, request->body);
        response.content_size = needed - 1;
    } else {
        response.status_code = 500;
        response.content_size = 0;
    }
    
    enable_cors(&response);
    return response;
}

HTTPResponse handle_request(const HTTPRequest* request, const Config* config) {
    HTTPResponse response = {0};
    response.content = NULL;
    response.content_size = 0;
    response.is_binary = 0;
    response.is_wasm = 0;
    response.skip_compression = 0;
    response.headers[0] = '\0';

    printf("DEBUG: Handling request for path: %s\n", request->path);

    for (int i = 0; i < middleware_count; i++) {
        HTTPResponse middleware_res = middlewares[i]((HTTPRequest*)request);
        if (middleware_res.status_code != 200) {
            return middleware_res;
        }
    }

    char decoded_path[1024] = {0};
    char file_path[2048] = {0};

    strncpy(decoded_path, request->path, sizeof(decoded_path)-1);
    url_decode(decoded_path);
    normalize_path(decoded_path);

    printf("DEBUG: Decoded path: %s\n", decoded_path);

    if (strstr(decoded_path, config->api_prefix) == decoded_path) {
        for (int i = 0; i < endpoint_count; i++) {
            if (strcmp(decoded_path, api_endpoints[i].path) == 0) {
                printf("DEBUG: Calling API endpoint: %s\n", decoded_path);
                return api_endpoints[i].handler((HTTPRequest*)request);
            }
        }
        printf("DEBUG: API endpoint not found: %s\n", decoded_path);
        return error_response(404, "Endpoint not found");
    }

    if (strstr(decoded_path, "/assets/") == decoded_path || 
        strstr(decoded_path, "/static/") == decoded_path) {

        snprintf(file_path, sizeof(file_path), "%s%s", config->frontend_path, decoded_path);
        printf("DEBUG: Serving static file: %s\n", file_path);
        
        response.content = read_file_content(file_path, &response.content_size);
        
        if (response.content) {
            response.status_code = 200;
            const char* mime_type = get_mime_type(file_path);
            strcpy(response.content_type, mime_type ? mime_type : DEFAULT_MIME_TYPE);

            if (strstr(file_path, ".wasm") != NULL) {
                strcpy(response.content_type, "application/wasm");
                response.is_binary = 1;
                response.is_wasm = 1;
                response.skip_compression = 1;
                add_header(&response, "Access-Control-Allow-Origin", "*");
                add_header(&response, "Cross-Origin-Opener-Policy", "same-origin");
                add_header(&response, "Cross-Origin-Embedder-Policy", "require-corp");
            } else if (strstr(file_path, ".gz") || strstr(file_path, ".br") || 
                     strstr(file_path, ".png") || strstr(file_path, ".jpg") || 
                     strstr(file_path, ".webp")) {
                response.skip_compression = 1;
            }

            printf("DEBUG: Sending file: %s (%zu bytes, type: %s)\n", 
                  file_path, response.content_size, response.content_type);
            return response;
        } else {
            printf("ERROR: Failed to read file: %s\n", file_path);
            return error_response(404, "Static file not found");
        }
    }

    struct stat st;
    int file_exists = 0;

    if (strchr(decoded_path, '.') != NULL) {
        snprintf(file_path, sizeof(file_path), "%s%s", config->frontend_path, decoded_path);
        file_exists = (stat(file_path, &st) == 0 && S_ISREG(st.st_mode));
        
        if (file_exists) {
            printf("DEBUG: Serving specific file: %s\n", file_path);
            response.content = read_file_content(file_path, &response.content_size);
            if (response.content) {
                response.status_code = 200;
                const char* mime_type = get_mime_type(file_path);
                strcpy(response.content_type, mime_type ? mime_type : DEFAULT_MIME_TYPE);
                return response;
            } else {
                printf("ERROR: Failed to read file: %s\n", file_path);
                return error_response(500, "Internal server error while reading file");
            }
        }
    }

    if (strchr(decoded_path, '.') == NULL) {
        snprintf(file_path, sizeof(file_path), "%s/index.html", config->frontend_path);
        printf("DEBUG: Serving index.html: %s\n", file_path);
        response.content = read_file_content(file_path, &response.content_size);
        
        if (response.content) {
            response.status_code = 200;
            strcpy(response.content_type, "text/html");
            return response;
        }
    }

    printf("DEBUG: File not found: %s\n", decoded_path);
    return error_response(404, "File not found");
}

char* build_response(const HTTPResponse* response, size_t* response_size, const Config* config) {
    (void)config; // Wyciszenie warningu o nieużywanym parametrze
    
    if (!response || !response->content) {
        if (response_size) *response_size = 0;
        return NULL;
    }

    const char* status_msg = "OK";
    switch (response->status_code) {
        case 200: status_msg = "OK"; break;
        case 404: status_msg = "Not Found"; break;
        case 500: status_msg = "Internal Server Error"; break;
        default: status_msg = "Unknown"; break;
    }

    printf("DEBUG: Building response for status %d, type %s, size %zu\n",
          response->status_code, response->content_type, response->content_size);

    char headers[2048] = {0};
    
    if (response->is_wasm) {
        snprintf(headers, sizeof(headers),
            "HTTP/1.1 %d %s\r\n"
            "Content-Type: application/wasm\r\n"
            "Content-Length: %zu\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "Cross-Origin-Opener-Policy: same-origin\r\n"
            "Cross-Origin-Embedder-Policy: require-corp\r\n"
            "Connection: close\r\n"
            "\r\n",
            response->status_code,
            status_msg,
            response->content_size);
    } else {
        snprintf(headers, sizeof(headers),
            "HTTP/1.1 %d %s\r\n"
            "Content-Type: %s; charset=utf-8\r\n"
            "Content-Length: %zu\r\n"
            "%s"
            "Connection: close\r\n"
            "\r\n",
            response->status_code,
            status_msg,
            response->content_type,
            response->content_size,
            response->headers);
    }

    size_t header_len = strlen(headers);
    size_t total_size = header_len + response->content_size;
    
    printf("DEBUG: Response headers (%zu bytes):\n%.*s\n", header_len, (int)header_len, headers);
    printf("DEBUG: First 100 bytes of content: %.*s\n",
          (int)(response->content_size > 100 ? 100 : response->content_size),
          response->content);

    char* http_response = malloc(total_size);
    if (!http_response) {
        perror("malloc failed in build_response");
        if (response_size) *response_size = 0;
        return NULL;
    }

    memcpy(http_response, headers, header_len);
    memcpy(http_response + header_len, response->content, response->content_size);

    if (response_size) {
        *response_size = total_size;
    }

    return http_response;
}

void free_response(HTTPResponse* response) {
    if (response) {
        if (response->content) {
            free(response->content);
            response->content = NULL;
        }
        response->content_size = 0;
    }
}
