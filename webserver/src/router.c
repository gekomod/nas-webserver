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
#include <errno.h>  // Dodaj tę linię
#include <unistd.h> // Dodaj dla write()
#include "profiler.h"
#include "logging.h"

#define MAX_CACHE_SIZE 100
#define MAX_MIDDLEWARES 10
#define MAX_ENDPOINTS 20
#define DEFAULT_MIME_TYPE "application/octet-stream"

static FileCache file_cache[MAX_CACHE_SIZE];
static MiddlewareFunc middlewares[MAX_MIDDLEWARES];
static ApiEndpoint api_endpoints[MAX_ENDPOINTS];
static int middleware_count = 0;
int endpoint_count = 0;
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
    
    if (strcasecmp(ext, "wasm") == 0) return "application/wasm";
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

HTTPResponse api_status(HTTPRequest* request) {
    (void)request;  // Oznaczamy jako nieużywany parametr
    
    HTTPResponse response = {0};
    response.status_code = 200;
    strcpy(response.content_type, "application/json");
    const char* content = "{\"status\":\"running\",\"version\":\"1.0\",\"endpoints\":[\"/api/status\",\"/api/echo\"]}";
    response.content = my_strdup(content);
    response.content_size = strlen(content);
    return response;
}

HTTPResponse api_echo(HTTPRequest* request) {
    HTTPResponse response = {0};
    response.status_code = 200;
    strcpy(response.content_type, "application/json");
    
    // Zabezpieczenie przed NULL w request
    const char* method = request && request->method ? request->method : "";
    const char* path = request && request->path ? request->path : "";
    const char* body = request && request->body ? request->body : "";

    // Obliczenie wymaganego rozmiaru bufora
    size_t needed = snprintf(NULL, 0, 
        "{\"method\":\"%s\",\"path\":\"%s\",\"body\":\"%.2000s\"}",
        method, path, body) + 1;

    // Alokacja pamięci
    response.content = malloc(needed);
    if (!response.content) {
        response.status_code = 500;
        response.content_size = 0;
        return response;
    }

    // Formatowanie odpowiedzi z ograniczeniem długości body
    snprintf(response.content, needed,
        "{\"method\":\"%s\",\"path\":\"%s\",\"body\":\"%.2000s\"}",
        method, path, body);
    
    response.content_size = needed - 1;
    enable_cors(&response);
    
    return response;
}

HTTPResponse handle_request(const HTTPRequest* request, const Config* config) {
    HTTPResponse response = {0};
    char decoded_path[1024] = {0};
    char file_path[2048] = {0};

        log_message(LOG_ACCESS, "Request: %s %s from %s", 
               request->method, request->path, 
               request->ssl ? "HTTPS" : "HTTP");

    if (strstr(request->path, "../") || strstr(request->path, "..\\")) {
        log_message(LOG_SECURITY, "Path traversal attempt detected: %s", request->path);
        return error_response(403, "Forbidden");
    }

    if (strlen(request->path) > 1024) {
        log_message(LOG_SECURITY, "Path too long: %s", request->path);
        return error_response(414, "URI Too Long");
    }
    
    // 1. Normalizacja ścieżki
    strncpy(decoded_path, request->path, sizeof(decoded_path)-1);
    url_decode(decoded_path);
    normalize_path(decoded_path);
    
    printf("DEBUG: Handling path: '%s'\n", decoded_path); // Log diagnostyczny

    // 2. Sprawdzenie endpointów API (najpierw!)
    if (strncmp(decoded_path, config->api_prefix, strlen(config->api_prefix)) == 0) {
        printf("DEBUG: This is an API request\n");
        
        for (int i = 0; i < endpoint_count; i++) {
            printf("DEBUG: Checking endpoint '%s'\n", api_endpoints[i].path);
            
            if (strcmp(decoded_path, api_endpoints[i].path) == 0) {
                printf("DEBUG: Found handler for '%s'\n", decoded_path);
                return api_endpoints[i].handler((HTTPRequest*)request);
            }
        }
        printf("ERROR: No handler for API path '%s'\n", decoded_path);
        return error_response(404, "Endpoint not found");
    }

    // 3. Obsługa plików statycznych (assets, static)
    if (strstr(decoded_path, "/assets/") == decoded_path || 
        strstr(decoded_path, "/static/") == decoded_path) {
        
        snprintf(file_path, sizeof(file_path), "%s%s", config->frontend_path, decoded_path);
        
        // Specjalna obsługa WASM
        if (strstr(file_path, ".wasm") != NULL) {
            return handle_wasm_file(file_path);
        }
        
        response.content = read_file_content(file_path, &response.content_size);
        if (response.content) {
            response.status_code = 200;
            const char* mime_type = get_mime_type(file_path);
            strcpy(response.content_type, mime_type ? mime_type : DEFAULT_MIME_TYPE);
            return response;
        }
        return error_response(404, "Static file not found");
    }

    // 4. Dla innych ścieżek z rozszerzeniem (np. .css, .js)
    if (strchr(decoded_path, '.') != NULL) {
        snprintf(file_path, sizeof(file_path), "%s%s", config->frontend_path, decoded_path);
        struct stat st;
        if (stat(file_path, &st) == 0 && S_ISREG(st.st_mode)) {
            response.content = read_file_content(file_path, &response.content_size);
            if (response.content) {
                response.status_code = 200;
                strcpy(response.content_type, get_mime_type(file_path));
                return response;
            }
        }
    }

    // 5. Domyślnie: index.html dla SPA
    snprintf(file_path, sizeof(file_path), "%s/index.html", config->frontend_path);
    response.content = read_file_content(file_path, &response.content_size);
    if (response.content) {
        response.status_code = 200;
        strcpy(response.content_type, "text/html");
        return response;
    }

    if (response.status_code >= 400) {
        log_message(LOG_ERROR, "Error %d for %s %s", 
                   response.status_code, request->method, request->path);
    }

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

    if (strcmp(response->content_type, "application/wasm") == 0) {
        snprintf(headers, sizeof(headers),
            "HTTP/1.1 %d OK\r\n"
            "Content-Type: application/wasm\r\n"
            "Content-Length: %zu\r\n"
            "Cross-Origin-Opener-Policy: same-origin\r\n"
            "Cross-Origin-Embedder-Policy: require-corp\r\n"
            "Cache-Control: no-store\r\n"
            "Connection: close\r\n\r\n",
            response->status_code,
            response->content_size);
    } else {
        snprintf(headers, sizeof(headers),
            "HTTP/1.1 %d %s\r\n"
            "Content-Type: %s\r\n"
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

HTTPResponse handle_wasm_file(const char* file_path) {
    FILE* file = fopen(file_path, "rb");
    if (!file) {
        return error_response(404, "WASM file not found");
    }

    fseek(file, 0, SEEK_END);
    size_t file_size = ftell(file);
    rewind(file);

    HTTPResponse response = {0};
    response.status_code = 200;
    strcpy(response.content_type, "application/wasm");
    response.is_binary = 1;
    response.skip_compression = 1; // Wyłącz kompresję dla WASM
    response.content = malloc(file_size);
    
    if (response.content) {
        size_t bytes_read = fread(response.content, 1, file_size, file);
        if (bytes_read != file_size) {
            free(response.content);
            fclose(file);
            return error_response(500, "Failed to read WASM file");
        }
        response.content_size = file_size;
        
        // Nagłówki wymagane dla WebAssembly
        add_header(&response, "Cross-Origin-Opener-Policy", "same-origin");
        add_header(&response, "Cross-Origin-Embedder-Policy", "require-corp");
        add_header(&response, "Cache-Control", "no-store");
    } else {
        fclose(file);
        return error_response(500, "Memory allocation failed");
    }
    
    fclose(file);
    return response;
}

HTTPResponse handle_wasm_request(const char* file_path) {
    FILE* file = fopen(file_path, "rb");
    if (!file) {
        return error_response(404, "WASM file not found");
    }

    fseek(file, 0, SEEK_END);
    size_t file_size = ftell(file);
    rewind(file);

    HTTPResponse response = {0};
    response.status_code = 200;
    strcpy(response.content_type, "application/wasm");
    response.is_binary = 1;
    response.skip_compression = 1;  // Disable compression for WASM
    response.content = malloc(file_size);
    
    if (response.content) {
        size_t bytes_read = fread(response.content, 1, file_size, file);
        if (bytes_read == file_size) {
            response.content_size = file_size;
            // Required security headers for WASM
            add_header(&response, "Cross-Origin-Opener-Policy", "same-origin");
            add_header(&response, "Cross-Origin-Embedder-Policy", "require-corp");
        } else {
            free(response.content);
            fclose(file);
            return error_response(500, "Error reading WASM file");
        }
    }
    
    fclose(file);
    return response;
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

void safe_write(int fd, const void* buf, size_t count) {
    ssize_t bytes_written;
    size_t total_written = 0;
    const char* ptr = buf;
    
    while (total_written < count) {
        bytes_written = write(fd, ptr + total_written, count - total_written);
        if (bytes_written < 0) {
            if (errno == EINTR) {
                continue;  // Przerwij jeśli sygnał przerwał zapis
            }
            perror("write failed");
            break;
        }
        total_written += bytes_written;
    }
}