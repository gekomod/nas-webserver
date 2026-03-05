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
#include "logging.h"
#include "../security/monitoring.h"

#define MAX_CACHE_SIZE 100
#define MAX_MIDDLEWARES 10
#define MAX_ENDPOINTS 50
#define DEFAULT_MIME_TYPE "application/octet-stream"
#define API_PREFIX "/api"

// Zmienne statyczne
static FileCache file_cache[MAX_CACHE_SIZE];
static MiddlewareFunc middlewares[MAX_MIDDLEWARES];
static ApiEndpoint api_endpoints[MAX_ENDPOINTS];
static int middleware_count = 0;
int endpoint_count = 0;
static int cache_initialized = 0;
time_t server_start_time = 0;

/* ========== FUNKCJE POMOCNICZE ========== */

int is_path_traversal(const char* path) {
    if (!path) return 1;
    
    int depth = 0;
    const char* ptr = path;
    
    while (*ptr) {
        if (strncmp(ptr, "../", 3) == 0) {
            depth--;
            ptr += 3;
        } else if (strncmp(ptr, "./", 2) == 0) {
            ptr += 2;
        } else if (strncmp(ptr, "//", 2) == 0) {
            ptr += 1;
        } else if (*ptr == '/') {
            depth++;
            ptr++;
        } else {
            ptr++;
        }
        
        if (depth < 0) return 1;
    }
    
    return 0;
}

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

/* Binary-safe memdup - używaj zamiast my_strdup dla plików binarnych/CSS/JS */
static char* memdup(const char* src, size_t size) {
    if (!src || size == 0) return NULL;
    char* dst = malloc(size);
    if (dst) memcpy(dst, src, size);
    return dst;
}

void init_cache() {
    if (!cache_initialized) {
        memset(file_cache, 0, sizeof(file_cache));
        cache_initialized = 1;
        printf("Cache initialized\n");
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
    printf("Cache freed\n");
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
        printf("Registering API endpoint: %s\n", path);
        api_endpoints[endpoint_count].path = my_strdup(path);
        api_endpoints[endpoint_count].handler = handler;
        endpoint_count++;
    } else {
        printf("ERROR: Cannot register endpoint %s - max limit reached\n", path);
    }
}

void init_api_routes() {
    printf("Initializing API routes...\n");
    
    // Zarejestruj wszystkie endpointy
    register_endpoint("/api/statuss", api_status);
    register_endpoint("/api/echo", api_echo);
    register_endpoint("/api/healths", api_health);
    register_endpoint("/api/heartbeat", api_heartbeat);
    register_endpoint("/api/ping", api_ping);
    register_endpoint("/api/auth/check", api_auth_check);
    register_endpoint("/api/system/boot-time", api_system_boot_time);
    register_endpoint("/api/system-health", api_system_health);
    
    printf("Registered %d API endpoints:\n", endpoint_count);
    for (int i = 0; i < endpoint_count; i++) {
        printf("  - %s\n", api_endpoints[i].path);
    }
}

/* ========== FUNKCJE GŁÓWNE ========== */

HTTPRequest parse_request(const char* raw_request) {
    HTTPRequest req = {0};
    if (!raw_request) return req;
    
    char* line = strtok((char*)raw_request, "\n");
    
    if (line) {
        sscanf(line, "%9s %255s %31s", req.method, req.path, req.protocol);
    }
    
    char* headers_end = strstr(raw_request, "\r\n\r\n");
    if (headers_end) {
        size_t headers_len = headers_end - raw_request;
        if (headers_len < sizeof(req.headers)) {
            strncpy(req.headers, raw_request, headers_len);
            req.headers[headers_len] = '\0';
        }
    }
    
    char* body_start = strstr(raw_request, "\r\n\r\n");
    if (body_start) {
        body_start += 4;
        strncpy(req.body, body_start, sizeof(req.body)-1);
        req.body[sizeof(req.body)-1] = '\0';
    }
    
    return req;
}

char* read_file_content(const char* path, size_t* out_size) {
    printf("DEBUG: Reading file: %s\n", path);
    
    FileCache* cached = get_cached_file(path);
    if (cached) {
        if (out_size) *out_size = cached->size;
        printf("DEBUG: Serving from cache: %s (%zu bytes)\n", path, cached->size);
        return memdup(cached->content, cached->size);  /* binary-safe, nie uciął CSS/JS */
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
    if (!path) return;
    
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
    if (!str) return;
    
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
    if (!filename) return DEFAULT_MIME_TYPE;
    
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
    if (!response || !name || !value) return;
    
    char header[1024];
    int needed = snprintf(header, sizeof(header), "%s: %s\r\n", name, value);
    
    if (needed > 0 && needed < (int)sizeof(header)) {
        // Sprawdź czy mamy miejsce w buforze headers
        size_t current_len = strlen(response->headers);
        size_t available = sizeof(response->headers) - current_len - 1;
        
        if ((size_t)needed < available) {
            strcat(response->headers, header);
        }
    }
}

void enable_cors(HTTPResponse* response) {
    add_header(response, "Access-Control-Allow-Origin", "*");
    add_header(response, "Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE");
    add_header(response, "Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With");
    add_header(response, "Access-Control-Allow-Credentials", "true");
    add_header(response, "Access-Control-Max-Age", "86400");
}

/* ========== ENDPOINTY API ========== */

HTTPResponse api_status(HTTPRequest* request) {
    (void)request;
    
    HTTPResponse response = {0};
    response.status_code = 200;
    strcpy(response.content_type, "application/json");
    
    const char* content = "{\"status\":\"running\",\"version\":\"1.0\",\"timestamp\":";
    char timestamp[20];
    time_t now = time(NULL);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));
    
    // Zwiększ rozmiar bufora - teraz 512 bajtów zamiast 117
    char* full_content = malloc(512);
    if (!full_content) {
        return error_response(500, "Memory allocation failed");
    }
    
    snprintf(full_content, 512, 
             "%s\"%s\",\"endpoints\":[\"/api/status\",\"/api/echo\",\"/api/health\","
             "\"/api/heartbeat\",\"/api/ping\",\"/api/auth/check\"]}", 
             content, timestamp);
    
    response.content = full_content;
    response.content_size = strlen(full_content);
    
    enable_cors(&response);
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
        "{\"method\":\"%s\",\"path\":\"%s\",\"body\":\"%.2000s\",\"timestamp\":%ld}",
        method, path, body, (long)time(NULL)) + 1;

    // Alokacja pamięci
    response.content = malloc(needed);
    if (!response.content) {
        response.status_code = 500;
        response.content_size = 0;
        return response;
    }

    // Formatowanie odpowiedzi z ograniczeniem długości body
    snprintf(response.content, needed,
        "{\"method\":\"%s\",\"path\":\"%s\",\"body\":\"%.2000s\",\"timestamp\":%ld}",
        method, path, body, (long)time(NULL));
    
    response.content_size = needed - 1;
    enable_cors(&response);
    
    return response;
}

HTTPResponse api_health(HTTPRequest* request) {
    (void)request;
    
    HTTPResponse response = {0};
    response.status_code = 200;
    strcpy(response.content_type, "application/json");
    
    time_t now = time(NULL);
    struct tm* tm_info = localtime(&now);
    char timestamp[20];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    
    // Oblicz uptime
    long uptime_seconds = server_start_time > 0 ? (now - server_start_time) : 0;
    
    // Stwórz JSON response
    char* json_response = malloc(512);
    if (!json_response) {
        return error_response(500, "Memory allocation failed");
    }
    
    snprintf(json_response, 512, 
             "{\"status\":\"healthy\",\"healthy\":true,\"timestamp\":\"%s\",\"uptime\":%ld,\"version\":\"1.0\"}",
             timestamp, uptime_seconds);
    
    response.content = json_response;
    response.content_size = strlen(json_response);
    
    // enable_cors(&response);
    return response;
}

HTTPResponse api_heartbeat(HTTPRequest* request) {
    HTTPResponse response = {0};
    response.status_code = 200;
    strcpy(response.content_type, "application/json");
    
    // Pobierz timestamp z body jeśli istnieje
    long client_timestamp = 0;
    if (request && request->body && strlen(request->body) > 0) {
        // Spróbuj parsować JSON
        char* timestamp_str = strstr(request->body, "\"timestamp\":");
        if (timestamp_str) {
            timestamp_str += 12; // Przesuń za "\"timestamp\":"
            client_timestamp = strtol(timestamp_str, NULL, 10);
        }
    }
    
    char* content = malloc(200);
    if (!content) {
        return error_response(500, "Memory allocation failed");
    }
    
    time_t now = time(NULL);
    snprintf(content, 200, 
             "{\"status\":\"ok\",\"server_timestamp\":%ld,\"client_timestamp\":%ld,\"uptime\":%ld}",
             (long)now, client_timestamp, (long)(now - server_start_time));
    
    response.content = content;
    response.content_size = strlen(content);
    
    enable_cors(&response);
    return response;
}

HTTPResponse api_auth_check(HTTPRequest* request) {
    (void)request;
    
    HTTPResponse response = {0};
    response.status_code = 200;
    strcpy(response.content_type, "application/json");
    
    const char* content = "{\"authenticated\":true,\"user\":\"admin\",\"permissions\":[\"read\",\"write\",\"admin\"]}";
    response.content = my_strdup(content);
    response.content_size = strlen(content);
    
    enable_cors(&response);
    return response;
}

HTTPResponse api_ping(HTTPRequest* request) {
    (void)request;
    
    HTTPResponse response = {0};
    response.status_code = 200;
    strcpy(response.content_type, "application/json");
    
    const char* content = "{\"pong\":true,\"timestamp\":";
    char* full_content = malloc(strlen(content) + 50);
    if (!full_content) {
        return error_response(500, "Memory allocation failed");
    }
    
    sprintf(full_content, "%s%ld}", content, (long)time(NULL));
    response.content = full_content;
    response.content_size = strlen(full_content);
    
    return response;
}

HTTPResponse api_system_boot_time(HTTPRequest* request) {
    (void)request;
    
    HTTPResponse response = {0};
    response.status_code = 200;
    strcpy(response.content_type, "application/json");
    
    // Symulowany boot time (w praktyce pobierany z systemu)
    static long boot_time = 0;
    if (boot_time == 0) {
        boot_time = time(NULL) - (rand() % 86400); // Losowy boot time w ciągu ostatnich 24h
    }
    
    char* content = malloc(100);
    if (!content) {
        return error_response(500, "Memory allocation failed");
    }
    
    snprintf(content, 100, "{\"bootTime\":%ld}", boot_time);
    response.content = content;
    response.content_size = strlen(content);
    
    enable_cors(&response);
    return response;
}

HTTPResponse api_system_health(HTTPRequest* request) {
    (void)request;
    
    HTTPResponse response = {0};
    response.status_code = 200;
    strcpy(response.content_type, "application/json");
    
    const char* content = "true"; // Vue oczekuje true/false
    response.content = my_strdup(content);
    response.content_size = strlen(content);
    
    return response;
}

/* ========== GŁÓWNA FUNKCJA OBSŁUGI ŻĄDAŃ ========== */

HTTPResponse handle_request(const HTTPRequest* request, const Config* config) {
    HTTPResponse response = {0};
    char decoded_path[1024] = {0};
    char file_path[2048] = {0};
    
    if (!request) {
        return error_response(400, "Invalid request");
    }
    
    printf("\n=== NEW REQUEST ===\n");
    printf("Method: %s\n", request->method);
    printf("Path: %s\n", request->path);
    printf("Protocol: %s\n", request->protocol);
    
    // 0. Obsługa OPTIONS (CORS preflight)
    if (strcmp(request->method, "OPTIONS") == 0) {
        printf("DEBUG: Handling OPTIONS request for CORS preflight\n");
        response.status_code = 200;
        enable_cors(&response);
        add_header(&response, "Content-Length", "0");
        return response;
    }
    
    // 1. Normalizacja ścieżki
    strncpy(decoded_path, request->path, sizeof(decoded_path)-1);
    decoded_path[sizeof(decoded_path)-1] = '\0';
    
    url_decode(decoded_path);
    normalize_path(decoded_path);
    
    printf("DEBUG: Decoded path: '%s'\n", decoded_path);

    // 2. Bezpieczeństwo
    if (is_path_traversal(decoded_path)) {
        log_message(LOG_SECURITY, "Path traversal attempt detected: %s", decoded_path);
        return error_response(403, "Access denied");
    }

    if (detect_sql_injection(request->path) || 
        detect_sql_injection(request->body)) {
        log_security_event(SECURITY_HIGH, "SQL_INJECTION_ATTEMPT", 
                          "unknown", request->path, 0, 400);
        return error_response(400, "Invalid request");
    }
    
    if (detect_xss_attempt(request->path) || 
        detect_xss_attempt(request->body)) {
        log_security_event(SECURITY_MEDIUM, "XSS_ATTEMPT", 
                          "unknown", request->path, 0, 400);
        return error_response(400, "Invalid request");
    }
    
    if (detect_path_traversal(request->path)) {
        log_security_event(SECURITY_HIGH, "PATH_TRAVERSAL_ATTEMPT", 
                          "unknown", request->path, 0, 403);
        return error_response(403, "Access denied");
    }
    
    // 3. Sprawdzenie endpointów API (najpierw!)
    if (strncmp(decoded_path, API_PREFIX, strlen(API_PREFIX)) == 0) {
        printf("DEBUG: This is an API request\n");
        printf("DEBUG: Looking for handler among %d registered endpoints\n", endpoint_count);
        
        for (int i = 0; i < endpoint_count; i++) {
            printf("DEBUG: Checking endpoint '%s' against '%s'\n", 
                   api_endpoints[i].path, decoded_path);
            
            if (api_endpoints[i].path && strcmp(decoded_path, api_endpoints[i].path) == 0) {
                printf("DEBUG: Found handler for '%s'\n", decoded_path);
                return api_endpoints[i].handler((HTTPRequest*)request);
            }
        }
        
        printf("ERROR: No handler for API path '%s'\n", decoded_path);
        printf("DEBUG: Available endpoints:\n");
        for (int i = 0; i < endpoint_count; i++) {
            printf("  - %s\n", api_endpoints[i].path);
        }
        
        return error_response(404, "Endpoint not found");
    }

    // 4. Obsługa plików statycznych (assets, static)
    if (strstr(decoded_path, "/assets/") == decoded_path || 
        strstr(decoded_path, "/static/") == decoded_path) {
        
        snprintf(file_path, sizeof(file_path), "%s%s", config->frontend_path, decoded_path);
        
        printf("DEBUG: Static file request: %s\n", file_path);
        
        // Specjalna obsługa WASM
        if (strstr(file_path, ".wasm") != NULL) {
            return handle_wasm_file(file_path);
        }
        
        response.content = read_file_content(file_path, &response.content_size);
        if (response.content) {
            response.status_code = 200;
            const char* mime_type = get_mime_type(file_path);
            strcpy(response.content_type, mime_type ? mime_type : DEFAULT_MIME_TYPE);

            /* Vite buduje assety z hashem w nazwie pliku - możemy cache'ować rok */
            add_header(&response, "Cache-Control", "public, max-age=31536000, immutable");

            /* Nagłówki CORS potrzebne dla modulepreload/crossorigin */
            add_header(&response, "Access-Control-Allow-Origin", "*");
            add_header(&response, "Vary", "Accept-Encoding");

            return response;
        }

        /* Plik nie istnieje - zwróć czytelny błąd zamiast 404 bez treści */
        log_message(LOG_ERROR, "Static asset not found: %s", file_path);
        return error_response(404, "Static file not found");
    }

    // 5. Dla innych ścieżek z rozszerzeniem (np. .css, .js)
    if (strchr(decoded_path, '.') != NULL) {
        snprintf(file_path, sizeof(file_path), "%s%s", config->frontend_path, decoded_path);
        struct stat st;
        if (stat(file_path, &st) == 0 && S_ISREG(st.st_mode)) {
            printf("DEBUG: File request with extension: %s\n", file_path);
            response.content = read_file_content(file_path, &response.content_size);
            if (response.content) {
                response.status_code = 200;
                strcpy(response.content_type, get_mime_type(file_path));
                return response;
            }
        }
    }

    // 6. Domyślnie: index.html dla SPA
    snprintf(file_path, sizeof(file_path), "%s/index.html", config->frontend_path);
    printf("DEBUG: Fallback to SPA index: %s\n", file_path);
    
    response.content = read_file_content(file_path, &response.content_size);
    if (response.content) {
        response.status_code = 200;
        strcpy(response.content_type, "text/html");
        return response;
    }

    printf("ERROR: File not found: %s\n", file_path);
    return error_response(404, "File not found");
}

char* build_response(const HTTPResponse* response, size_t* response_size, const Config* config) {
    if (!response || !response->content) {
        if (response_size) *response_size = 0;
        return NULL;
    }

    const char* status_msg = "OK";
    switch (response->status_code) {
        case 200: status_msg = "OK"; break;
        case 400: status_msg = "Bad Request"; break;
        case 403: status_msg = "Forbidden"; break;
        case 404: status_msg = "Not Found"; break;
        case 408: status_msg = "Request Timeout"; break;
        case 500: status_msg = "Internal Server Error"; break;
        case 503: status_msg = "Service Unavailable"; break;
        default: status_msg = "Unknown"; break;
    }

    // Utwórz kopię response do dodania nagłówków
    HTTPResponse temp_response = *response;
    add_security_headers(&temp_response, config);

    // Dodaj podstawowe nagłówki jeśli nie istnieją
    if (strstr(temp_response.headers, "Content-Type:") == NULL) {
        add_header(&temp_response, "Content-Type", temp_response.content_type);
    }
    
    // ZAWSZE dodaj Content-Length
    char content_length[32];
    snprintf(content_length, sizeof(content_length), "%zu", temp_response.content_size);
    add_header(&temp_response, "Content-Length", content_length);
    
    // Dla połączeń HTTP/1.1, dodaj Connection: close lub keep-alive
    add_header(&temp_response, "Connection", "close");

    // Zbuduj nagłówki
    char headers[8192] = {0};   /* zwiększono - musi pomieścić wszystkie nagłówki z temp_response */
    snprintf(headers, sizeof(headers),
        "HTTP/1.1 %d %s\r\n"
        "%s"
        "\r\n",
        temp_response.status_code,
        status_msg,
        temp_response.headers);

    size_t header_len = strlen(headers);
    size_t total_size = header_len + temp_response.content_size;
    
    char* http_response = malloc(total_size);
    if (!http_response) {
        if (response_size) *response_size = 0;
        return NULL;
    }

    memcpy(http_response, headers, header_len);
    if (temp_response.content_size > 0) {
        memcpy(http_response + header_len, temp_response.content, temp_response.content_size);
    }

    if (response_size) {
        *response_size = total_size;
    }

    return http_response;
}

HTTPResponse handle_wasm_file(const char* file_path) {
    FILE* file = fopen(file_path, "rb");
    if (!file) {
        printf("ERROR: WASM file not found: %s\n", file_path);
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
        add_header(&response, "Accept-Ranges", "bytes");
    } else {
        fclose(file);
        return error_response(500, "Memory allocation failed");
    }
    
    fclose(file);
    printf("DEBUG: Served WASM file: %s (%zu bytes)\n", file_path, file_size);
    return response;
}

void add_security_headers(HTTPResponse* response, const Config* config) {
    // HSTS - tylko dla HTTPS
    if (config->enable_https && config->hsts_enabled) {
        char hsts_header[50];
        snprintf(hsts_header, sizeof(hsts_header), "max-age=%d", config->hsts_max_age);
        add_header(response, "Strict-Transport-Security", hsts_header);
    }
    
    // XSS Protection
    add_header(response, "X-Content-Type-Options", "nosniff");
    add_header(response, "X-Frame-Options", "DENY");
    add_header(response, "X-XSS-Protection", "1; mode=block");
    
    // NIE DODAWAJ Content-Security-Policy na razie
    // add_header(response, "Content-Security-Policy", "...");
    
    // Referrer Policy
    add_header(response, "Referrer-Policy", "strict-origin-when-cross-origin");
    
    // Cache Control dla API
    if (strstr(response->content_type, "application/json") != NULL) {
        add_header(response, "Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
        add_header(response, "Pragma", "no-cache");
        add_header(response, "Expires", "0");
    }
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
