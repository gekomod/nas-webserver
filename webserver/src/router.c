#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <ctype.h>
#include <strings.h>
#include "router.h"

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L // For strdup
#endif

#include <string.h> // Make sure this is included

// Funkcja pomocnicza do konwersji hex
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
    if (new) {
        memcpy(new, s, len);
    }
    return new;
}

// Parsowanie surowego żądania HTTP
HTTPRequest parse_request(const char* raw_request) {
    HTTPRequest req = {0};
    char* line = strtok((char*)raw_request, "\n");
    
    if (line) {
        sscanf(line, "%9s %255s %31s", req.method, req.path, req.protocol);
    }
    
    // Nagłówki
    char* headers_end = strstr(raw_request, "\r\n\r\n");
    if (headers_end) {
        size_t headers_len = headers_end - raw_request;
        strncpy(req.headers, raw_request, headers_len < sizeof(req.headers) ? headers_len : sizeof(req.headers)-1);
    }
    
    // Body (dla POST)
    char* body_start = strstr(raw_request, "\r\n\r\n");
    if (body_start) {
        body_start += 4;
        strncpy(req.body, body_start, sizeof(req.body)-1);
    }
    
    return req;
}

// Czytanie zawartości pliku (usunięto nieużywany base_path)
char* read_file_content(const char* path, size_t* out_size) {
    FILE* file = fopen(path, "rb");
    if (!file) {
        perror("fopen failed");
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    long length = ftell(file);
    fseek(file, 0, SEEK_SET);

    if (length <= 0) {
        fclose(file);
        return NULL;
    }

    char* buffer = malloc(length);
    if (!buffer) {
        fclose(file);
        return NULL;
    }

    size_t read = fread(buffer, 1, length, file);
    fclose(file);

    if (read != (size_t)length) {
        free(buffer);
        return NULL;
    }

    if (out_size) {
        *out_size = length;
    }
    
    return buffer;
}

// Główna funkcja routingu
HTTPResponse handle_request(const HTTPRequest* request, const Config* config) {
    HTTPResponse response = {0};
    response.content = NULL;
    response.content_size = 0;
    response.is_binary = 0;

    char decoded_path[1024] = {0};
    char file_path[2048] = {0};
    
    // 1. Dekodowanie URL i normalizacja ścieżki
    strncpy(decoded_path, request->path, sizeof(decoded_path)-1);
    url_decode(decoded_path);
    normalize_path(decoded_path);

    // 2. Obsługa endpointów API
    if (strstr(decoded_path, config->api_prefix) == decoded_path) {
        if (strcmp(decoded_path, "/api/status") == 0) {
            return api_status();
        } else if (strcmp(decoded_path, "/api/echo") == 0) {
            return api_echo(request);
        } else {
            response.status_code = 404;
            strcpy(response.content_type, "application/json");
            response.content = my_strdup("{\"error\":\"Endpoint not found\"}");
            if (response.content) {
                response.content_size = strlen(response.content);
            }
            return response;
        }
    }

    // 3. Obsługa plików statycznych (assets, static)
    if (strstr(decoded_path, "/assets/") == decoded_path || 
        strstr(decoded_path, "/static/") == decoded_path) {

        snprintf(file_path, sizeof(file_path), "%s%s", config->frontend_path, decoded_path);
        response.content = read_file_content(file_path, &response.content_size);

        if (response.content) {
            response.status_code = 200;
            const char* mime_type = get_mime_type(file_path);
            strcpy(response.content_type, mime_type ? mime_type : "application/octet-stream");

            if (strstr(file_path, ".wasm") != NULL) {
                strcpy(response.content_type, "application/wasm");
                response.is_binary = 1;
            } else if (strstr(file_path, ".js") != NULL) {
                strcpy(response.content_type, "application/javascript");
            } else if (strstr(file_path, ".css") != NULL) {
                strcpy(response.content_type, "text/css");
            }

            return response;
        }
    }

    // 4. Obsługa SPA - główna logika
    struct stat st;
    int file_exists = 0;

    // 4a. Sprawdź czy żądany plik istnieje
    if (strcmp(decoded_path, "/") != 0) {
        snprintf(file_path, sizeof(file_path), "%s%s", config->frontend_path, decoded_path);
        file_exists = (stat(file_path, &st) == 0 && S_ISREG(st.st_mode));
    }

    // 4b. Jeśli plik istnieje i ma rozszerzenie - obsłuż normalnie
    if (file_exists && strchr(decoded_path, '.') != NULL) {
        response.content = read_file_content(file_path, &response.content_size);
        if (response.content) {
            response.status_code = 200;
            const char* mime_type = get_mime_type(file_path);
            strcpy(response.content_type, mime_type ? mime_type : "application/octet-stream");
            return response;
        }
    }

    // 5. Fallback na index.html dla wszystkich ścieżek SPA
    snprintf(file_path, sizeof(file_path), "%s/index.html", config->frontend_path);
    response.content = read_file_content(file_path, &response.content_size);
    
    if (response.content) {
        response.status_code = 200;
        strcpy(response.content_type, "text/html");
    } else {
        response.status_code = 404;
        strcpy(response.content_type, "text/html");
        response.content = my_strdup("<h1>404 Not Found</h1><p>File not found</p>");
        if (response.content) {
            response.content_size = strlen(response.content);
        }
    }

    return response;
}

// Funckja normalize_path
void normalize_path(char* path) {
    char* src = path;
    char* dst = path;
    
    while (*src) {
        // Usuń podwójne ukośniki
        if (*src == '/' && *(src+1) == '/') {
            src++;
            continue;
        }
        *dst++ = *src++;
    }
    *dst = '\0';
}

// Budowanie odpowiedzi HTTP
char* build_response(const HTTPResponse* response, size_t* response_size) {
    if (!response || !response->content) {
        if (response_size) *response_size = 0;
        return NULL;
    }

    const char* status_msg = response->status_code == 200 ? "OK" : "Not Found";
    
    // Additional headers for WASM
    const char* extra_headers = "";
    if (strcmp(response->content_type, "application/wasm") == 0) {
        extra_headers = "Access-Control-Allow-Origin: *\r\n"
                       "Cross-Origin-Opener-Policy: same-origin\r\n"
                       "Cross-Origin-Embedder-Policy: require-corp\r\n";
    }

    size_t header_len = snprintf(NULL, 0,
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
        extra_headers);

    char* http_response = malloc(header_len + response->content_size);
    if (!http_response) {
        if (response_size) *response_size = 0;
        return NULL;
    }

    sprintf(http_response,
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
        extra_headers);

    memcpy(http_response + header_len, response->content, response->content_size);

    if (response_size) {
        *response_size = header_len + response->content_size;
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

// Rozpoznawanie typu MIME
const char* get_mime_type(const char* filename) {
    const char* ext = strrchr(filename, '.');
    if (!ext) return NULL;
    
    ext++; // Pomijamy kropkę
    
    // Rozszerzona lista typów MIME
    if (strcasecmp(ext, "html") == 0) return "text/html";
    if (strcasecmp(ext, "js") == 0) return "application/javascript";
    if (strcasecmp(ext, "css") == 0) return "text/css";
    if (strcasecmp(ext, "json") == 0) return "application/json";
    if (strcasecmp(ext, "png") == 0) return "image/png";
    if (strcasecmp(ext, "jpg") == 0 || strcasecmp(ext, "jpeg") == 0) return "image/jpeg";
    if (strcasecmp(ext, "svg") == 0) return "image/svg+xml";
    if (strcasecmp(ext, "ico") == 0) return "image/x-icon";
    if (strcasecmp(ext, "woff") == 0) return "font/woff";
    if (strcasecmp(ext, "woff2") == 0) return "font/woff2";
    if (strcasecmp(ext, "ttf") == 0) return "font/ttf";
    if (strcasecmp(ext, "wasm") == 0) return "application/wasm"; // Dodane dla WASM

    return NULL;
}

// Dekodowanie URL
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

HTTPResponse api_status(void) {
    HTTPResponse response = {0};
    response.status_code = 200;
    strcpy(response.content_type, "application/json");
    const char* content = "{\"status\":\"running\",\"version\":\"1.0\",\"endpoints\":[\"/api/status\",\"/api/echo\"]}";
    response.content = my_strdup(content);
    response.content_size = strlen(content);
    return response;
}

HTTPResponse api_echo(const HTTPRequest* request) {
    HTTPResponse response = {0};
    response.status_code = 200;
    strcpy(response.content_type, "application/json");
    
    // Calculate needed size
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
    
    return response;
}
