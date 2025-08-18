#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "error.h"
#include "router.h"
#include "logging.h"

const char* error_message(ErrorCode code) {
    switch (code) {
        case ERR_FILE_NOT_FOUND: return "File not found";
        case ERR_PERMISSION_DENIED: return "Permission denied";
        case ERR_INTERNAL_SERVER: return "Internal server error";
        case ERR_BAD_REQUEST: return "Bad request";
        case ERR_NOT_IMPLEMENTED: return "Not implemented";
        default: return "Unknown error";
    }
}

HTTPResponse error_response(int status_code, const char* message) {
    HTTPResponse response = {0};
    response.status_code = status_code;
    strcpy(response.content_type, "text/html");

    log_message(LOG_ERROR, "Error %d: %s", status_code, message);
    
    // Generate HTML error page
    size_t needed = snprintf(NULL, 0, 
        "<!DOCTYPE html>"
        "<html>"
        "<head>"
        "<title>Error %d</title>"
        "<style>"
        "body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }"
        "h1 { color: #d9534f; }"
        ".error-box { max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 5px; }"
        "</style>"
        "</head>"
        "<body>"
        "<div class=\"error-box\">"
        "<h1>Error %d</h1>"
        "<p>%s</p>"
        "</div>"
        "</body>"
        "</html>",
        status_code, status_code, message) + 1;
    
    response.content = malloc(needed);
    if (response.content) {
        snprintf(response.content, needed,
            "<!DOCTYPE html>"
            "<html>"
            "<head>"
            "<title>Error %d</title>"
            "<style>"
            "body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }"
            "h1 { color: #d9534f; }"
            ".error-box { max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 5px; }"
            "</style>"
            "</head>"
            "<body>"
            "<div class=\"error-box\">"
            "<h1>Error %d</h1>"
            "<p>%s</p>"
            "</div>"
            "</body>"
            "</html>",
            status_code, status_code, message);
        response.content_size = needed - 1;
    } else {
        // Fallback to simple text if malloc fails
        response.content = my_strdup(message);
        if (response.content) {
            response.content_size = strlen(message);
        }
    }
    
    return response;
}
