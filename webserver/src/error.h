#ifndef ERROR_H
#define ERROR_H

#include "router.h"

typedef enum {
    ERR_FILE_NOT_FOUND,
    ERR_PERMISSION_DENIED,
    ERR_INTERNAL_SERVER,
    ERR_BAD_REQUEST,
    ERR_NOT_IMPLEMENTED
} ErrorCode;

const char* error_message(ErrorCode code);
HTTPResponse error_response(int status_code, const char* message);

#endif
