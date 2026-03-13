cmake_minimum_required(VERSION 3.18)
project(nas-web VERSION 2.2.83 LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(WITH_LUA     "Embed Lua 5.4 scripting"     ON)
option(WITH_QUICKJS "Embed QuickJS JS engine"      ON)
option(WITH_NGHTTP2 "HTTP/2 support (nghttp2)"    ON)
option(WITH_QUICHE  "HTTP/3 support (quiche)"     OFF)
option(WITH_ZSTD    "zstd compression (vendored)" OFF)
option(WITH_JANET   "Janet WAF scripting (vendored)" OFF)

add_compile_options(-Wall -Wextra -Wno-unused-parameter -O2 -g)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBUV   REQUIRED libuv)
pkg_check_modules(OPENSSL REQUIRED openssl)
pkg_check_modules(ZLIB    REQUIRED zlib)

set(DEPS ${LIBUV_LIBRARIES} ${OPENSSL_LIBRARIES} ${ZLIB_LIBRARIES} pthread)
set(INCS include ${LIBUV_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIRS} ${ZLIB_INCLUDE_DIRS})
set(DEFS "")

# ── QuickJS (no conflict with Node.js — vendored or system) ─────────────────
if(WITH_QUICKJS)
    set(QJS_VENDOR "${CMAKE_SOURCE_DIR}/vendor/quickjs")
    if(EXISTS "${QJS_VENDOR}/quickjs.c")
        # Vendored source: fetch_quickjs.sh was run — build as static lib
        foreach(_f quickjs.c libregexp.c libunicode.c libbf.c cutils.c)
            if(EXISTS "${QJS_VENDOR}/${_f}")
                list(APPEND QJS_SRCS "${QJS_VENDOR}/${_f}")
            endif()
        endforeach()
        # When real quickjs.c is present, rename our shim so it doesn't shadow
        # the real quickjs.h that must have been downloaded with the sources.
        # fetch_quickjs.sh copies ALL .h files, so real quickjs.h should exist.
        # If only our stub quickjs.h exists, move it out of the way.
        # Detect if quickjs.h is our stub or the real one
        # Real QuickJS header always contains JSRuntime typedef
        # Our stub contains the marker "nas-web"
        file(READ "${QJS_VENDOR}/quickjs.h" _QJS_H_CONTENT)
        string(FIND "${_QJS_H_CONTENT}" "nas-web" _IS_STUB)
        if(NOT ${_IS_STUB} EQUAL -1)
            # It's our stub — rename it so real quickjs.c can include the real header
            file(RENAME "${QJS_VENDOR}/quickjs.h" "${QJS_VENDOR}/quickjs_stub.h")
            message(STATUS "QuickJS: moved stub quickjs.h -> quickjs_stub.h")
        endif()

        add_library(quickjs_vendor STATIC ${QJS_SRCS})
        target_include_directories(quickjs_vendor BEFORE PUBLIC "${QJS_VENDOR}")
        target_compile_options(quickjs_vendor PRIVATE
            -Wno-unused-parameter -Wno-sign-compare
            -Wno-missing-field-initializers -Wno-implicit-fallthrough
            -Wno-cast-function-type -Wno-unused-variable
            -Wno-unused-but-set-variable -Wno-enum-conversion)
        target_compile_definitions(quickjs_vendor PRIVATE
            CONFIG_VERSION="2024-01-13"
            CONFIG_BIGNUM=1)
        list(APPEND INCS "${QJS_VENDOR}")
        list(APPEND DEFS HAVE_QUICKJS=1)
        set(QJS_LINK_LIB quickjs_vendor)
        message(STATUS "QuickJS: vendored source -> JS scripting ENABLED (ES2020)")
    else()
        # Shim header only — compiles, JS calls are no-ops
        list(APPEND INCS "${QJS_VENDOR}")
        message(STATUS "QuickJS: stub shim (run vendor/quickjs/fetch_quickjs.sh to enable)")
    endif()
endif()

# ── Lua ───────────────────────────────────────────────────────────────────────
if(WITH_LUA)
    pkg_check_modules(LUA lua5.4)
    if(LUA_FOUND)
        list(APPEND INCS ${LUA_INCLUDE_DIRS})
        list(APPEND DEPS ${LUA_LIBRARIES})
        list(APPEND DEFS HAVE_LUA)
        message(STATUS "Lua 5.4 found (pkg-config)")
    else()
        # Fallback: szukaj ręcznie (Debian/Ubuntu: /usr/include/lua5.4)
        find_path(LUA_INC lua.h
            PATHS /usr/include/lua5.4 /usr/local/include/lua5.4
                  /usr/include /usr/local/include
            PATH_SUFFIXES lua5.4 lua)
        find_library(LUA_LIB NAMES lua5.4 lua
            PATHS /usr/lib /usr/local/lib
                  /usr/lib/x86_64-linux-gnu /usr/lib/aarch64-linux-gnu)
        if(LUA_INC AND LUA_LIB)
            list(APPEND INCS ${LUA_INC})
            list(APPEND DEPS ${LUA_LIB})
            list(APPEND DEFS HAVE_LUA)
            message(STATUS "Lua 5.4 found (manual: ${LUA_LIB})")
        else()
            message(STATUS "Lua 5.4 NOT found - using stub (install liblua5.4-dev)")
        endif()
    endif()
endif()

# nghttp2
if(WITH_NGHTTP2)
    pkg_check_modules(NGHTTP2 libnghttp2)
    if(NGHTTP2_FOUND)
        list(APPEND INCS ${NGHTTP2_INCLUDE_DIRS})
        list(APPEND DEPS ${NGHTTP2_LIBRARIES})
        list(APPEND DEFS HAVE_NGHTTP2)
        message(STATUS "nghttp2 found - HTTP/2 enabled")
    else()
        message(STATUS "nghttp2 NOT found - HTTP/2 disabled")
    endif()
endif()

# ── Brotli compression ───────────────────────────────────────────────────────
option(WITH_BROTLI "Brotli compression support" ON)
option(WITH_ACME   "ACME/Let's Encrypt client (built-in)" ON)
option(WITH_MODSEC "ModSecurity WAF (requires libmodsecurity-dev)" OFF)
if(WITH_BROTLI)
    find_library(BROTLI_ENC brotlienc)
    find_library(BROTLI_DEC brotlidec)
    find_library(BROTLI_COM brotlicommon)
    find_path(BROTLI_INC brotli/encode.h)
    if(BROTLI_ENC AND BROTLI_DEC AND BROTLI_COM AND BROTLI_INC)
        list(APPEND INCS ${BROTLI_INC})
        list(APPEND DEPS ${BROTLI_ENC} ${BROTLI_DEC} ${BROTLI_COM})
        list(APPEND DEFS HAVE_BROTLI)
        message(STATUS "Brotli found - br compression enabled")
    else()
        message(STATUS "Brotli NOT found - install libbrotli-dev to enable")
    endif()
endif()

# quiche
if(WITH_ACME)
    # ACME uses OpenSSL which is always a dependency — no extra libs needed
    list(APPEND DEFS HAVE_ACME)
    message(STATUS "  ACME: ON (Let's Encrypt built-in)")
else()
    message(STATUS "  ACME: OFF")
endif()

if(WITH_MODSEC)
    find_library(MODSEC_LIB modsecurity)
    find_path(MODSEC_INC modsecurity/modsecurity.h)
    if(MODSEC_LIB AND MODSEC_INC)
        list(APPEND INCS ${MODSEC_INC})
        list(APPEND DEPS ${MODSEC_LIB})
        list(APPEND DEFS WITH_MODSEC)
        message(STATUS "ModSecurity found: ${MODSEC_LIB}")
    else()
        message(FATAL_ERROR "WITH_MODSEC=ON but libmodsecurity not found.\n"
            "Install: apt install libmodsecurity-dev libmodsecurity3\n"
            "And optionally: apt install modsecurity-crs")
    endif()
endif()

if(WITH_QUICHE)
    find_library(QUICHE_LIB quiche HINTS $ENV{QUICHE_DIR}/target/release)
    find_path(QUICHE_INC quiche.h HINTS $ENV{QUICHE_DIR}/include)
    if(QUICHE_LIB AND QUICHE_INC)
        list(APPEND INCS ${QUICHE_INC})
        list(APPEND DEPS ${QUICHE_LIB} dl)
        list(APPEND DEFS HAVE_QUICHE)
        message(STATUS "quiche found - HTTP/3 enabled")
    endif()
endif()

# ── zstd (vendored) ───────────────────────────────────────────────────────────
if(WITH_ZSTD)
    set(ZSTD_VENDOR "${CMAKE_SOURCE_DIR}/vendor/zstd")
    if(EXISTS "${ZSTD_VENDOR}/lib/zstd.h")
        # Collect all .c files from lib/ subdirs
        file(GLOB_RECURSE ZSTD_SRCS
            "${ZSTD_VENDOR}/lib/common/*.c"
            "${ZSTD_VENDOR}/lib/compress/*.c"
            "${ZSTD_VENDOR}/lib/decompress/*.c"
        )
        add_library(zstd_vendor STATIC ${ZSTD_SRCS})
        target_include_directories(zstd_vendor PUBLIC "${ZSTD_VENDOR}/lib")
        target_compile_options(zstd_vendor PRIVATE
            -Wno-unused-parameter -Wno-sign-compare -Wno-unused-variable
            -Wno-implicit-fallthrough -Wno-missing-field-initializers)
        list(APPEND INCS "${ZSTD_VENDOR}/lib")
        list(APPEND DEFS HAVE_ZSTD=1)
        set(ZSTD_LINK_LIB zstd_vendor)
        message(STATUS "zstd: vendored source -> compression ENABLED")
    else()
        # Stub only — compiles, zstd calls return errors
        list(APPEND INCS "${ZSTD_VENDOR}")
        message(STATUS "zstd: stub (run vendor/zstd/fetch_zstd.sh to enable)")
    endif()
else()
    list(APPEND INCS "${CMAKE_SOURCE_DIR}/vendor/zstd")
    message(STATUS "zstd: stub (WITH_ZSTD=OFF)")
endif()

# ── Janet WAF scripting (vendored) ────────────────────────────────────────────
if(WITH_JANET)
    set(JANET_VENDOR "${CMAKE_SOURCE_DIR}/vendor/janet")
    if(EXISTS "${JANET_VENDOR}/janet.c")
        add_library(janet_vendor STATIC "${JANET_VENDOR}/janet.c")
        target_include_directories(janet_vendor PUBLIC "${JANET_VENDOR}")
        target_compile_options(janet_vendor PRIVATE
            -Wno-unused-parameter -Wno-sign-compare -Wno-unused-variable
            -Wno-implicit-fallthrough -Wno-missing-field-initializers
            -Wno-deprecated-declarations -Wno-cast-function-type)
        list(APPEND INCS "${JANET_VENDOR}")
        list(APPEND DEFS HAVE_JANET=1)
        set(JANET_LINK_LIB janet_vendor)
        message(STATUS "Janet: vendored source -> WAF scripting ENABLED")
    else()
        list(APPEND INCS "${JANET_VENDOR}")
        message(STATUS "Janet: stub (run vendor/janet/fetch_janet.sh to enable)")
    endif()
else()
    list(APPEND INCS "${CMAKE_SOURCE_DIR}/vendor/janet")
    message(STATUS "Janet: stub (WITH_JANET=OFF)")
endif()

# ── cssmin + optimization module (always included, header-only) ───────────────
list(APPEND INCS "${CMAKE_SOURCE_DIR}/vendor/cssmin")

# Binary
add_executable(nas-web src/core/server.cc)
target_include_directories(nas-web PRIVATE ${INCS})
target_compile_definitions(nas-web PRIVATE ${DEFS} NAS_WEB_VERSION="${PROJECT_VERSION}")
set(ALL_VENDOR_LIBS "")
if(DEFINED QJS_LINK_LIB)
    list(APPEND ALL_VENDOR_LIBS ${QJS_LINK_LIB})
endif()
if(DEFINED ZSTD_LINK_LIB)
    list(APPEND ALL_VENDOR_LIBS ${ZSTD_LINK_LIB})
endif()
if(DEFINED JANET_LINK_LIB)
    list(APPEND ALL_VENDOR_LIBS ${JANET_LINK_LIB})
endif()
if(ALL_VENDOR_LIBS)
    target_link_libraries(nas-web PRIVATE ${ALL_VENDOR_LIBS} ${DEPS})
else()
    target_link_libraries(nas-web PRIVATE ${DEPS})
endif()

# Tests
enable_testing()
foreach(t test_parser test_cache test_ratelimit)
    add_executable(${t} tests/${t}.cc)
    target_include_directories(${t} PRIVATE include)
    target_compile_options(${t} PRIVATE -std=c++20 -Wno-unused-variable)
    add_test(NAME ${t} COMMAND ${t})
endforeach()

# Install
install(TARGETS nas-web DESTINATION /usr/local/bin)
install(FILES conf/nas-web.conf DESTINATION /etc/nas-web
        RENAME nas-web.conf)
install(DIRECTORY scripts/ DESTINATION /etc/nas-web/scripts)
install(FILES nas-web.service DESTINATION /etc/systemd/system)
# Create log directory
install(DIRECTORY DESTINATION /var/log/nas-web)

# Summary
message(STATUS "")
message(STATUS "=== nas-web ${PROJECT_VERSION} ===")
message(STATUS "  JS/QuickJS: ${WITH_QUICKJS}")
message(STATUS "  Lua:    ${WITH_LUA}")
message(STATUS "  HTTP/2:  ${WITH_NGHTTP2}")
message(STATUS "  Brotli:  ${WITH_BROTLI}")
message(STATUS "  zstd:    ${WITH_ZSTD}")
message(STATUS "  Janet:   ${WITH_JANET}")
message(STATUS "  HTTP/3: ${WITH_QUICHE}")
message(STATUS "  ACME:   ${WITH_ACME}")
message(STATUS "  Optimizer: ON (CSS minify, HTML rewrite, WebP)")
message(STATUS "=========================")
