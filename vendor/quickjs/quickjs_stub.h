/*
 * quickjs.h — QuickJS public API shim for nas-web
 *
 * To enable real QuickJS (ES2020):
 *   cd vendor/quickjs && bash fetch_quickjs.sh
 *   cmake .. -DWITH_QUICKJS=ON && make -j$(nproc)
 *
 * This shim provides the full public API surface so nas-web compiles
 * without the real library. All calls are no-ops / stubs.
 */
#pragma once
#ifndef QUICKJS_H
#define QUICKJS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* ── Value representation ──────────────────────────────────────────────── */
typedef struct JSRuntime  JSRuntime;
typedef struct JSContext  JSContext;
typedef struct JSObject   JSObject;
typedef struct JSClass    JSClass;

typedef uint64_t JSValue;
typedef const JSValue JSValueConst;

#define JS_TAG_INT       0
#define JS_TAG_BOOL      1
#define JS_TAG_NULL      2
#define JS_TAG_UNDEFINED 3
#define JS_TAG_EXCEPTION 6
#define JS_TAG_STRING    8
#define JS_TAG_OBJECT    9

/* Pack tag+val into a JSValue (stub — just use integer codes) */
#define JS_MKVAL(tag, val)  ((JSValue)((uint64_t)(tag) << 32 | (uint32_t)(val)))
#define JS_NULL             JS_MKVAL(JS_TAG_NULL, 0)
#define JS_UNDEFINED        JS_MKVAL(JS_TAG_UNDEFINED, 0)
#define JS_EXCEPTION        JS_MKVAL(JS_TAG_EXCEPTION, 0)
#define JS_TRUE             JS_MKVAL(JS_TAG_BOOL, 1)
#define JS_FALSE            JS_MKVAL(JS_TAG_BOOL, 0)

static inline int JS_VALUE_GET_TAG(JSValue v){ return (int)(v >> 32); }
static inline int JS_IsNull(JSValue v)      { return JS_VALUE_GET_TAG(v)==JS_TAG_NULL; }
static inline int JS_IsUndefined(JSValue v) { return JS_VALUE_GET_TAG(v)==JS_TAG_UNDEFINED; }
static inline int JS_IsException(JSValue v) { return JS_VALUE_GET_TAG(v)==JS_TAG_EXCEPTION; }
static inline int JS_IsBool(JSValue v)      { return JS_VALUE_GET_TAG(v)==JS_TAG_BOOL; }
static inline int JS_IsInt(JSValue v)       { return JS_VALUE_GET_TAG(v)==JS_TAG_INT; }

/* ── CFunction types ────────────────────────────────────────────────────── */
typedef JSValue JSCFunction(JSContext*, JSValueConst, int, JSValueConst*);
typedef JSValue JSCFunctionMagic(JSContext*, JSValueConst, int, JSValueConst*,
                                  int magic, JSValue* data);
typedef enum {
    JS_CFUNC_generic,
    JS_CFUNC_generic_magic,
    JS_CFUNC_constructor,
} JSCFunctionEnum;

/* ── Runtime / Context ──────────────────────────────────────────────────── */
static inline JSRuntime* JS_NewRuntime(void)                    { return NULL; }
static inline void       JS_FreeRuntime(JSRuntime* rt)          { (void)rt; }
static inline JSContext* JS_NewContext(JSRuntime* rt)           { (void)rt; return NULL; }
static inline void       JS_FreeContext(JSContext* ctx)         { (void)ctx; }
static inline void       JS_SetContextOpaque(JSContext* c,void*p){ (void)c;(void)p; }
static inline void*      JS_GetContextOpaque(JSContext* c)      { (void)c; return NULL; }
static inline void       JS_SetMemoryLimit(JSRuntime* r,size_t n){ (void)r;(void)n; }
static inline void       JS_SetMaxStackSize(JSRuntime* r,size_t n){(void)r;(void)n;}
static inline JSRuntime* JS_GetRuntime(JSContext* c)            { (void)c; return NULL; }

/* ── Eval ───────────────────────────────────────────────────────────────── */
#define JS_EVAL_TYPE_GLOBAL   0
#define JS_EVAL_TYPE_MODULE   1
#define JS_EVAL_FLAG_STRICT   2

static inline JSValue JS_Eval(JSContext* c, const char* s, size_t l,
                               const char* f, int fl)
    { (void)c;(void)s;(void)l;(void)f;(void)fl; return JS_UNDEFINED; }

/* ── Value lifecycle ────────────────────────────────────────────────────── */
static inline void    JS_FreeValue(JSContext* c, JSValue v)     { (void)c;(void)v; }
static inline JSValue JS_DupValue(JSContext* c, JSValue v)      { (void)c; return v; }

/* ── Type constructors ──────────────────────────────────────────────────── */
static inline JSValue JS_NewBool(JSContext* c, int b)           { (void)c; return JS_MKVAL(JS_TAG_BOOL,b?1:0); }
static inline JSValue JS_NewInt32(JSContext* c, int32_t n)      { (void)c; return JS_MKVAL(JS_TAG_INT,(uint32_t)n); }
static inline JSValue JS_NewInt64(JSContext* c, int64_t n)      { (void)c; (void)n; return JS_MKVAL(JS_TAG_INT,0); }
static inline JSValue JS_NewFloat64(JSContext* c, double d)     { (void)c;(void)d; return JS_MKVAL(JS_TAG_INT,0); }
static inline JSValue JS_NewObject(JSContext* c)                { (void)c; return JS_MKVAL(JS_TAG_OBJECT,0); }
static inline JSValue JS_NewArray(JSContext* c)                 { (void)c; return JS_MKVAL(JS_TAG_OBJECT,0); }

static inline JSValue JS_NewStringLen(JSContext* c, const char* s, size_t l)
    { (void)c;(void)s;(void)l; return JS_MKVAL(JS_TAG_STRING,0); }
static inline JSValue JS_NewString(JSContext* c, const char* s)
    { (void)c;(void)s; return JS_MKVAL(JS_TAG_STRING,0); }
static inline JSValue JS_NewAtomString(JSContext* c, const char* s)
    { (void)c;(void)s; return JS_MKVAL(JS_TAG_STRING,0); }

/* ── C-string conversion ────────────────────────────────────────────────── */
static inline const char* JS_ToCStringLen(JSContext* c, size_t* plen, JSValue v)
    { (void)c;(void)plen;(void)v; return NULL; }
static inline const char* JS_ToCString(JSContext* c, JSValue v)
    { (void)c;(void)v; return NULL; }
static inline void JS_FreeCString(JSContext* c, const char* s)
    { (void)c;(void)s; }
static inline int JS_ToInt32(JSContext* c, int32_t* p, JSValue v)
    { (void)c;(void)v; if(p)*p=0; return 0; }
static inline int JS_ToInt64(JSContext* c, int64_t* p, JSValue v)
    { (void)c;(void)v; if(p)*p=0; return 0; }
static inline int JS_ToFloat64(JSContext* c, double* p, JSValue v)
    { (void)c;(void)v; if(p)*p=0.0; return 0; }

/* ── Type checks ────────────────────────────────────────────────────────── */
static inline int JS_IsString(JSValue v)   { return JS_VALUE_GET_TAG(v)==JS_TAG_STRING; }
static inline int JS_IsObject(JSValue v)   { return JS_VALUE_GET_TAG(v)==JS_TAG_OBJECT; }
static inline int JS_IsArray(JSContext* c, JSValue v) { (void)c;(void)v; return 0; }
static inline int JS_IsFunction(JSContext* c, JSValue v) { (void)c;(void)v; return 0; }
static inline int JS_IsNumber(JSValue v)   { return JS_VALUE_GET_TAG(v)==JS_TAG_INT; }

/* ── Property access ────────────────────────────────────────────────────── */
static inline JSValue JS_GetPropertyStr(JSContext* c, JSValueConst o, const char* k)
    { (void)c;(void)o;(void)k; return JS_UNDEFINED; }
static inline int JS_SetPropertyStr(JSContext* c, JSValueConst o,
                                     const char* k, JSValue v)
    { (void)c;(void)o;(void)k;(void)v; return 0; }
static inline JSValue JS_GetPropertyUint32(JSContext* c, JSValueConst o, uint32_t i)
    { (void)c;(void)o;(void)i; return JS_UNDEFINED; }
static inline int JS_SetPropertyUint32(JSContext* c, JSValueConst o,
                                        uint32_t i, JSValue v)
    { (void)c;(void)o;(void)i;(void)v; return 0; }

/* ── Global object ──────────────────────────────────────────────────────── */
static inline JSValue JS_GetGlobalObject(JSContext* c) { (void)c; return JS_MKVAL(JS_TAG_OBJECT,1); }

/* ── Function call ──────────────────────────────────────────────────────── */
static inline JSValue JS_Call(JSContext* c, JSValueConst fn, JSValueConst th,
                               int argc, JSValueConst* argv)
    { (void)c;(void)fn;(void)th;(void)argc;(void)argv; return JS_UNDEFINED; }
static inline JSValue JS_CallConstructor(JSContext* c, JSValueConst fn,
                                          int argc, JSValueConst* argv)
    { (void)c;(void)fn;(void)argc;(void)argv; return JS_UNDEFINED; }

/* ── CFunction registration ─────────────────────────────────────────────── */
static inline JSValue JS_NewCFunction(JSContext* c, JSCFunction* fn,
                                       const char* name, int len)
    { (void)c;(void)fn;(void)name;(void)len; return JS_MKVAL(JS_TAG_OBJECT,2); }
static inline JSValue JS_NewCFunction2(JSContext* c, JSCFunctionMagic* fn,
                                        const char* name, int len,
                                        JSCFunctionEnum cproto, int magic,
                                        JSValue* data)
    { (void)c;(void)fn;(void)name;(void)len;(void)cproto;(void)magic;(void)data;
      return JS_MKVAL(JS_TAG_OBJECT,2); }

/* ── Exception handling ─────────────────────────────────────────────────── */
static inline JSValue JS_GetException(JSContext* c) { (void)c; return JS_NULL; }
static inline JSValue JS_Throw(JSContext* c, JSValue v) { (void)c; (void)v; return JS_EXCEPTION; }
static inline JSValue JS_ThrowTypeError(JSContext* c, const char* fmt, ...)
    { (void)c;(void)fmt; return JS_EXCEPTION; }

/* ── Module / class stubs ───────────────────────────────────────────────── */
typedef int JSClassID;
typedef int JSModuleDef;
static inline JSModuleDef* JS_NewCModule(JSContext* c, const char* n,
                                          int (*init)(JSContext*, JSModuleDef*))
    { (void)c;(void)n;(void)init; return NULL; }

/* ── Marker so vendor code knows this is the shim ──────────────────────── */
#define QUICKJS_SHIM_ONLY 1

#ifdef __cplusplus
}
#endif
#endif /* QUICKJS_H */
