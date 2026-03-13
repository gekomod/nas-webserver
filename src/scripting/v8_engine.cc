#pragma once
// ─────────────────────────────────────────────────────────────────────────────
//  v8_engine.cc — JS engine stub
//  JS middleware disabled — Lua handles all scripting (see lua_engine.cc)
//  No V8/QuickJS dependency, no conflict with Node.js
// ─────────────────────────────────────────────────────────────────────────────
#include "../../include/np_types.hh"
#include "../../include/np_config.hh"

static const char* JS_RUNTIME = "disabled";

class V8Engine {
public:
    static void init_platform(const char*) {}   // no-op
    static void shutdown_platform() {}           // no-op
    bool load_script(const std::string&, const std::string&) { return false; }
    bool load_inline(const std::string&, const std::string&) { return false; }
    bool run_on_request(const std::string&, Request&, Response&) { return false; }
    bool run_on_response(const std::string&, const Request&, Response&) { return false; }
    int  loaded_count() const { return 0; }
};
