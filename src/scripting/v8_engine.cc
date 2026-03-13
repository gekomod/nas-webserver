#pragma once
// ─────────────────────────────────────────────────────────────────────────────
//  v8_engine.cc — JS engine stub
//  Placeholder for potential V8/QuickJS integration.
//  All methods are intentional no-ops — suppress unused warnings.
// ─────────────────────────────────────────────────────────────────────────────
#include "../../include/np_types.hh"
#include "../../include/np_config.hh"

static constexpr const char* JS_RUNTIME = "disabled";

class V8Engine {
public:
    static void init_platform([[maybe_unused]] const char* exec_path) {}
    static void shutdown_platform() {}
    bool load_script([[maybe_unused]] const std::string& name,
                     [[maybe_unused]] const std::string& path)   { return false; }
    bool load_inline([[maybe_unused]] const std::string& name,
                     [[maybe_unused]] const std::string& src)    { return false; }
    bool run_on_request([[maybe_unused]] const std::string& name,
                        [[maybe_unused]] Request& req,
                        [[maybe_unused]] Response& res)          { return false; }
    bool run_on_response([[maybe_unused]] const std::string& name,
                         [[maybe_unused]] const Request& req,
                         [[maybe_unused]] Response& res)         { return false; }
    int  loaded_count() const { return 0; }
};
