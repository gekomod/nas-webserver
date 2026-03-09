#pragma once
#include <unordered_set>
// ─────────────────────────────────────────────────────────────────────────────
//  middleware_pipeline.cc  —  JS + Lua middleware execution pipeline
//
//  Middleware chain dla każdej lokalizacji:
//
//    Request → [JS auth.js] → [Lua acl.lua] → Upstream
//                                                 ↓
//    Client  ← [JS transform.js] ← [Lua log.lua] ← Response
//
//  Każdy middleware może:
//    • PASS    — przepuść bez zmian
//    • MODIFY  — zmień request/response i przekaż dalej
//    • BLOCK   — zwróć odpowiedź natychmiast (short-circuit)
//
//  Timeout per middleware (domyślnie 50ms) — przekroczenie = PASS
//  (fail-open: middleware nie może zablokować ruchu przez timeout)
// ─────────────────────────────────────────────────────────────────────────────
#include "../../include/np_types.hh"
#include "../../include/np_config.hh"
#include "v8_engine.cc"
#include "lua_engine.cc"
#include <unordered_map>
#include <string>
#include <memory>
#include <filesystem>

namespace fs = std::filesystem;

// ═════════════════════════════════════════════════════════════════════════════
class MiddlewarePipeline {
public:
    explicit MiddlewarePipeline(const Config& cfg)
        : v8_(), lua_()
    {
        // Preload all scripts from scripts_dir
        try {
            if(!cfg.scripts_dir.empty() && fs::exists(cfg.scripts_dir)){
                for(auto& e : fs::directory_iterator(cfg.scripts_dir)){
                    auto path = e.path();
                    auto ext  = path.extension().string();
                    if(ext==".js")   load_script(ScriptEngine::JS,  path.stem().string(), path.string());
                    if(ext==".lua")  load_script(ScriptEngine::Lua, path.stem().string(), path.string());
                }
            }
        } catch(std::exception& ex){
            fprintf(stderr, "[middleware] scripts_dir scan error: %s\n", ex.what());
        }

        // Load location-specific scripts
        for(auto& srv : cfg.servers){
            for(auto& loc : srv.locations){
                for(auto& mw : loc.middlewares){
                    if(mw.engine == ScriptEngine::None) continue;
                    if(!mw.path.empty())
                        load_script(mw.engine,
                                    script_name_from_path(mw.path),
                                    mw.path);
                    else if(!mw.inline_code.empty())
                        load_inline(mw.engine,
                                    "inline_" + std::to_string(fnv1a(mw.inline_code)),
                                    mw.inline_code);
                }
            }
        }
    }

    // ── Run request phase ─────────────────────────────────────────────────────
    // Returns nullopt → pass, or Response → short-circuit with this response
    std::optional<Response> run_request(
            const std::vector<MiddlewareScript>& chain,
            Request& req) {

        for(auto& mw : chain){
            if(mw.engine == ScriptEngine::None) continue;

            auto name = mw.path.empty()
                ? "inline_" + std::to_string(fnv1a(mw.inline_code))
                : script_name_from_path(mw.path);

            if(mw.engine == ScriptEngine::JS){
                Response block_resp;
                bool blocked = v8_.run_on_request(name, req, block_resp);
                if(blocked) return block_resp;

            } else if(mw.engine == ScriptEngine::Lua){
                auto result = lua_.run_on_request(name, req, mw.timeout_ms);
                if(result.action == LuaResult::Action::Block) {
                    if(result.response) return *result.response;
                    return Response::make_error(403);
                }
            }
        }
        return std::nullopt;  // all passed
    }

    // ── Run response phase ────────────────────────────────────────────────────
    void run_response(
            const std::vector<MiddlewareScript>& chain,
            const Request& req,
            Response& resp) {

        for(auto& mw : chain){
            if(mw.engine == ScriptEngine::None) continue;
            auto name = mw.path.empty()
                ? "inline_" + std::to_string(fnv1a(mw.inline_code))
                : script_name_from_path(mw.path);

            if(mw.engine == ScriptEngine::JS){
                // JS disabled — stub
                (void)name;

            } else if(mw.engine == ScriptEngine::Lua){
                auto modified = lua_.run_on_response(name, req, resp, mw.timeout_ms);
                if(modified) resp = std::move(*modified);
            }
        }
    }

    // ── Script loading ────────────────────────────────────────────────────────
    bool load_script(ScriptEngine eng, const std::string& name,
                     const std::string& path){
        bool ok = false;
        if(eng==ScriptEngine::JS)  ok=v8_.load_script(name, path);
        if(eng==ScriptEngine::Lua) ok=lua_.load_script(name, path);
        if(ok) loaded_scripts_.insert(name);
        return ok;
    }

    bool load_inline(ScriptEngine eng, const std::string& name,
                     const std::string& src){
        bool ok = false;
        if(eng==ScriptEngine::JS)  ok=v8_.load_script(name, src);
        if(eng==ScriptEngine::Lua) ok=lua_.load_inline(name, src);
        if(ok) loaded_scripts_.insert(name);
        return ok;
    }

    int loaded_count() const { return (int)loaded_scripts_.size(); }

    std::string status_json() const {
        std::string out = std::string("{\"js_runtime\":\"") + JS_RUNTIME + "\",\"lua_runtime\":\""
                          LUA_RUNTIME "\",\"scripts\":[";
        bool first=true;
        for(auto& s : loaded_scripts_){
            if(!first) out+=',';
            out += '"' + s + '"';
            first=false;
        }
        out += "]}";
        return out;
    }

private:
    V8Engine  v8_;
    LuaEngine lua_;
    std::unordered_set<std::string> loaded_scripts_;

    static std::string script_name_from_path(const std::string& path){
        auto pos = path.rfind('/');
        auto name = pos==std::string::npos ? path : path.substr(pos+1);
        auto dot  = name.rfind('.');
        return dot==std::string::npos ? name : name.substr(0, dot);
    }
};
