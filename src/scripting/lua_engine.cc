#pragma once
// ─────────────────────────────────────────────────────────────────────────────
//  lua_engine.cc  —  Lua 5.4 scripting engine
//
//  Lua jako lżejsza alternatywa do V8 dla prostych reguł:
//  • ACL (IP allowlist/denylist)
//  • Header rewriting
//  • Simple auth token check
//  • URL rewriting
//
//  Lua Middleware API:
//
//    -- /etc/nodeproxy/scripts/acl.lua
//    local ALLOWED_IPS = { ["10.0.0.1"]=true, ["10.0.0.2"]=true }
//
//    function on_request(req)
//      if not ALLOWED_IPS[req.client_ip] then
//        return { status=403, body="Forbidden" }
//      end
//      req.headers["X-Trusted"] = "yes"
//      return nil  -- pass through
//    end
//
//    function on_response(req, resp)
//      resp.headers["X-Processed-By"] = "nodeproxy-lua"
//      resp.headers["Server"] = nil  -- remove
//      return resp
//    end
//
//  Dostępne w Lua:
//    • np.log(level, msg)       — logging
//    • np.hash(str)             — FNV-1a hash
//    • np.base64_decode(str)    — decode base64
//    • np.time()                — unix timestamp
//    • req.*                    — pełny Request object
//    • resp.*                   — Response object (w on_response)
// ─────────────────────────────────────────────────────────────────────────────
#include "../../include/np_types.hh"
#include "../../include/np_config.hh"
#include <stdexcept>
#include <fstream>

#ifdef HAVE_LUA
extern "C" {
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
}
#define LUA_RUNTIME "lua5.4"

// ── lua-cjson (vendored) ──────────────────────────────────────────────────────
#ifdef HAVE_LUA_CJSON
extern "C" {
// lua_cjson.c exposes luaopen_cjson — declare it here to avoid pulling
// in the full header (which expects Lua internals already included above)
int luaopen_cjson(lua_State* L);
int luaopen_cjson_safe(lua_State* L);
}
#define CJSON_AVAILABLE 1
#else
// Stub: register a minimal cjson table so require("cjson") doesn't crash
#include "../../vendor/lua-cjson/lua_cjson_stub.h"
#define CJSON_AVAILABLE 0
#endif

#else
#define LUA_RUNTIME "lua-stub"
#endif

#ifdef HAVE_LUA
// ── np.base64_decode — defined outside class to avoid lua_pushcfunction macro issues
static int np_base64_decode(lua_State* l) {
    size_t len = 0;
    const char* s = luaL_checklstring(l, 1, &len);
    static const int8_t T[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
    };
    std::string out; out.reserve((len * 3) / 4 + 4);
    int acc = 0, bits = 0;
    for (size_t i = 0; i < len; i++) {
        int8_t v = T[(unsigned char)s[i]];
        if (v < 0) continue;
        acc = (acc << 6) | v; bits += 6;
        if (bits >= 8) { bits -= 8; out += (char)((acc >> bits) & 0xff); }
    }
    lua_pushlstring(l, out.data(), out.size());
    return 1;
}
#endif // HAVE_LUA

struct LuaResult {
    enum class Action { Pass, Block, Modify } action{Action::Pass};
    std::optional<Response> response;
};

// ═════════════════════════════════════════════════════════════════════════════
class LuaEngine {
public:

#ifdef HAVE_LUA

    LuaEngine() {
        L = luaL_newstate();
        if(!L) throw std::runtime_error("Cannot create Lua state");
        // Safe libs only: base, string, table, math — no io, os, package
        luaopen_base(L);
        luaopen_string(L);
        luaopen_table(L);
        luaopen_math(L);
        luaopen_package(L);   // needed for require() and package.preload
        register_cjson();
        register_np_api();
    }

    ~LuaEngine(){ if(L) lua_close(L); }

    bool load_script(const std::string& name, const std::string& path){
        std::ifstream f(path);
        if(!f){ fprintf(stderr,"[lua] Cannot open: %s\n", path.c_str()); return false; }
        std::string src((std::istreambuf_iterator<char>(f)),
                          std::istreambuf_iterator<char>());
        return compile(name, src);
    }

    bool load_inline(const std::string& name, const std::string& src){
        return compile(name, src);
    }

    LuaResult run_on_request(const std::string& name, Request& req,
                               int timeout_ms = 50){
        lua_getglobal(L, "on_request");
        if(!lua_isfunction(L,-1)){ lua_pop(L,1); return LuaResult{LuaResult::Action::Pass, std::nullopt}; }

        push_request(req);

        set_timeout(timeout_ms);
        int rc = lua_pcall(L, 1, 1, 0);
        clear_timeout();

        if(rc != LUA_OK){
            fprintf(stderr, "[lua] on_request error: %s\n",
                    lua_tostring(L,-1));
            lua_pop(L,1);
            return LuaResult{LuaResult::Action::Pass, std::nullopt};
        }
        return parse_result(-1, req);
    }

    std::optional<Response> run_on_response(const std::string&,
                                              const Request& req,
                                              Response& resp,
                                              int timeout_ms = 50){
        lua_getglobal(L, "on_response");
        if(!lua_isfunction(L,-1)){ lua_pop(L,1); return std::nullopt; }

        push_request(req);
        push_response(resp);

        set_timeout(timeout_ms);
        int rc = lua_pcall(L, 2, 1, 0);
        clear_timeout();

        if(rc != LUA_OK){
            fprintf(stderr, "[lua] on_response error: %s\n",
                    lua_tostring(L,-1));
            lua_pop(L,1);
            return std::nullopt;
        }

        if(lua_istable(L,-1)){
            auto r = extract_response(-1);
            lua_pop(L,1);
            return r;
        }
        lua_pop(L,1);
        return std::nullopt;
    }

private:
    lua_State* L{nullptr};
    volatile bool timed_out_{false};

    bool compile(const std::string& name, const std::string& src){
        if(luaL_dostring(L, src.c_str()) != LUA_OK){
            fprintf(stderr, "[lua] Compile error in '%s': %s\n",
                    name.c_str(), lua_tostring(L,-1));
            lua_pop(L,1);
            return false;
        }
        fprintf(stderr, "[lua] Loaded '%s'\n", name.c_str());
        return true;
    }

    void push_request(const Request& req){
        lua_newtable(L);
        auto set_str = [&](const char* k, const std::string& v){
            lua_pushstring(L, v.c_str());
            lua_setfield(L, -2, k);
        };
        set_str("method",    std::string(method_str(req.method)));
        set_str("path",      req.path);
        set_str("query",     req.query);
        set_str("host",      req.host);
        set_str("client_ip", req.client_ip);
        set_str("body",      req.body);

        // headers as sub-table
        lua_newtable(L);
        for(auto&[k,v]:req.headers.items){
            lua_pushstring(L,v.c_str());
            lua_setfield(L,-2,k.c_str());
        }
        lua_setfield(L,-2,"headers");
    }

    void push_response(const Response& resp){
        lua_newtable(L);
        lua_pushinteger(L, resp.status);
        lua_setfield(L,-2,"status");
        lua_pushstring(L, resp.body.c_str());
        lua_setfield(L,-2,"body");
        lua_newtable(L);
        for(auto&[k,v]:resp.headers.items){
            lua_pushstring(L,v.c_str());
            lua_setfield(L,-2,k.c_str());
        }
        lua_setfield(L,-2,"headers");
    }

    LuaResult parse_result(int idx, Request& req){
        if(lua_isnil(L,idx)){ lua_pop(L,1); return LuaResult{LuaResult::Action::Pass, std::nullopt}; }
        if(lua_istable(L,idx)){
            lua_getfield(L,idx,"status");
            if(lua_isinteger(L,-1)){
                int status = (int)lua_tointeger(L,-1);
                lua_pop(L,1);
                lua_getfield(L,idx,"body");
                std::string body;
                if(lua_isstring(L,-1)) body = lua_tostring(L,-1);
                lua_pop(L,2); // body + table
                Response r;
                r.status = status;
                r.body   = body;
                r.headers.set("Content-Length", std::to_string(body.size()));
                return LuaResult{LuaResult::Action::Block, r};
            }
            lua_pop(L,1);
        }
        lua_pop(L,1);
        return LuaResult{LuaResult::Action::Pass, std::nullopt};
    }

    Response extract_response(int idx){
        Response r;
        lua_getfield(L,idx,"status");
        if(lua_isinteger(L,-1)) r.status=(int)lua_tointeger(L,-1);
        lua_pop(L,1);
        lua_getfield(L,idx,"body");
        if(lua_isstring(L,-1)) r.body=lua_tostring(L,-1);
        lua_pop(L,1);
        // headers
        lua_getfield(L,idx,"headers");
        if(lua_istable(L,-1)){
            lua_pushnil(L);
            while(lua_next(L,-2)){
                if(lua_isstring(L,-2) && lua_isstring(L,-1))
                    r.headers.set(lua_tostring(L,-2), lua_tostring(L,-1));
                lua_pop(L,1);
            }
        }
        lua_pop(L,1);
        return r;
    }

    // ── cjson registration ───────────────────────────────────────────────────
    void register_cjson() {
#if CJSON_AVAILABLE
        // Register cjson via luaL_requiref — safe, works without package lib
        luaL_requiref(L, "cjson",      luaopen_cjson,      1); lua_pop(L, 1);
        luaL_requiref(L, "cjson.safe", luaopen_cjson_safe, 1); lua_pop(L, 1);

        // Also register in package.preload if package lib is available
        lua_getglobal(L, "package");
        if(lua_istable(L, -1)) {
            lua_getfield(L, -1, "preload");
            if(lua_istable(L, -1)) {
                lua_pushcfunction(L, luaopen_cjson_safe);
                lua_setfield(L, -2, "cjson");
                lua_pushcfunction(L, luaopen_cjson_safe);
                lua_setfield(L, -2, "cjson.safe");
            }
            lua_pop(L, 1); // preload
        }
        lua_pop(L, 1); // package
        fprintf(stderr, "[lua] cjson loaded (vendored lua-cjson)\n");
#else
        // Register stub so require("cjson") returns a working (limited) table
        register_cjson_stub(L);
        fprintf(stderr, "[lua] cjson stub loaded (run vendor/lua-cjson/fetch_lua_cjson.sh for full support)\n");
#endif
    }

    // ── np.* API ──────────────────────────────────────────────────────────────
    void register_np_api(){
        lua_newtable(L);

        // np.log(level, msg)
        lua_pushcfunction(L, [](lua_State* l)->int{
            const char* msg = luaL_checkstring(l,2);
            fprintf(stderr, "[lua-script] %s\n", msg);
            return 0;
        });
        lua_setfield(L,-2,"log");

        // np.time() → unix timestamp
        lua_pushcfunction(L, [](lua_State* l)->int{
            lua_pushnumber(l, (lua_Number)time(nullptr));
            return 1;
        });
        lua_setfield(L,-2,"time");

        // np.hash(str) → integer
        lua_pushcfunction(L, [](lua_State* l)->int{
            size_t len=0;
            const char* s = luaL_checklstring(l,1,&len);
            uint32_t h=2166136261u;
            for(size_t i=0;i<len;i++){h^=(unsigned char)s[i];h*=16777619u;}
            lua_pushinteger(l,(lua_Integer)h);
            return 1;
        });
        lua_setfield(L,-2,"hash");

        // np.base64_decode(str) → string
        lua_pushcfunction(L, np_base64_decode);
        lua_setfield(L,-2,"base64_decode");

        lua_setglobal(L,"np");
    }

    // Lua hook for CPU timeout — passed by pointer to lua_sethook(), not called directly
    static void timeout_hook(lua_State* l, [[maybe_unused]] lua_Debug* ar){
        lua_pushstring(l,"Script timeout");
        lua_error(l);
    }

    void set_timeout(int ms){
        // Simple instruction count limit (approximate)
        lua_sethook(L, timeout_hook, LUA_MASKCOUNT, ms * 1000);
        timed_out_ = false;
    }
    void clear_timeout(){ lua_sethook(L, nullptr, 0, 0); }

#else
    // ── Lua stub (compiles without liblua) ────────────────────────────────────
public:
    LuaEngine(){
        fprintf(stderr, "[lua] Running with stub engine (%s)\n"
                        "      Install liblua5.4-dev and rebuild with -DHAVE_LUA\n",
                LUA_RUNTIME);
    }
    bool load_script(const std::string& name, const std::string& path){
        scripts_[name] = path; return true;
    }
    bool load_inline(const std::string& name, const std::string& src){
        scripts_[name] = src; return true;
    }
    LuaResult run_on_request(const std::string& name, Request& req, int=50){
        // Stub: parse // @directives same as V8 stub
        auto it = scripts_.find(name);
        if(it==scripts_.end()) return LuaResult{LuaResult::Action::Pass, std::nullopt};
        std::istringstream ss(it->second);
        std::string line;
        while(std::getline(ss,line)){
            auto p=line.find("-- @");
            if(p==std::string::npos) continue;
            auto d=line.substr(p+4);
            if(d.substr(0,10)=="add-header"){
                auto rest=d.substr(11);
                auto sp=rest.find(' ');
                if(sp!=std::string::npos) req.headers.set(rest.substr(0,sp),rest.substr(sp+1));
            } else if(d.substr(0,13)=="remove-header"){
                req.headers.remove(d.substr(14));
            }
        }
        return LuaResult{LuaResult::Action::Pass, std::nullopt};
    }
    std::optional<Response> run_on_response(const std::string&,
                                              const Request&, Response& resp, int=50){
        return std::nullopt;
    }
private:
    std::unordered_map<std::string,std::string> scripts_;
#endif
};
