#pragma once
// vendor/lua-cjson/lua_cjson_stub.h
// Minimal stub — present when fetch_lua_cjson.sh has NOT been run yet.
// CMake detects the absence of lua_cjson.c and falls back to this stub,
// which registers a no-op cjson module so existing scripts don't crash.
//
// When lua_cjson.c IS present (after fetch), this file is unused.

#ifdef HAVE_LUA
extern "C" {
#include <lua.h>
#include <lauxlib.h>
}

static int _cjson_stub_encode(lua_State* L) {
    lua_pushstring(L, "{}");  // stub: always returns empty object
    return 1;
}
static int _cjson_stub_decode(lua_State* L) {
    luaL_checkstring(L, 1);
    lua_newtable(L);          // stub: always returns empty table
    return 1;
}

// Call from LuaEngine::register_np_api() or constructor
static void register_cjson_stub(lua_State* L) {
    lua_newtable(L);
    lua_pushcfunction(L, _cjson_stub_encode);
    lua_setfield(L, -2, "encode");
    lua_pushcfunction(L, _cjson_stub_decode);
    lua_setfield(L, -2, "decode");
    lua_pushstring(L, "stub");
    lua_setfield(L, -2, "_VERSION");
    // Register as package.preload["cjson"] so require("cjson") works
    lua_getglobal(L, "package");
    if (lua_istable(L, -1)) {
        lua_getfield(L, -1, "preload");
        if (lua_istable(L, -1)) {
            lua_pushvalue(L, -3);   // copy cjson table
            lua_pushcclosure(L, [](lua_State* l) -> int {
                lua_newtable(l);
                lua_pushcfunction(l, _cjson_stub_encode);
                lua_setfield(l, -2, "encode");
                lua_pushcfunction(l, _cjson_stub_decode);
                lua_setfield(l, -2, "decode");
                return 1;
            }, 0);
            lua_setfield(L, -2, "cjson");
        }
        lua_pop(L, 1); // preload
    }
    lua_pop(L, 1); // package
    lua_setglobal(L, "cjson");
}
#endif // HAVE_LUA
