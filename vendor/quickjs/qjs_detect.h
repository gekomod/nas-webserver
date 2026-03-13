// Auto-detection for QuickJS — included by v8_engine.cc
#pragma once
#if defined(HAVE_QUICKJS) && HAVE_QUICKJS
  // Real QuickJS compiled in via CMake (fetch_quickjs.sh was run)
  #include "quickjs.h"
  #define QJS_SOURCE "vendored"
#else
  // Stub shim — all API calls compile but are no-ops
  #include "quickjs_stub.h"
  #define QJS_SOURCE "shim (disabled)"
#endif
