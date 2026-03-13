#pragma once
// ─────────────────────────────────────────────────────────────────────────────
//  static_handler.cc  —  static file serving (gzip, ETag, Range, SPA)
// ─────────────────────────────────────────────────────────────────────────────
#include "../../include/np_types.hh"
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <cstring>
#include <cstdio>
#include <sstream>
#include <iomanip>

#ifdef HAVE_ZLIB
#include <zlib.h>
#define ZLIB_OK 1
#else
#define ZLIB_OK 0
#endif

static std::string_view mime_type(std::string_view p){
    auto e=p.rfind('.');
    if(e==std::string_view::npos) return "application/octet-stream";
    auto x=p.substr(e+1);
    if(x=="html"||x=="htm") return "text/html; charset=utf-8";
    if(x=="css")   return "text/css";
    if(x=="js"||x=="mjs") return "application/javascript";
    if(x=="json")  return "application/json";
    if(x=="wasm")  return "application/wasm";
    if(x=="svg")   return "image/svg+xml";
    if(x=="png")   return "image/png";
    if(x=="jpg"||x=="jpeg") return "image/jpeg";
    if(x=="gif")   return "image/gif";
    if(x=="webp")  return "image/webp";
    if(x=="ico")   return "image/x-icon";
    if(x=="woff")  return "font/woff";
    if(x=="woff2") return "font/woff2";
    if(x=="ttf")   return "font/ttf";
    if(x=="txt")   return "text/plain; charset=utf-8";
    if(x=="xml")   return "application/xml";
    if(x=="pdf")   return "application/pdf";
    if(x=="mp4")   return "video/mp4";
    if(x=="webm")  return "video/webm";
    if(x=="mp3")   return "audio/mpeg";
    return "application/octet-stream";
}

static std::string make_etag(const struct stat& st){
    char buf[64];
    snprintf(buf,sizeof(buf),"\"%lx-%zx\"",(long)st.st_mtime,(size_t)st.st_size);
    return buf;
}

#if ZLIB_OK
static std::string gzip_compress(const std::string& src){
    z_stream zs{}; zs.next_in=(Bytef*)src.data(); zs.avail_in=(uInt)src.size();
    if(deflateInit2(&zs,Z_DEFAULT_COMPRESSION,Z_DEFLATED,15|16,8,Z_DEFAULT_STRATEGY)!=Z_OK) return {};
    std::string out; out.resize(deflateBound(&zs,(uLong)src.size()));
    zs.next_out=(Bytef*)out.data(); zs.avail_out=(uInt)out.size();
    if(deflate(&zs,Z_FINISH)!=Z_STREAM_END){deflateEnd(&zs);return {};}
    out.resize(zs.total_out); deflateEnd(&zs); return out;
}
#else
static std::string gzip_compress(const std::string&){ return {}; }
#endif

// ── Brotli compression ────────────────────────────────────────────────────────
#if defined(HAVE_BROTLI)
#include <brotli/encode.h>
static std::string brotli_compress(const std::string& src){
    size_t out_size = BrotliEncoderMaxCompressedSize(src.size());
    if(out_size == 0) return {};
    std::string out(out_size, '\0');
    if(BrotliEncoderCompress(
        BROTLI_DEFAULT_QUALITY, BROTLI_DEFAULT_WINDOW, BROTLI_DEFAULT_MODE,
        src.size(), (const uint8_t*)src.data(),
        &out_size, (uint8_t*)out.data()) == BROTLI_FALSE) return {};
    out.resize(out_size);
    return out;
}
#else
static std::string brotli_compress(const std::string&){ return {}; }
#endif

struct StaticConfig {
    std::string root;
    bool   gzip{true};
    bool   brotli{true};   // prefer brotli over gzip when client supports it
    bool   etag{true};
    int    cache_max_age{0};
    bool   autoindex{false};
    bool   spa_fallback{false};    // SPA: 404 → serve index.html
    std::string index_file{"index.html"};
    size_t gzip_min_size{1024};
};

Response serve_static(const Request& req, const StaticConfig& cfg){
    // Block path traversal
    if(req.path.find("..")!=std::string::npos)
        return Response::make_error(403,"Path traversal denied");

    std::string fs_path=cfg.root+req.path;
    struct stat st;

    auto try_serve=[&](const std::string& path, const struct stat& fst)->Response{
        // ETag / conditional
        std::string etag=make_etag(fst);
        if(cfg.etag){
            auto inm=req.headers.get("If-None-Match");
            if(!inm.empty()&&inm==etag){
                Response r; r.status=304;
                r.headers.set("ETag",etag);
                return r;
            }
            auto ims=req.headers.get("If-Modified-Since");
            if(!ims.empty()){
                struct tm tm_s{}; strptime(ims.data(),"%a, %d %b %Y %H:%M:%S GMT",&tm_s);
                if(fst.st_mtime<=timegm(&tm_s)){
                    Response r; r.status=304; r.headers.set("ETag",etag); return r;
                }
            }
        }

        // Check for pre-compressed .gz / .br / .zst
        auto accept_enc = req.headers.get("Accept-Encoding");
        bool client_gz   = accept_enc.find("gzip") != std::string_view::npos;
        bool client_br   = accept_enc.find("br")   != std::string_view::npos;
        bool client_zstd = opt::client_accepts_zstd(accept_enc);
        bool use_gz=false, use_br=false, use_zstd=false;
        std::string read_path=path;
        struct stat gz_st, br_st, zst_st;

        // Prefer zstd > brotli > gzip (pre-compressed files)
        if(opt::zstd_available() && client_zstd && (size_t)fst.st_size >= cfg.gzip_min_size) {
            std::string zst = path+".zst";
            if(stat(zst.c_str(),&zst_st)==0){ read_path=zst; use_zstd=true; }
        }
        if(!use_zstd && cfg.brotli && client_br && (size_t)fst.st_size >= cfg.gzip_min_size) {
            std::string br = path+".br";
            if(stat(br.c_str(),&br_st)==0){ read_path=br; use_br=true; }
        }
        if(!use_zstd && !use_br && cfg.gzip && client_gz && (size_t)fst.st_size >= cfg.gzip_min_size){
            std::string gz=path+".gz";
            if(stat(gz.c_str(),&gz_st)==0){read_path=gz;use_gz=true;}
        }

        int fd=open(read_path.c_str(),O_RDONLY);
        if(fd<0) return Response::make_error(404);
        auto& rstat=use_gz?gz_st:fst;
        std::string data; data.resize((size_t)rstat.st_size);
        ssize_t n=read(fd,data.data(),(size_t)rstat.st_size); close(fd);
        if(n<0) return Response::make_error(500);
        data.resize((size_t)n);

        // CSS minification (before compression)
        std::string content_type_str(mime_type(path));
        if(opt::is_css(content_type_str) && !use_gz && !use_br && !use_zstd) {
            auto minified = opt::minify_css(data);
            if(opt::should_minify_css(data, minified)) data = std::move(minified);
        }
        // HTML optimization (lazy images, charset, strip comments)
        if(opt::is_html(content_type_str) && !use_gz && !use_br && !use_zstd) {
            data = opt::optimize_html(data);
        }

        // Runtime compression: zstd > brotli > gzip
        bool rt_gz=false, rt_br=false, rt_zstd=false;
        if(!use_br && !use_gz && !use_zstd && data.size() >= cfg.gzip_min_size
           && opt::is_compressible(content_type_str)) {
            if(opt::zstd_available() && client_zstd) {
                auto compressed = opt::zstd_compress(data);
                if(!compressed.empty() && compressed.size() < data.size()) {
                    data = std::move(compressed); rt_zstd = true;
                }
            }
            if(!rt_zstd && cfg.brotli && client_br) {
                auto compressed = brotli_compress(data);
                if(!compressed.empty() && compressed.size() < data.size()) {
                    data = std::move(compressed); rt_br = true;
                }
            }
            if(!rt_zstd && !rt_br && cfg.gzip && client_gz) {
                auto compressed = gzip_compress(data);
                if(!compressed.empty() && compressed.size() < data.size()) {
                    data = std::move(compressed); rt_gz = true;
                }
            }
        }

        Response resp; resp.status=200;
        resp.headers.set("Content-Type",content_type_str);
        if(cfg.etag) resp.headers.set("ETag",etag);
        if(use_zstd || rt_zstd) resp.headers.set("Content-Encoding","zstd");
        else if(use_br  || rt_br) resp.headers.set("Content-Encoding","br");
        else if(use_gz || rt_gz) resp.headers.set("Content-Encoding","gzip");
        if(cfg.gzip || cfg.brotli || opt::zstd_available()) resp.headers.set("Vary","Accept-Encoding");
        char lm[64]; strftime(lm,sizeof(lm),"%a, %d %b %Y %H:%M:%S GMT",gmtime(&fst.st_mtime));
        resp.headers.set("Last-Modified",lm);
        if(cfg.cache_max_age>0){
            bool immutable=req.path.size()>=7&&req.path.substr(0,8)=="/assets/";
            std::string cc="public, max-age="+std::to_string(cfg.cache_max_age);
            if(immutable) cc+=", immutable";
            resp.headers.set("Cache-Control",cc);
        } else {
            resp.headers.set("Cache-Control","no-cache");
        }
        resp.headers.set("Content-Length",std::to_string(data.size()));
        resp.body=std::move(data);
        return resp;
    };

    if(stat(fs_path.c_str(),&st)==0){
        if(S_ISDIR(st.st_mode)){
            std::string idx=fs_path+"/"+cfg.index_file;
            struct stat idx_st;
            if(stat(idx.c_str(),&idx_st)==0) return try_serve(idx,idx_st);
            return Response::make_error(403);
        }
        return try_serve(fs_path,st);
    }

    // SPA fallback: serve index.html for unknown paths (client-side routing)
    if(cfg.spa_fallback){
        std::string idx=cfg.root+"/"+cfg.index_file;
        if(stat(idx.c_str(),&st)==0) return try_serve(idx,st);
    }

    return Response::make_error(404,"Not found: "+req.path);
}
