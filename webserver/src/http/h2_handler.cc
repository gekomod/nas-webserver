#pragma once
// ─────────────────────────────────────────────────────────────────────────────
//  h2_handler.cc  —  HTTP/2 connection handler (nghttp2)
//
//  HTTP/2 vs HTTP/1.1 w kontekście Node.js proxy:
//    • Multiplexing: 100 żądań na jednym połączeniu TCP
//    • Header compression (HPACK): mniejszy overhead przy wielu małych req.
//    • Server Push: opcjonalne, wyłączone domyślnie (rzadko przydatne dla proxy)
//    • Stream priority: respektowane do kolejkowania upstream requests
//
//  Implementacja:
//    • nghttp2 w trybie server (callback-based API)
//    • Każdy HTTP/2 stream mapowany na np_request_t + np_response_t
//    • TLS wymagany (h2 bez TLS = h2c, wspieramy ale ostrzegamy)
//    • ALPN negotiation: "h2" → HTTP/2, "http/1.1" → HTTP/1.1 fallback
//
//  QUIC/HTTP3:
//    • Wymaga quiche (Cloudflare) lub ngtcp2
//    • Osobny UDP socket na tym samym porcie (Alt-Svc header)
//    • Implementacja w h3_handler.cc
// ─────────────────────────────────────────────────────────────────────────────
#include "../../include/np_types.hh"
#include "../../include/np_config.hh"
#include <functional>
#include <unordered_map>
#include <cstring>

#ifdef HAVE_NGHTTP2
#include <nghttp2/nghttp2.h>
#define H2_AVAILABLE 1
#else
#define H2_AVAILABLE 0
#endif

// Callback: called when a complete HTTP/2 stream (request) is ready
using H2RequestCallback = std::function<
    void(Request req, std::function<void(Response)> send_response)>;

// ═════════════════════════════════════════════════════════════════════════════
class H2Handler {
public:
#if H2_AVAILABLE
    explicit H2Handler(int fd, bool is_tls, H2RequestCallback cb)
        : fd_(fd), is_tls_(is_tls), on_request_(std::move(cb))
    {
        nghttp2_session_callbacks* cbs;
        nghttp2_session_callbacks_new(&cbs);

        nghttp2_session_callbacks_set_send_callback(cbs, send_cb);
        nghttp2_session_callbacks_set_on_frame_recv_callback(cbs, frame_recv_cb);
        nghttp2_session_callbacks_set_on_header_callback(cbs, header_cb);
        nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cbs, data_chunk_cb);
        nghttp2_session_callbacks_set_on_stream_close_callback(cbs, stream_close_cb);
        nghttp2_session_callbacks_set_on_begin_headers_callback(cbs, begin_headers_cb);

        nghttp2_session_server_new(&session_, cbs, this);
        nghttp2_session_callbacks_del(cbs);

        // Send server settings
        nghttp2_settings_entry iv[] = {
            {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 256},
            {NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE,    65535},
            {NGHTTP2_SETTINGS_MAX_FRAME_SIZE,         16384},
            {NGHTTP2_SETTINGS_ENABLE_PUSH,            0},  // disable server push
        };
        nghttp2_submit_settings(session_, NGHTTP2_FLAG_NONE,
                                iv, sizeof(iv)/sizeof(iv[0]));
    }

    ~H2Handler(){
        if(session_) nghttp2_session_del(session_);
    }

    // Feed received data from client
    int receive(const uint8_t* data, size_t len){
        ssize_t r = nghttp2_session_mem_recv(session_, data, len);
        if(r < 0){
            fprintf(stderr, "[h2] mem_recv error: %s\n",
                    nghttp2_strerror((int)r));
            return -1;
        }
        return nghttp2_session_send(session_);
    }

    // Send HTTP/2 response for a stream
    void send_response(int32_t stream_id, const Response& resp){
        // Build HPACK headers
        std::vector<nghttp2_nv> nv;

        // :status (pseudo-header must come first)
        auto status_str = std::to_string(resp.status);
        nv.push_back(make_nv(":status", status_str));

        for(auto&[k,v] : resp.headers.items){
            // Skip hop-by-hop headers
            if(ci_eq(k,"Connection")||ci_eq(k,"Transfer-Encoding")) continue;
            // Lowercase header names (HTTP/2 requirement)
            std::string lk = k;
            for(char& c:lk) c=(char)tolower((unsigned char)c);
            nv.push_back(make_nv(lk, v));
        }

        // DATA provider
        nghttp2_data_provider prd;
        prd.source.ptr = (void*)this;

        // Store body for this stream
        stream_bodies_[stream_id] = resp.body;

        prd.read_callback = [](nghttp2_session*,
                                int32_t sid,
                                uint8_t* buf, size_t length,
                                uint32_t* data_flags,
                                nghttp2_data_source* src,
                                void* user_data) -> ssize_t {
            auto* h = (H2Handler*)user_data;
            auto it = h->stream_bodies_.find(sid);
            if(it==h->stream_bodies_.end() ||
               h->stream_offsets_[sid] >= it->second.size()){
                *data_flags |= NGHTTP2_DATA_FLAG_EOF;
                return 0;
            }
            auto& body   = it->second;
            auto& offset = h->stream_offsets_[sid];
            size_t avail = body.size() - offset;
            size_t ncopy = std::min(avail, length);
            memcpy(buf, body.data()+offset, ncopy);
            offset += ncopy;
            if(offset >= body.size()) *data_flags |= NGHTTP2_DATA_FLAG_EOF;
            return (ssize_t)ncopy;
        };

        nghttp2_submit_response(session_, stream_id,
                                nv.data(), nv.size(),
                                resp.body.empty() ? nullptr : &prd);
        nghttp2_session_send(session_);
    }

    bool wants_write() const {
        return nghttp2_session_want_write(session_) != 0;
    }

    // ALPN protocol string for SSL negotiation
    static constexpr std::string_view ALPN_PROTO = "h2";

private:
    int                  fd_;
    bool                 is_tls_;
    nghttp2_session*     session_{nullptr};
    H2RequestCallback    on_request_;

    // Per-stream state
    std::unordered_map<int32_t, Request>     streams_;
    std::unordered_map<int32_t, std::string> stream_bodies_;
    std::unordered_map<int32_t, size_t>      stream_offsets_;

    // ── nghttp2 callbacks (static → dispatch to 'this') ──────────────────────
    static ssize_t send_cb(nghttp2_session*, const uint8_t* data,
                            size_t length, int, void* ud){
        auto* h = (H2Handler*)ud;
        ssize_t r = write(h->fd_, data, length);
        if(r<0 && errno==EAGAIN) return NGHTTP2_ERR_WOULDBLOCK;
        return r;
    }

    static int begin_headers_cb(nghttp2_session*, const nghttp2_frame* frame,
                                  void* ud){
        auto* h = (H2Handler*)ud;
        if(frame->hd.type == NGHTTP2_HEADERS &&
           frame->headers.cat == NGHTTP2_HCAT_REQUEST){
            h->streams_[frame->hd.stream_id] = Request{};
            h->streams_[frame->hd.stream_id].h2_stream_id = frame->hd.stream_id;
            h->streams_[frame->hd.stream_id].is_h2 = true;
        }
        return 0;
    }

    static int header_cb(nghttp2_session*, const nghttp2_frame* frame,
                          const uint8_t* name, size_t nlen,
                          const uint8_t* value, size_t vlen,
                          uint8_t, void* ud){
        auto* h = (H2Handler*)ud;
        auto  it = h->streams_.find(frame->hd.stream_id);
        if(it==h->streams_.end()) return 0;

        std::string k((char*)name, nlen);
        std::string v((char*)value, vlen);
        Request& req = it->second;

        // HTTP/2 pseudo-headers
        if(k==":method")    req.method = method_parse(v);
        else if(k==":path"){
            auto q = v.find('?');
            if(q!=std::string::npos){
                req.path  = v.substr(0,q);
                req.query = v.substr(q+1);
            } else { req.path = v; }
        }
        else if(k==":scheme") req.scheme = v;
        else if(k==":authority") req.host = v;
        else req.headers.set(k, v);

        return 0;
    }

    static int data_chunk_cb(nghttp2_session*, uint8_t, int32_t stream_id,
                               const uint8_t* data, size_t len, void* ud){
        auto* h = (H2Handler*)ud;
        auto  it = h->streams_.find(stream_id);
        if(it!=h->streams_.end()) it->second.body.append((char*)data, len);
        return 0;
    }

    static int frame_recv_cb(nghttp2_session*, const nghttp2_frame* frame,
                               void* ud){
        auto* h = (H2Handler*)ud;
        // Request complete when END_STREAM flag is set on HEADERS or DATA
        if((frame->hd.type==NGHTTP2_HEADERS ||
            frame->hd.type==NGHTTP2_DATA) &&
           (frame->hd.flags & NGHTTP2_FLAG_END_STREAM)){

            auto it = h->streams_.find(frame->hd.stream_id);
            if(it==h->streams_.end()) return 0;

            Request req = std::move(it->second);
            h->streams_.erase(it);
            int32_t sid = req.h2_stream_id;

            // Call handler — it will call send_response when ready
            h->on_request_(std::move(req),
                [h, sid](Response resp){
                    h->send_response(sid, resp);
                });
        }
        return 0;
    }

    static int stream_close_cb(nghttp2_session*, int32_t stream_id,
                                 uint32_t, void* ud){
        auto* h = (H2Handler*)ud;
        h->streams_.erase(stream_id);
        h->stream_bodies_.erase(stream_id);
        h->stream_offsets_.erase(stream_id);
        return 0;
    }

    static nghttp2_nv make_nv(const std::string& name,
                                const std::string& value){
        return {
            (uint8_t*)name.data(),  (uint8_t*)value.data(),
            name.size(), value.size(),
            NGHTTP2_NV_FLAG_NONE
        };
    }

#else
    // ── HTTP/2 stub ────────────────────────────────────────────────────────────
public:
    H2Handler(int fd, bool, H2RequestCallback cb)
        : fd_(fd), on_request_(std::move(cb)){
        fprintf(stderr, "[h2] nghttp2 not available — HTTP/2 disabled\n"
                        "     Install libnghttp2-dev and rebuild with -DHAVE_NGHTTP2\n");
    }
    int receive(const uint8_t*, size_t){ return -1; }
    void send_response(int32_t, const Response&){}
    bool wants_write() const { return false; }
    static constexpr std::string_view ALPN_PROTO = "h2";
private:
    int fd_;
    H2RequestCallback on_request_;
#endif
};
