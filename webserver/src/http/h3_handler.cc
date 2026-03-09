#pragma once
// ─────────────────────────────────────────────────────────────────────────────
//  h3_handler.cc  —  HTTP/3 / QUIC support
//
//  HTTP/3 = HTTP/2 semantics over QUIC (UDP-based transport).
//
//  Dlaczego HTTP/3 ma sens dla Node.js proxy:
//    • Head-of-line blocking eliminowany na poziomie transportu
//    • 0-RTT reconnect (klient mobilny zmienia IP → brak TCP handshake)
//    • Built-in TLS 1.3
//    • Szczególnie przydatne dla API z dużą liczbą małych żądań
//
//  Implementacja: quiche (Cloudflare) — najpopularniejsza biblioteka QUIC w C
//  Alternatywa: ngtcp2 + nghttp3
//
//  Integracja:
//    1. Serwer słucha na UDP port 443 (ten sam co TCP/TLS)
//    2. Pierwszy response HTTP/1.1 lub HTTP/2 zawiera:
//       Alt-Svc: h3=":443"; ma=86400
//    3. Klient (przeglądarka) przy kolejnym połączeniu próbuje QUIC
//    4. QUIC handshake → HTTP/3 streams
//
//  Uwaga: quiche wymaga Rust + cargo do budowania z źródeł.
//  W tej implementacji: pełny interface z graceful fallback jeśli
//  quiche nie jest dostępny.
// ─────────────────────────────────────────────────────────────────────────────
#include "../../include/np_types.hh"
#include <cstdint>
#include <functional>
#include <unordered_map>
#include <vector>
#include <cstring>
#include <cstdio>

#ifdef HAVE_QUICHE
#include <quiche.h>
#define H3_AVAILABLE 1
#else
#define H3_AVAILABLE 0
#endif

using H3RequestCallback = std::function<
    void(Request, std::function<void(Response)>)>;

// ═════════════════════════════════════════════════════════════════════════════
class H3Handler {
public:
    struct Config {
        std::string cert_path;
        std::string key_path;
        uint64_t    max_idle_timeout_ms{30000};
        uint64_t    initial_max_data{10*1024*1024};
        uint64_t    initial_max_stream_data{1024*1024};
        uint64_t    initial_max_streams_bidi{100};
        bool        enable_0rtt{true};
        bool        grease{true};    // QUIC greasing for ossification resistance
    };

#if H3_AVAILABLE
    H3Handler(int udp_fd, const Config& cfg, H3RequestCallback cb)
        : udp_fd_(udp_fd), on_request_(std::move(cb))
    {
        quiche_cfg_ = quiche_config_new(QUICHE_PROTOCOL_VERSION);

        quiche_config_load_cert_chain_from_pem_file(quiche_cfg_,
            cfg.cert_path.c_str());
        quiche_config_load_priv_key_from_pem_file(quiche_cfg_,
            cfg.key_path.c_str());

        // ALPN: h3 (HTTP/3)
        static const uint8_t alpn[] = "\x02h3";
        quiche_config_set_application_protos(quiche_cfg_,
            alpn, sizeof(alpn)-1);

        quiche_config_set_max_idle_timeout(quiche_cfg_,
            cfg.max_idle_timeout_ms);
        quiche_config_set_initial_max_data(quiche_cfg_,
            cfg.initial_max_data);
        quiche_config_set_initial_max_stream_data_bidi_local(quiche_cfg_,
            cfg.initial_max_stream_data);
        quiche_config_set_initial_max_stream_data_bidi_remote(quiche_cfg_,
            cfg.initial_max_stream_data);
        quiche_config_set_initial_max_streams_bidi(quiche_cfg_,
            cfg.initial_max_streams_bidi);
        quiche_config_set_disable_active_migration(quiche_cfg_, false);

        if(cfg.enable_0rtt)
            quiche_config_enable_early_data(quiche_cfg_);
        if(cfg.grease)
            quiche_config_grease(quiche_cfg_, true);

        fprintf(stderr, "[h3] QUIC/HTTP3 ready on udp fd=%d\n", udp_fd);
    }

    ~H3Handler(){
        for(auto& [cid, conn] : connections_)
            quiche_conn_free(conn.qconn);
        if(quiche_cfg_) quiche_config_free(quiche_cfg_);
    }

    // Process incoming UDP datagram
    void receive(const uint8_t* buf, size_t len,
                  const struct sockaddr* from, socklen_t from_len){
        // Parse QUIC header to get connection ID
        uint8_t  scid[QUICHE_MAX_CONN_ID_LEN];
        size_t   scid_len = sizeof(scid);
        uint8_t  dcid[QUICHE_MAX_CONN_ID_LEN];
        size_t   dcid_len = sizeof(dcid);
        uint8_t  token[128];
        size_t   token_len = sizeof(token);
        uint32_t version;
        uint8_t  ptype;

        int rc = quiche_header_info(buf, len, QUICHE_MAX_CONN_ID_LEN,
                                    &version, &ptype,
                                    scid, &scid_len,
                                    dcid, &dcid_len,
                                    token, &token_len);
        if(rc < 0){
            fprintf(stderr, "[h3] header_info error: %d\n", rc);
            return;
        }

        std::string cid_key((char*)dcid, dcid_len);
        auto it = connections_.find(cid_key);

        if(it == connections_.end()){
            // New connection
            if(!quiche_version_is_supported(version)){
                send_version_negotiation(dcid, dcid_len, scid, scid_len, from, from_len);
                return;
            }
            accept_new(buf, len, scid, scid_len, dcid, dcid_len,
                        token, token_len, version, from, from_len);
            return;
        }

        // Existing connection
        QuicConn& conn = it->second;
        quiche_recv_info recv_info{
            from, from_len,
            (struct sockaddr*)&conn.local_addr, conn.local_addr_len
        };

        ssize_t done = quiche_conn_recv(conn.qconn, (uint8_t*)buf, len,
                                         &recv_info);
        if(done < 0){
            fprintf(stderr, "[h3] conn_recv error: %zd\n", done);
            connections_.erase(it);
            return;
        }

        if(quiche_conn_is_established(conn.qconn) && !conn.h3_conn){
            // Initialize HTTP/3 layer
            quiche_h3_config* h3cfg = quiche_h3_config_new();
            conn.h3_conn = quiche_h3_conn_new_with_transport(
                conn.qconn, h3cfg);
            quiche_h3_config_free(h3cfg);
        }

        process_h3_events(conn, cid_key);
        flush_egress(conn, from, from_len);
    }

    // Inject Alt-Svc header into HTTP/1.1 and HTTP/2 responses
    // so browsers discover and use HTTP/3 on next request
    static void inject_alt_svc(Response& resp, uint16_t port=443){
        resp.headers.set("Alt-Svc",
            "h3=\":" + std::to_string(port) + "\"; ma=86400");
    }

private:
    struct QuicConn {
        quiche_conn*    qconn{nullptr};
        quiche_h3_conn* h3_conn{nullptr};
        struct sockaddr_storage local_addr{};
        socklen_t local_addr_len{};
        // In-progress request streams
        std::unordered_map<uint64_t, Request> streams;
    };

    int                 udp_fd_;
    quiche_config*      quiche_cfg_{nullptr};
    H3RequestCallback   on_request_;
    std::unordered_map<std::string, QuicConn> connections_;

    void accept_new(const uint8_t* buf, size_t len,
                    const uint8_t* scid, size_t scid_len,
                    const uint8_t* dcid, size_t dcid_len,
                    const uint8_t* token, size_t token_len,
                    uint32_t version,
                    const struct sockaddr* from, socklen_t from_len){
        // Validate or mint token (address validation)
        uint8_t odcid[QUICHE_MAX_CONN_ID_LEN];
        size_t  odcid_len = sizeof(odcid);

        if(token_len == 0){
            // Send retry with token
            uint8_t retry[1200];
            ssize_t rlen = quiche_retry(scid, scid_len, dcid, dcid_len,
                                         dcid, dcid_len,  // new scid = dcid
                                         version, retry, sizeof(retry));
            if(rlen > 0)
                sendto(udp_fd_, retry, (size_t)rlen, 0, from, from_len);
            return;
        }

        // Accept connection
        uint8_t new_cid[QUICHE_MAX_CONN_ID_LEN];
        size_t  new_cid_len = sizeof(new_cid);
        // Use dcid as connection ID
        memcpy(new_cid, dcid, dcid_len);
        new_cid_len = dcid_len;

        struct sockaddr_storage local{};
        socklen_t local_len = sizeof(local);
        getsockname(udp_fd_, (struct sockaddr*)&local, &local_len);

        quiche_conn* qconn = quiche_accept(
            new_cid, new_cid_len,
            odcid_len > 0 ? odcid : nullptr,
            odcid_len,
            (struct sockaddr*)&local, local_len,
            from, from_len,
            quiche_cfg_);

        if(!qconn){
            fprintf(stderr, "[h3] quiche_accept failed\n");
            return;
        }

        std::string cid_key((char*)new_cid, new_cid_len);
        QuicConn& conn = connections_[cid_key];
        conn.qconn = qconn;
        memcpy(&conn.local_addr, &local, local_len);
        conn.local_addr_len = local_len;

        // Feed the initial packet
        quiche_recv_info ri{from, from_len,
            (struct sockaddr*)&local, local_len};
        quiche_conn_recv(qconn, (uint8_t*)buf, len, &ri);

        fprintf(stderr, "[h3] New QUIC connection accepted\n");
    }

    void process_h3_events(QuicConn& conn, const std::string& cid){
        if(!conn.h3_conn) return;

        quiche_h3_event* ev;
        while(true){
            int64_t stream_id = quiche_h3_conn_poll(
                conn.h3_conn, conn.qconn, &ev);
            if(stream_id < 0) break;

            switch(quiche_h3_event_type(ev)){
            case QUICHE_H3_EVENT_HEADERS: {
                // New request stream
                Request& req = conn.streams[(uint64_t)stream_id];
                req.is_h2 = true;  // HTTP/3 uses same request model
                req.h2_stream_id = (int32_t)stream_id;
                req.version = HttpVersion::HTTP30;

                quiche_h3_event_for_each_header(ev,
                    [](uint8_t* name, size_t nlen,
                       uint8_t* value, size_t vlen,
                       void* argp) -> int {
                        auto* r = (Request*)argp;
                        std::string k((char*)name, nlen);
                        std::string v((char*)value, vlen);
                        if(k==":method")    r->method=method_parse(v);
                        else if(k==":path"){
                            auto q=v.find('?');
                            if(q!=std::string::npos){r->path=v.substr(0,q);r->query=v.substr(q+1);}
                            else r->path=v;
                        }
                        else if(k==":authority") r->host=v;
                        else if(k==":scheme")    r->scheme=v;
                        else r->headers.set(k,v);
                        return 0;
                    }, &req);
                break;
            }
            case QUICHE_H3_EVENT_DATA: {
                // Request body data
                auto it = conn.streams.find((uint64_t)stream_id);
                if(it!=conn.streams.end()){
                    uint8_t tmp[65536];
                    ssize_t n;
                    while((n=quiche_h3_recv_body(conn.h3_conn, conn.qconn,
                            (uint64_t)stream_id, tmp, sizeof(tmp)))>0)
                        it->second.body.append((char*)tmp,(size_t)n);
                }
                break;
            }
            case QUICHE_H3_EVENT_FINISHED: {
                // Request complete
                auto sit = conn.streams.find((uint64_t)stream_id);
                if(sit!=conn.streams.end()){
                    Request req = std::move(sit->second);
                    conn.streams.erase(sit);
                    uint64_t sid = (uint64_t)stream_id;

                    on_request_(std::move(req),
                        [this, &conn, sid](Response resp){
                            send_h3_response(conn, sid, resp);
                        });
                }
                break;
            }
            default: break;
            }
            quiche_h3_event_free(ev);
        }
    }

    void send_h3_response(QuicConn& conn, uint64_t stream_id,
                           const Response& resp){
        std::vector<quiche_h3_header> hdrs;
        auto status_str = std::to_string(resp.status);
        hdrs.push_back({
            (uint8_t*)":status", 7,
            (uint8_t*)status_str.c_str(), status_str.size()
        });
        for(auto&[k,v]:resp.headers.items){
            if(ci_eq(k,"Connection")||ci_eq(k,"Transfer-Encoding")) continue;
            std::string lk=k; for(char&c:lk) c=(char)tolower((unsigned char)c);
            hdrs.push_back({(uint8_t*)lk.data(),lk.size(),
                             (uint8_t*)v.data(),v.size()});
        }
        quiche_h3_send_response(conn.h3_conn, conn.qconn,
                                  stream_id, hdrs.data(), hdrs.size(),
                                  resp.body.empty());
        if(!resp.body.empty()){
            quiche_h3_send_body(conn.h3_conn, conn.qconn, stream_id,
                                 (uint8_t*)resp.body.data(), resp.body.size(),
                                 true);
        }
    }

    void send_version_negotiation(const uint8_t* scid, size_t scid_len,
                                   const uint8_t* dcid, size_t dcid_len,
                                   const struct sockaddr* to, socklen_t to_len){
        uint8_t buf[1200];
        ssize_t len = quiche_negotiate_version(scid, scid_len, dcid, dcid_len,
                                                buf, sizeof(buf));
        if(len > 0) sendto(udp_fd_, buf, (size_t)len, 0, to, to_len);
    }

    void flush_egress(QuicConn& conn,
                       const struct sockaddr* to, socklen_t to_len){
        uint8_t out[1350];
        quiche_send_info si;
        while(true){
            ssize_t n = quiche_conn_send(conn.qconn, out, sizeof(out), &si);
            if(n == QUICHE_ERR_DONE) break;
            if(n < 0) break;
            sendto(udp_fd_, out, (size_t)n, 0, to, to_len);
        }
    }

#else
    // ── HTTP/3 stub ────────────────────────────────────────────────────────────
public:
    H3Handler(int, const Config&, H3RequestCallback){
        fprintf(stderr, "[h3] quiche not available — HTTP/3 disabled\n"
                        "     Build quiche and set QUICHE_DIR, then rebuild with -DHAVE_QUICHE\n");
    }
    void receive(const uint8_t*, size_t, const struct sockaddr*, socklen_t){}

    static void inject_alt_svc(Response& resp, uint16_t port=443){
        resp.headers.set("Alt-Svc",
            "h3=\":" + std::to_string(port) + "\"; ma=86400");
    }

private:
    H3RequestCallback on_request_;
#endif
};
