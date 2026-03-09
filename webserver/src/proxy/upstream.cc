#pragma once
// ─────────────────────────────────────────────────────────────────────────────
//  upstream.cc  —  Load balancer: round-robin / least-conn / weighted / ip-hash
//                  + async health checks + per-backend stats
// ─────────────────────────────────────────────────────────────────────────────
#include "../../include/np_types.hh"
#include "../../include/np_config.hh"
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <thread>
#include <mutex>
#include <atomic>
#include <memory>
#include <vector>
#include <chrono>
#include <cstring>
#include <cstdio>
#include <functional>

enum class UpState { Healthy, Degraded, Down };

struct BackendStats {
    std::atomic<uint64_t> req_total{0};
    std::atomic<uint64_t> req_err{0};
    std::atomic<uint64_t> latency_sum_ms{0};  // for avg
    std::atomic<int>      active{0};
    std::atomic<int>      fails{0};
    int64_t               last_fail_ms{0};
    int64_t               last_ok_ms{0};
};

struct PoolConn {
    int    fd{-1};
    bool   in_use{false};
    int64_t last_used_ms{0};
    int    requests{0};
};

class UpstreamPool {
public:
    const UpstreamServer cfg;
    std::atomic<UpState> state{UpState::Healthy};
    BackendStats         stats;

    explicit UpstreamPool(const UpstreamServer& c):cfg(c){}

    PoolConn* acquire(){
        std::lock_guard lg(mu_);
        for(auto& c:pool_){
            if(!c.in_use&&c.fd>=0){
                char probe; int r=recv(c.fd,&probe,1,MSG_PEEK|MSG_DONTWAIT);
                if(r==0){close(c.fd);c.fd=connect_new();if(c.fd<0)continue;}
                c.in_use=true; c.last_used_ms=now_ms();
                stats.active++; return &c;
            }
        }
        int fd=connect_new(); if(fd<0) return nullptr;
        pool_.push_back({fd,true,now_ms(),0});
        stats.active++; return &pool_.back();
    }

    void release(PoolConn* c, bool ok, int64_t latency_ms=0){
        std::lock_guard lg(mu_);
        stats.active--; c->requests++; c->in_use=false;
        stats.req_total++;
        if(ok){
            stats.latency_sum_ms.fetch_add((uint64_t)latency_ms);
            stats.last_ok_ms = now_ms();
        } else {
            stats.req_err++;
            mark_fail();
        }
        if(!ok||c->requests>2000||c->fd<0){
            if(c->fd>=0){close(c->fd);c->fd=-1;}
        }
    }

    void mark_fail(){
        int f = ++stats.fails;
        stats.last_fail_ms = now_ms();
        if(f >= cfg.max_fails) state.store(UpState::Down);
        else state.store(UpState::Degraded);
    }
    void mark_ok(){
        stats.fails.store(0);
        stats.last_ok_ms = now_ms();
        state.store(UpState::Healthy);
    }

    int active_conns() const { return stats.active.load(); }

    std::string json() const {
        static const char* sn[]={"healthy","degraded","down"};
        uint64_t req  = stats.req_total.load();
        uint64_t err  = stats.req_err.load();
        uint64_t lsum = stats.latency_sum_ms.load();
        uint64_t avg_lat = req > 0 ? lsum/req : 0;
        char buf[512];
        snprintf(buf,sizeof(buf),
            "{\"host\":\"%s\",\"port\":%d,\"state\":\"%s\","
            "\"active\":%d,\"req\":%llu,\"err\":%llu,"
            "\"avg_lat_ms\":%llu,\"weight\":%d,\"backup\":%s}",
            cfg.host.c_str(), cfg.port,
            sn[(int)state.load()],
            stats.active.load(),
            (unsigned long long)req,
            (unsigned long long)err,
            (unsigned long long)avg_lat,
            cfg.weight,
            cfg.backup ? "true" : "false");
        return buf;
    }

private:
    std::mutex mu_;
    std::vector<PoolConn> pool_;

    int connect_new(){
        int fd=socket(AF_INET,SOCK_STREAM,0);
        if(fd<0) return -1;
        int one=1;
        setsockopt(fd,IPPROTO_TCP,TCP_NODELAY,&one,sizeof(one));
        setsockopt(fd,SOL_SOCKET,SO_KEEPALIVE,&one,sizeof(one));
        struct timeval tv{5,0};
        setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&tv,sizeof(tv));
        struct sockaddr_in addr{}; addr.sin_family=AF_INET;
        addr.sin_port=htons(cfg.port);
        inet_pton(AF_INET,cfg.host.c_str(),&addr.sin_addr);
        if(connect(fd,(sockaddr*)&addr,sizeof(addr))<0){close(fd);mark_fail();return -1;}
        int fl=fcntl(fd,F_GETFL,0); fcntl(fd,F_SETFL,fl|O_NONBLOCK);
        return fd;
    }
};

class UpstreamGroup {
public:
    explicit UpstreamGroup(const UpstreamConfig& cfg):cfg_(cfg){
        for(auto& s:cfg.servers) pools_.push_back(std::make_unique<UpstreamPool>(s));
        if(cfg.hc_enabled&&!pools_.empty()){
            hc_run_=true;
            hc_thread_=std::thread(&UpstreamGroup::hc_loop,this);
        }
    }
    ~UpstreamGroup(){
        hc_run_=false;
        if(hc_thread_.joinable()) hc_thread_.join();
    }

    // Pick backend using configured strategy
    UpstreamPool* pick(const std::string& client_ip = ""){
        // Collect healthy pools (and backup if all down)
        std::vector<UpstreamPool*> alive, backup;
        for(auto& p:pools_){
            if(p->state.load() == UpState::Down) continue;
            if(p->cfg.backup) backup.push_back(p.get());
            else alive.push_back(p.get());
        }
        if(alive.empty()) alive = backup; // failover to backup servers
        if(alive.empty()) return nullptr;

        switch(cfg_.strategy){
            case LBStrategy::RoundRobin:
                return alive[rr_idx_.fetch_add(1) % alive.size()];

            case LBStrategy::WeightedRR: {
                // Weighted round-robin via expanded rotation
                int total_w = 0;
                for(auto* p : alive) total_w += p->cfg.weight;
                if(total_w <= 0) return alive[0];
                int slot = (int)(rr_idx_.fetch_add(1) % total_w);
                for(auto* p : alive){
                    slot -= p->cfg.weight;
                    if(slot < 0) return p;
                }
                return alive.back();
            }

            case LBStrategy::IPHash: {
                // Consistent hash: same IP → same backend (sticky without cookie)
                size_t h = std::hash<std::string>{}(client_ip);
                return alive[h % alive.size()];
            }

            case LBStrategy::LeastConn:
            default: {
                UpstreamPool* best = alive[0];
                for(auto* p : alive)
                    if(p->active_conns() < best->active_conns()) best = p;
                return best;
            }
        }
    }

    // Override: temporarily disable/enable a backend from admin panel
    void set_backend_state(const std::string& host, int port, bool enabled){
        for(auto& p : pools_){
            if(p->cfg.host == host && p->cfg.port == port){
                p->state.store(enabled ? UpState::Healthy : UpState::Down);
                break;
            }
        }
    }

    std::string status_json() const {
        static const char* strat[]={"least_conn","round_robin","weighted_rr","ip_hash"};
        std::string out = "{\"name\":\"" + cfg_.name +
            "\",\"strategy\":\"" + strat[(int)cfg_.strategy] +
            "\",\"hc_enabled\":" + (cfg_.hc_enabled?"true":"false") +
            ",\"hc_path\":\"" + cfg_.hc_path + "\"" +
            ",\"servers\":[";
        for(size_t i=0;i<pools_.size();i++){
            if(i) out+=",";
            out += pools_[i]->json();
        }
        return out + "]}";
    }

    size_t server_count() const { return pools_.size(); }

private:
    const UpstreamConfig cfg_;
    std::vector<std::unique_ptr<UpstreamPool>> pools_;
    std::thread hc_thread_;
    std::atomic<bool> hc_run_{false};
    std::atomic<uint64_t> rr_idx_{0};

    void hc_loop(){
        while(hc_run_){
            std::this_thread::sleep_for(std::chrono::seconds(cfg_.hc_interval));
            if(!hc_run_) break;
            for(auto& pool : pools_){
                // Skip recently failed (respect fail_timeout)
                if(pool->state.load() == UpState::Down){
                    int64_t elapsed = (now_ms() - pool->stats.last_fail_ms) / 1000;
                    if(elapsed < pool->cfg.fail_timeout) continue;
                }
                bool ok = probe_http(pool->cfg.host, pool->cfg.port,
                                     cfg_.hc_path, cfg_.hc_expected_status);
                if(ok){
                    if(pool->state.load() != UpState::Healthy){
                        NW_INFO("upstream", "Backend %s:%d recovered",
                                pool->cfg.host.c_str(), pool->cfg.port);
                    }
                    pool->mark_ok();
                } else {
                    if(pool->state.load() == UpState::Healthy){
                        NW_WARN("upstream", "Backend %s:%d health check FAILED",
                                pool->cfg.host.c_str(), pool->cfg.port);
                    }
                    pool->mark_fail();
                }
            }
        }
    }

    static bool probe_http(const std::string& host, int port,
                           const std::string& path, int expected){
        int fd = socket(AF_INET,SOCK_STREAM,0);
        if(fd < 0) return false;
        struct timeval tv{3,0};
        setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));
        setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&tv,sizeof(tv));
        struct sockaddr_in addr{}; addr.sin_family=AF_INET;
        addr.sin_port = htons(port);
        inet_pton(AF_INET,host.c_str(),&addr.sin_addr);
        bool ok = false;
        if(connect(fd,(sockaddr*)&addr,sizeof(addr))==0){
            std::string req = "GET " + path + " HTTP/1.0\r\nHost: " + host +
                              "\r\nConnection: close\r\n\r\n";
            if(send(fd,req.c_str(),req.size(),0) > 0){
                char resp[128]{}; int n=recv(fd,resp,127,0);
                if(n > 0){
                    int status = 0;
                    sscanf(resp,"HTTP/%*s %d",&status);
                    ok = (expected > 0) ? (status == expected) : (status >= 200 && status < 400);
                }
            }
        }
        close(fd);
        return ok;
    }
};
