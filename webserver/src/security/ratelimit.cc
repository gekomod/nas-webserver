#pragma once
// ─────────────────────────────────────────────────────────────────────────────
//  ratelimit.cc  —  token bucket rate limiter (per-worker, lock-free)
// ─────────────────────────────────────────────────────────────────────────────
#include "../../include/np_types.hh"
#include <unordered_map>
#include <ctime>
#include <cstdio>
#include <sstream>

struct Bucket {
    double  tokens;
    double  rate;        // tokens/sec
    double  burst;
    int64_t last_ms;
    bool    blocked{false};
    int64_t blocked_until_ms{0};
    int     active_conns{0};
    uint64_t total{0},rejected{0};
};

class RateLimiter {
public:
    struct Config {
        double rate{200.0/60.0};  // convert req/min → tokens/sec
        double burst{50.0};
        int    max_conns{0};
        int    block_sec{300};
    };

    explicit RateLimiter(Config cfg):cfg_(cfg){}

    // Returns true → BLOCK. Sets retry_after_ms.
    bool check(const std::string& ip, int64_t* retry_after_ms=nullptr){
        auto& b=get(ip);
        int64_t now=now_ms();
        if(b.blocked){
            if(now<b.blocked_until_ms){
                if(retry_after_ms) *retry_after_ms=b.blocked_until_ms-now;
                b.rejected++; return true;
            }
            b.blocked=false; b.tokens=cfg_.burst;
        }
        double elapsed=(now-b.last_ms)/1000.0;
        b.tokens=std::min(b.burst,b.tokens+b.rate*elapsed);
        b.last_ms=now;
        if(b.tokens<1.0){
            if(retry_after_ms)
                *retry_after_ms=(int64_t)((1.0-b.tokens)/b.rate*1000);
            b.rejected++;
            if(b.tokens<-b.burst*2){
                b.blocked=true;
                b.blocked_until_ms=now+cfg_.block_sec*1000LL;
                fprintf(stderr,"[rl] IP %s blocked for %ds\n",
                        ip.c_str(),cfg_.block_sec);
            }
            return true;
        }
        b.tokens-=1.0; b.total++; return false;
    }

    bool conn_add(const std::string& ip){
        if(cfg_.max_conns<=0) return false;
        auto& b=get(ip);
        if(b.active_conns>=cfg_.max_conns) return true;
        b.active_conns++; return false;
    }
    void conn_remove(const std::string& ip){
        auto it=table_.find(ip);
        if(it!=table_.end()&&it->second.active_conns>0)
            it->second.active_conns--;
    }

    std::string stats_json() const {
        uint64_t total=0,rejected=0,blocked=0;
        for(auto&[ip,b]:table_){total+=b.total;rejected+=b.rejected;if(b.blocked)blocked++;}
        char buf[256];
        snprintf(buf,sizeof(buf),
            "{\"tracked_ips\":%zu,\"total_req\":%llu,"
            "\"rejected\":%llu,\"blocked_ips\":%llu}",
            table_.size(),(unsigned long long)total,
            (unsigned long long)rejected,(unsigned long long)blocked);
        return buf;
    }

private:
    Bucket& get(const std::string& ip){
        auto [it,ins]=table_.emplace(ip,Bucket{});
        if(ins){it->second={cfg_.burst,cfg_.rate,cfg_.burst,now_ms()};}
        return it->second;
    }
    std::unordered_map<std::string,Bucket> table_;
    Config cfg_;
};
