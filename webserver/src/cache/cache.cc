#pragma once
// ─────────────────────────────────────────────────────────────────────────────
//  cache.cc  —  HTTP response cache (RFC 7234)
//  LRU hash map, per-worker (zero locking on read path)
// ─────────────────────────────────────────────────────────────────────────────
#include "../../include/np_types.hh"
#include <atomic>

// Global cache stats — defined here as weak symbols so test_cache.cc gets them
// server.cc declares them before #include-ing this file, so they're shared there
#ifndef NAS_WEB_SERVER_CC
static std::atomic<uint64_t> g_stat_cache_hit{0};
static std::atomic<uint64_t> g_stat_cache_miss{0};
static std::atomic<uint64_t> g_stat_cache_entries{0};
#endif
#include <list>
#include <unordered_map>
#include <ctime>
#include <cstdio>
#include <sstream>

struct CacheEntry {
    std::string key;
    std::string serialized;   // ready-to-send HTTP/1.1 response
    int         status{};
    time_t      created{};
    time_t      expires{};
    std::string etag;
    std::string last_modified;
    size_t      size{};
};

class ResponseCache {
public:
    struct Stats {
        uint64_t hits{},misses{},evictions{},stores{},bytes_stored{};
        double hit_ratio() const {
            auto t=hits+misses; return t?(double)hits/t:0.0;
        }
    };

    ResponseCache(int max_entries, int default_ttl)
        : max_(max_entries), ttl_(default_ttl) {}

    static std::string make_key(const Request& req){
        return std::string(method_str(req.method))
             + ':' + req.host + req.path
             + (req.query.empty() ? "" : '?'+req.query);
    }

    const CacheEntry* get(const std::string& key){
        auto it=map_.find(key);
        if(it==map_.end()){
            stats_.misses++;
            g_stat_cache_miss.fetch_add(1, std::memory_order_relaxed);
            return nullptr;
        }
        auto& lit=it->second;
        if(time(nullptr)>lit->second.expires){
            evict(it); stats_.misses++;
            g_stat_cache_miss.fetch_add(1, std::memory_order_relaxed);
            return nullptr;
        }
        lru_.splice(lru_.begin(),lru_,lit);
        stats_.hits++;
        g_stat_cache_hit.fetch_add(1, std::memory_order_relaxed);
        return &lit->second;
    }

    bool put(const std::string& key, const Response& resp,
              const Request& req, int ttl_override=0){
        bool force = (ttl_override > 0);
        if(!is_cacheable(resp,req,force)) return false;
        int ttl=ttl_override>0?ttl_override:get_ttl(resp);
        if(ttl <= 0) return false; // nothing to cache without a TTL
        while((int)map_.size()>=max_) evict_lru();

        auto it=map_.find(key);
        if(it!=map_.end()){lru_.erase(it->second);map_.erase(it);}

        CacheEntry e;
        e.key     =key;
        e.status  =resp.status;
        e.created =time(nullptr);
        e.expires =e.created+ttl;
        e.etag    =std::string(resp.headers.get("ETag"));
        e.last_modified=std::string(resp.headers.get("Last-Modified"));

        Response cr=resp;
        cr.headers.set("X-Cache","HIT");
        cr.headers.set("Age","0");
        cr.headers.remove("Connection");
        cr.headers.remove("Transfer-Encoding");
        e.serialized=cr.serialize_h1();
        e.size=e.serialized.size();

        lru_.push_front({key,std::move(e)});
        map_[key]=lru_.begin();
        stats_.stores++;
        stats_.bytes_stored+=lru_.begin()->second.size;
        g_stat_cache_entries.store(map_.size(), std::memory_order_relaxed);
        return true;
    }

    bool check_conditional(const CacheEntry& e, const Request& req){
        auto inm=req.headers.get("If-None-Match");
        if(!inm.empty()&&!e.etag.empty()&&inm==e.etag) return true;
        return false;
    }

    void invalidate(const std::string& key){
        auto it=map_.find(key);
        if(it!=map_.end()) evict(it);
    }

    void purge_expired(){
        time_t now=time(nullptr);
        for(auto it=map_.begin();it!=map_.end();){
            if(it->second->second.expires<now){
                lru_.erase(it->second);
                it=map_.erase(it);
                stats_.evictions++;
            } else ++it;
        }
    }

    Stats stats() const { return stats_; }
    size_t size() const { return map_.size(); }
    int max_entries() const { return max_; }

    void flush() {
        lru_.clear();
        map_.clear();
        stats_ = Stats{};
        g_stat_cache_entries.store(0, std::memory_order_relaxed);
    }

    // Iterate entries for admin panel (key, size_bytes, ttl_remaining_sec, hits)
    template<typename F>
    void each_entry(F&& fn) const {
        time_t now = time(nullptr);
        int count = 0;
        for(auto& [key, e] : lru_) {
            if(++count > 50) break; // max 50 entries in panel
            int ttl_left = (int)std::max((time_t)0, e.expires - now);
            fn(key, e.size, ttl_left, (uint64_t)0);
        }
    }

    std::string stats_json() const {
        char buf[256];
        snprintf(buf,sizeof(buf),
            "{\"entries\":%zu,\"max\":%d,\"hits\":%llu,"
            "\"misses\":%llu,\"evictions\":%llu,"
            "\"bytes_stored\":%llu,\"hit_ratio\":%.3f}",
            map_.size(),max_,
            (unsigned long long)stats_.hits,
            (unsigned long long)stats_.misses,
            (unsigned long long)stats_.evictions,
            (unsigned long long)stats_.bytes_stored,
            stats_.hit_ratio());
        return buf;
    }

private:
    static bool is_cacheable(const Response& resp, const Request& req, bool force=false){
        if(req.method!=Method::GET&&req.method!=Method::HEAD) return false;
        int s=resp.status;
        if(s!=200&&s!=203&&s!=204&&s!=206&&s!=301&&s!=404&&s!=410) return false;
        auto cc=resp.headers.get("Cache-Control");
        if(!cc.empty()){
            if(cc.find("no-store")!=std::string_view::npos)  return false; // always respect no-store
            if(!force && cc.find("private")!=std::string_view::npos)  return false;
            if(!force && cc.find("no-cache")!=std::string_view::npos) return false;
        }
        return true;
    }

    int get_ttl(const Response& resp) const {
        auto cc=resp.headers.get("Cache-Control");
        if(!cc.empty()){
            auto sm=cc.find("s-maxage=");
            if(sm!=std::string_view::npos) return std::stoi(std::string(cc.substr(sm+9)));
            auto mx=cc.find("max-age=");
            if(mx!=std::string_view::npos) return std::stoi(std::string(cc.substr(mx+8)));
        }
        return ttl_;
    }

    using LRU = std::list<std::pair<std::string,CacheEntry>>;
    using Map = std::unordered_map<std::string,LRU::iterator>;

    void evict(Map::iterator it){
        stats_.bytes_stored -= it->second->second.size;
        lru_.erase(it->second); map_.erase(it); stats_.evictions++;
    }
    void evict_lru(){
        auto it=map_.find(lru_.back().first);
        if(it!=map_.end()) evict(it);
    }

    LRU   lru_;
    Map   map_;
    int   max_,ttl_;
    Stats stats_;
};
