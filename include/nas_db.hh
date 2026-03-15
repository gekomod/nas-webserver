#pragma once
// ── nas_db.hh — SQLite3-backed persistence for blacklist + ban events ─────────
//
// Replaces:
//   /var/lib/nas-web/blacklist.txt   → table: blacklist
//   /var/lib/nas-web/recent_bans.txt → table: ban_events
//
// Design:
//   • Single WAL-mode database at /var/lib/nas-web/nas-web.db
//   • One global NasDb instance (g_db) opened once at startup
//   • All writes are synchronous but fast — WAL mode, no fsync per write
//   • Thread-safe: all public methods lock a single mutex
//   • Migration: on first open, imports existing .txt files if present
//
// Usage:
//   g_db.open("/var/lib/nas-web/nas-web.db");
//   g_db.blacklist_add("1.2.3.4");
//   g_db.blacklist_remove("1.2.3.4");
//   auto ips = g_db.blacklist_load();   // returns unordered_set<string>
//   g_db.ban_insert({ip, reason, detail, ts});
//   auto bans = g_db.ban_load_recent(200);
// ─────────────────────────────────────────────────────────────────────────────

#ifdef HAVE_SQLITE

#include <sqlite3.h>  // vendor/sqlite/ added to include path by CMakeLists
#include <string>
#include <vector>
#include <unordered_set>
#include <mutex>
#include <ctime>
#include <cstdio>
#include <filesystem>

// Forward-declare AutoBan::BanEvent to avoid circular include.
// We use a plain struct here and map to/from AutoBan::BanEvent in server.cc.
struct DbBanEvent {
    std::string ip;
    std::string reason;
    std::string detail;
    time_t      ts{0};
};

struct NasDb {
    // ── Open / init ───────────────────────────────────────────────────────────
    bool open(const std::string& path) {
        std::lock_guard<std::mutex> lk(mu_);
        std::filesystem::create_directories(
            std::filesystem::path(path).parent_path());

        if(sqlite3_open(path.c_str(), &db_) != SQLITE_OK) {
            log_err("sqlite3_open", path);
            db_ = nullptr;
            return false;
        }

        // WAL mode: concurrent readers, fast writes, no full fsync per commit
        exec("PRAGMA journal_mode=WAL");
        exec("PRAGMA synchronous=NORMAL");
        exec("PRAGMA foreign_keys=ON");

        // Schema
        exec(R"(
            CREATE TABLE IF NOT EXISTS blacklist (
                ip   TEXT PRIMARY KEY NOT NULL,
                ts   INTEGER NOT NULL DEFAULT (strftime('%s','now'))
            );
            CREATE TABLE IF NOT EXISTS ban_events (
                id     INTEGER PRIMARY KEY AUTOINCREMENT,
                ts     INTEGER NOT NULL,
                ip     TEXT    NOT NULL,
                reason TEXT    NOT NULL,
                detail TEXT    NOT NULL DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_ban_ts ON ban_events(ts DESC);
            CREATE INDEX IF NOT EXISTS idx_ban_ip ON ban_events(ip);
        )");

        db_path_ = path;
        return true;
    }

    bool is_open() const { return db_ != nullptr; }

    void close() {
        std::lock_guard<std::mutex> lk(mu_);
        if(db_) { sqlite3_close(db_); db_ = nullptr; }
    }

    // ── Blacklist ─────────────────────────────────────────────────────────────
    bool blacklist_add(const std::string& ip) {
        std::lock_guard<std::mutex> lk(mu_);
        if(!db_) return false;
        const char* sql = "INSERT OR IGNORE INTO blacklist(ip) VALUES(?)";
        sqlite3_stmt* st = prepare(sql);
        if(!st) return false;
        sqlite3_bind_text(st, 1, ip.c_str(), -1, SQLITE_STATIC);
        bool ok = (sqlite3_step(st) == SQLITE_DONE);
        sqlite3_finalize(st);
        return ok;
    }

    bool blacklist_remove(const std::string& ip) {
        std::lock_guard<std::mutex> lk(mu_);
        if(!db_) return false;
        const char* sql = "DELETE FROM blacklist WHERE ip = ?";
        sqlite3_stmt* st = prepare(sql);
        if(!st) return false;
        sqlite3_bind_text(st, 1, ip.c_str(), -1, SQLITE_STATIC);
        bool ok = (sqlite3_step(st) == SQLITE_DONE);
        sqlite3_finalize(st);
        return ok;
    }

    bool blacklist_contains(const std::string& ip) {
        std::lock_guard<std::mutex> lk(mu_);
        if(!db_) return false;
        const char* sql = "SELECT 1 FROM blacklist WHERE ip = ? LIMIT 1";
        sqlite3_stmt* st = prepare(sql);
        if(!st) return false;
        sqlite3_bind_text(st, 1, ip.c_str(), -1, SQLITE_STATIC);
        bool found = (sqlite3_step(st) == SQLITE_ROW);
        sqlite3_finalize(st);
        return found;
    }

    std::unordered_set<std::string> blacklist_load() {
        std::lock_guard<std::mutex> lk(mu_);
        std::unordered_set<std::string> result;
        if(!db_) return result;
        sqlite3_stmt* st = prepare("SELECT ip FROM blacklist");
        if(!st) return result;
        while(sqlite3_step(st) == SQLITE_ROW) {
            const char* ip = (const char*)sqlite3_column_text(st, 0);
            if(ip) result.insert(ip);
        }
        sqlite3_finalize(st);
        return result;
    }

    size_t blacklist_count() {
        std::lock_guard<std::mutex> lk(mu_);
        if(!db_) return 0;
        sqlite3_stmt* st = prepare("SELECT COUNT(*) FROM blacklist");
        if(!st) return 0;
        size_t n = 0;
        if(sqlite3_step(st) == SQLITE_ROW)
            n = (size_t)sqlite3_column_int64(st, 0);
        sqlite3_finalize(st);
        return n;
    }

    // ── Ban events ────────────────────────────────────────────────────────────
    bool ban_insert(const DbBanEvent& ev) {
        std::lock_guard<std::mutex> lk(mu_);
        if(!db_) return false;
        const char* sql =
            "INSERT INTO ban_events(ts,ip,reason,detail) VALUES(?,?,?,?)";
        sqlite3_stmt* st = prepare(sql);
        if(!st) return false;
        sqlite3_bind_int64(st, 1, (sqlite3_int64)ev.ts);
        sqlite3_bind_text (st, 2, ev.ip.c_str(),     -1, SQLITE_STATIC);
        sqlite3_bind_text (st, 3, ev.reason.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text (st, 4, ev.detail.c_str(), -1, SQLITE_STATIC);
        bool ok = (sqlite3_step(st) == SQLITE_DONE);
        sqlite3_finalize(st);
        // Keep table bounded — delete oldest beyond limit
        prune_bans_nolock(2000);
        return ok;
    }

    std::vector<DbBanEvent> ban_load_recent(int limit = 200) {
        std::lock_guard<std::mutex> lk(mu_);
        std::vector<DbBanEvent> result;
        if(!db_) return result;
        const char* sql =
            "SELECT ts,ip,reason,detail FROM ban_events "
            "ORDER BY ts DESC LIMIT ?";
        sqlite3_stmt* st = prepare(sql);
        if(!st) return result;
        sqlite3_bind_int(st, 1, limit);
        while(sqlite3_step(st) == SQLITE_ROW) {
            DbBanEvent ev;
            ev.ts     = (time_t)sqlite3_column_int64(st, 0);
            const char* ip  = (const char*)sqlite3_column_text(st, 1);
            const char* rsn = (const char*)sqlite3_column_text(st, 2);
            const char* det = (const char*)sqlite3_column_text(st, 3);
            if(ip)  ev.ip     = ip;
            if(rsn) ev.reason = rsn;
            if(det) ev.detail = det;
            result.push_back(std::move(ev));
        }
        sqlite3_finalize(st);
        return result;
    }

    // ── Migration from .txt files ─────────────────────────────────────────────
    // Call once at startup AFTER open(). Safe to call even if files don't exist.
    void migrate_from_txt(const std::string& blacklist_txt,
                          const std::string& bans_txt) {
        // Blacklist
        FILE* f = fopen(blacklist_txt.c_str(), "r");
        if(f) {
            char buf[64];
            int imported = 0;
            while(fgets(buf, sizeof(buf), f)) {
                std::string ip(buf);
                while(!ip.empty() &&
                      (ip.back()=='\n'||ip.back()=='\r'||ip.back()==' '))
                    ip.pop_back();
                if(!ip.empty()) {
                    blacklist_add(ip);
                    imported++;
                }
            }
            fclose(f);
            if(imported > 0)
                fprintf(stderr, "[nas_db] Migrated %d IPs from %s\n",
                        imported, blacklist_txt.c_str());
        }

        // Ban events
        FILE* fb = fopen(bans_txt.c_str(), "r");
        if(fb) {
            char buf[512];
            int imported = 0;
            while(fgets(buf, sizeof(buf), fb)) {
                std::string line(buf);
                while(!line.empty() && (line.back()=='\n'||line.back()=='\r'))
                    line.pop_back();
                // Format: ts|ip|reason|detail
                auto p1 = line.find('|');
                auto p2 = line.find('|', p1+1);
                auto p3 = line.find('|', p2+1);
                if(p1==std::string::npos||p2==std::string::npos||
                   p3==std::string::npos) continue;
                DbBanEvent ev;
                try { ev.ts = (time_t)std::stoll(line.substr(0, p1)); }
                catch(...) { continue; }
                ev.ip     = line.substr(p1+1, p2-p1-1);
                ev.reason = line.substr(p2+1, p3-p2-1);
                ev.detail = line.substr(p3+1);
                ban_insert(ev);
                imported++;
            }
            fclose(fb);
            if(imported > 0)
                fprintf(stderr, "[nas_db] Migrated %d ban events from %s\n",
                        imported, bans_txt.c_str());
        }
    }

private:
    sqlite3*   db_{nullptr};
    std::mutex mu_;
    std::string db_path_;

    void exec(const char* sql) {
        char* err = nullptr;
        if(sqlite3_exec(db_, sql, nullptr, nullptr, &err) != SQLITE_OK) {
            fprintf(stderr, "[nas_db] SQL error: %s\n", err ? err : "?");
            sqlite3_free(err);
        }
    }

    sqlite3_stmt* prepare(const char* sql) {
        sqlite3_stmt* st = nullptr;
        if(sqlite3_prepare_v2(db_, sql, -1, &st, nullptr) != SQLITE_OK) {
            fprintf(stderr, "[nas_db] prepare error: %s — %s\n",
                    sqlite3_errmsg(db_), sql);
            return nullptr;
        }
        return st;
    }

    void log_err(const char* fn, const std::string& ctx) {
        fprintf(stderr, "[nas_db] %s(%s): %s\n",
                fn, ctx.c_str(), db_ ? sqlite3_errmsg(db_) : "no db");
    }

    void prune_bans_nolock(int keep) {
        // Called without locking — already inside a locked method
        const char* sql =
            "DELETE FROM ban_events WHERE id NOT IN "
            "(SELECT id FROM ban_events ORDER BY ts DESC LIMIT ?)";
        sqlite3_stmt* st = nullptr;
        if(sqlite3_prepare_v2(db_, sql, -1, &st, nullptr) != SQLITE_OK) return;
        sqlite3_bind_int(st, 1, keep);
        sqlite3_step(st);
        sqlite3_finalize(st);
    }
};

// Defined once in server.cc
#ifndef NAS_DB_IMPL
extern NasDb g_db;
#endif

#else // !HAVE_SQLITE
// Stub when compiled without SQLite — existing .txt code remains active
struct NasDb {
    bool open(const std::string&) { return false; }
    bool is_open() const { return false; }
    void close() {}
    bool blacklist_add(const std::string&) { return false; }
    bool blacklist_remove(const std::string&) { return false; }
    bool blacklist_contains(const std::string&) { return false; }
    std::unordered_set<std::string> blacklist_load() { return {}; }
    size_t blacklist_count() { return 0; }
    struct DbBanEvent {};
    bool ban_insert(const DbBanEvent&) { return false; }
    std::vector<DbBanEvent> ban_load_recent(int = 200) { return {}; }
    void migrate_from_txt(const std::string&, const std::string&) {}
};
#ifndef NAS_DB_IMPL
extern NasDb g_db;
#endif
#endif // HAVE_SQLITE
