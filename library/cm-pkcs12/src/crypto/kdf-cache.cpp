//  See kdf-cache.h.

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>
#include <unordered_map>

#include "kdf-cache.h"
#include "drbg.h"
#include "hmac.h"
#include "uapkic-errors.h"
#include "private-key.h"

namespace {

using Clock = std::chrono::steady_clock;

const size_t SECRET_LEN = 32;

struct Entry {
    ByteArray* dk;
    Clock::time_point used;
};

struct Config {
    bool enabled = false;
    bool debug = false;
    std::chrono::seconds ttl{43200};
    size_t max_entries = 5000;
    ByteArray* secret = nullptr;
};

struct Pending {
    bool set = false;
    std::string key;
    ByteArray* dk = nullptr;
};

std::once_flag g_once;
Config g_config;
std::mutex g_mutex;
std::unordered_map<std::string, Entry> g_entries;
std::atomic<unsigned long long> g_lookups{0};
std::atomic<unsigned long long> g_hits{0};

thread_local int t_proven = 0;
thread_local Pending t_pending;

unsigned long env_number(const char* name, unsigned long fallback) {
    const char* v = std::getenv(name);
    if (!v || !*v) return fallback;
    char* end = nullptr;
    unsigned long n = std::strtoul(v, &end, 10);
    return (end && *end == '\0') ? n : fallback;
}

void configure() {
    const char* dbg = std::getenv("UAPKI_KDF_CACHE_DEBUG");
    g_config.debug = dbg && std::strcmp(dbg, "1") == 0;
    const char* on = std::getenv("UAPKI_KDF_CACHE");
    if (on && std::strcmp(on, "0") == 0) return;
    g_config.ttl         = std::chrono::seconds(env_number("UAPKI_KDF_CACHE_TTL_S", 43200));
    g_config.max_entries = env_number("UAPKI_KDF_CACHE_MAX", 5000);
    if (g_config.max_entries == 0) return;
    ByteArray* secret = ba_alloc_by_len(SECRET_LEN);
    if (!secret || drbg_random(secret) != RET_OK) {
        ba_free_private(secret);
        std::fprintf(stderr, "[kdf-cache] off: no random secret\n");
        return;
    }
    g_config.secret  = secret;
    g_config.enabled = true;
}

bool enabled() {
    std::call_once(g_once, configure);
    return g_config.enabled;
}

void trace(const char* what, KdfCacheKind kind, uint8_t id, size_t iterations, size_t out_len) {
    std::call_once(g_once, configure);
    if (!g_config.debug) return;
    long long us = (long long)std::chrono::duration_cast<std::chrono::microseconds>(Clock::now().time_since_epoch()).count();
    std::fprintf(stderr, "[kdf-cache] %lld %s kind=%d id=%d iter=%zu len=%zu\n", us, what, (int)kind, (int)id, iterations, out_len);
}

ByteArray* copy_of(const ByteArray* ba) {
    return ba_alloc_from_uint8(ba_get_buf_const(ba), ba_get_len(ba));
}

void append_number(std::string& out, unsigned long long n) {
    for (int i = 0; i < 8; i++) out.push_back((char)((n >> (8 * i)) & 0xff));
}

//  The public key's entries: a kind byte no derivation uses.
const char SPKI_KIND = 'S';

//  HMAC-SHA-256(secret, bytes) appended to `out`: false when it can't be made.
bool append_hmac(std::string& out, const uint8_t* bytes, size_t len) {
    HmacCtx* ctx = hmac_alloc(HASH_ALG_SHA256);
    if (!ctx) return false;
    ByteArray* ba = ba_alloc_from_uint8(bytes, len);
    ByteArray* mac = nullptr;
    int ret = ba ? hmac_init(ctx, g_config.secret) : RET_MEMORY_ALLOC_ERROR;
    if (ret == RET_OK) ret = hmac_update(ctx, ba);
    if (ret == RET_OK) ret = hmac_final(ctx, &mac);
    hmac_free(ctx);
    ba_free_private(ba);
    if (ret != RET_OK || !mac) {
        ba_free(mac);
        return false;
    }
    out.append(reinterpret_cast<const char*>(ba_get_buf_const(mac)), ba_get_len(mac));
    ba_free(mac);
    return true;
}

//  The derivation's inputs, the password as HMAC-SHA-256(secret, password): "" when it can't be made.
std::string key_of(KdfCacheKind kind, uint8_t id, HashAlg hash_alg, const ByteArray* salt,
        size_t iterations, size_t out_len, const char* pass) {
    if (!salt || !pass) return std::string();

    std::string key;
    key.push_back((char)kind);
    key.push_back((char)id);
    append_number(key, (unsigned long long)hash_alg);
    append_number(key, (unsigned long long)iterations);
    append_number(key, (unsigned long long)out_len);
    append_number(key, (unsigned long long)ba_get_len(salt));
    key.append(reinterpret_cast<const char*>(ba_get_buf_const(salt)), ba_get_len(salt));
    if (!append_hmac(key, reinterpret_cast<const uint8_t*>(pass), std::strlen(pass))) return std::string();
    return key;
}

//  A private key's public-key entry: the kind byte, HMAC-SHA-256(secret, its bytes). "" when it can't be made.
std::string spki_key_of(const ByteArray* private_key_info) {
    std::string key(1, SPKI_KIND);
    if (!append_hmac(key, ba_get_buf_const(private_key_info), ba_get_len(private_key_info))) return std::string();
    return key;
}

//  g_mutex held.
void erase(std::unordered_map<std::string, Entry>::iterator it) {
    ba_free_private(it->second.dk);
    g_entries.erase(it);
}

//  g_mutex held: room for one more - the expired ones go, then the least recently used.
void make_room(Clock::time_point now) {
    if (g_entries.size() < g_config.max_entries) return;
    for (auto it = g_entries.begin(); it != g_entries.end();) {
        auto next = std::next(it);
        if (now - it->second.used > g_config.ttl) erase(it);
        it = next;
    }
    while (g_entries.size() >= g_config.max_entries) {
        auto oldest = g_entries.begin();
        for (auto it = g_entries.begin(); it != g_entries.end(); ++it) {
            if (it->second.used < oldest->second.used) oldest = it;
        }
        erase(oldest);
    }
}

//  The entry under `key`, copied, refreshed - nullptr when absent or expired (then dropped).
ByteArray* lookup(const std::string& key) {
    ByteArray* found = nullptr;
    Clock::time_point now = Clock::now();
    std::lock_guard<std::mutex> lock(g_mutex);
    auto it = g_entries.find(key);
    if (it != g_entries.end()) {
        if (now - it->second.used > g_config.ttl) {
            erase(it);
        }
        else {
            it->second.used = now;
            found = copy_of(it->second.dk);
        }
    }
    return found;
}

void store(const std::string& key, const ByteArray* dk) {
    ByteArray* value = copy_of(dk);
    if (!value) return;
    Clock::time_point now = Clock::now();
    std::lock_guard<std::mutex> lock(g_mutex);
    auto it = g_entries.find(key);
    if (it != g_entries.end()) {
        it->second.used = now;
        ba_free_private(value);
        return;
    }
    make_room(now);
    g_entries.emplace(key, Entry{value, now});
}

void clear_pending() {
    ba_free_private(t_pending.dk);
    t_pending.dk  = nullptr;
    t_pending.set = false;
    t_pending.key.clear();
}

void count_lookup(bool hit) {
    if (hit) g_hits++;
    unsigned long long n = ++g_lookups;
    if (n % 1000 == 0) {
        size_t entries;
        {
            std::lock_guard<std::mutex> lock(g_mutex);
            entries = g_entries.size();
        }
        std::fprintf(stderr, "[kdf-cache] lookups=%llu hits=%llu entries=%zu\n", n, g_hits.load(), entries);
    }
}

}   //  namespace

extern "C" int kdf_cache_get(KdfCacheKind kind, uint8_t id, HashAlg hash_alg, const ByteArray* salt,
        size_t iterations, size_t out_len, const char* pass, ByteArray** dk) {
    if (!dk || !enabled()) return 0;
    std::string key = key_of(kind, id, hash_alg, salt, iterations, out_len, pass);
    if (key.empty()) return 0;

    ByteArray* found = lookup(key);
    count_lookup(found != nullptr);
    trace(found ? "hit" : "miss", kind, id, iterations, out_len);
    if (!found) return 0;
    *dk = found;
    return 1;
}

extern "C" void kdf_cache_put(KdfCacheKind kind, uint8_t id, HashAlg hash_alg, const ByteArray* salt,
        size_t iterations, size_t out_len, const char* pass, const ByteArray* dk) {
    if (!dk || !enabled()) return;
    if (t_proven <= 0) {
        trace("not stored: password unproven", kind, id, iterations, out_len);
        return;
    }
    std::string key = key_of(kind, id, hash_alg, salt, iterations, out_len, pass);
    if (key.empty()) return;
    store(key, dk);
    trace("stored", kind, id, iterations, out_len);
}

extern "C" void kdf_cache_set_pending(KdfCacheKind kind, uint8_t id, HashAlg hash_alg, const ByteArray* salt,
        size_t iterations, size_t out_len, const char* pass, const ByteArray* dk) {
    clear_pending();
    if (!dk || !enabled()) return;
    std::string key = key_of(kind, id, hash_alg, salt, iterations, out_len, pass);
    if (key.empty()) return;
    t_pending.dk = copy_of(dk);
    if (!t_pending.dk) return;
    t_pending.key = key;
    t_pending.set = true;
    trace("pending", kind, id, iterations, out_len);
}

extern "C" void kdf_cache_commit_pending(void) {
    if (t_pending.set) {
        store(t_pending.key, t_pending.dk);
        trace("pending stored", (KdfCacheKind)0, 0, 0, 0);
    }
    clear_pending();
}

extern "C" int kdf_cache_private_key_get_spki(const ByteArray* privateKeyInfo, ByteArray** spki) {
    if (!privateKeyInfo || !spki || !enabled()) return private_key_get_spki(privateKeyInfo, spki);
    std::string key = spki_key_of(privateKeyInfo);
    if (key.empty()) return private_key_get_spki(privateKeyInfo, spki);

    ByteArray* found = lookup(key);
    count_lookup(found != nullptr);
    trace(found ? "spki hit" : "spki miss", (KdfCacheKind)0, 0, 0, 0);
    if (found) {
        *spki = found;
        return RET_OK;
    }
    const int ret = private_key_get_spki(privateKeyInfo, spki);
    if (ret == RET_OK && *spki) store(key, *spki);
    return ret;
}

extern "C" void kdf_cache_trace(const char* what) {
    trace(what, (KdfCacheKind)0, 0, 0, 0);
}

extern "C" void kdf_cache_drop_pending(void) {
    clear_pending();
}

extern "C" void kdf_cache_proven_begin(void) {
    t_proven++;
}

extern "C" void kdf_cache_proven_end(void) {
    if (t_proven > 0) t_proven--;
}
