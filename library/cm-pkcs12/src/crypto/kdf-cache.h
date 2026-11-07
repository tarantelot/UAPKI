/*
 * A process-wide cache of password-based key derivations (PBKDF), so a key
 * container opened again with the same password skips its deliberately slow
 * iterated hashing (~120 ms of CPU for a 10,000-iteration DSTU container).
 *
 * The cache maps the derivation's inputs to its output:
 *   (kind, id, hash algorithm, salt, iterations, output length, HMAC(password))
 *     -> derived key
 * Salt, iterations and algorithms come from the container itself; the password
 * is kept only as an HMAC-SHA-256 under a random per-process secret, never in
 * plaintext. A derivation is a pure function of these inputs, so a hit returns
 * exactly what computing it again would.
 *
 * Only derivations made under a password the container has PROVEN are stored:
 * the PKCS#12 MAC derivation is held as "pending" on the calling thread and
 * committed by the caller once the MAC matched (kdf_cache_commit_pending), and
 * the derivations that follow in the same decode are stored while the caller
 * marks the password proven (kdf_cache_proven_begin/end). A wrong password is
 * never cached. The private key itself is never cached - only the derived key
 * that decrypts it; each open still parses and decrypts the container.
 *
 * It also keeps each private key's PUBLIC key (SubjectPublicKeyInfo), which
 * private_key_get_spki() computes by an elliptic-curve multiplication, several
 * times per open (both key ids of every key in the container, then the key
 * info, twice): keyed by HMAC-SHA-256(secret, the decrypted private key's
 * bytes), the value public by definition (kdf_cache_private_key_get_spki).
 *
 * Entries expire after UAPKI_KDF_CACHE_TTL_S idle seconds (default 43200),
 * at most UAPKI_KDF_CACHE_MAX are kept (default 5000, least recently used
 * evicted), and evicted values are wiped. UAPKI_KDF_CACHE=0 turns it off.
 */

#ifndef CM_PKCS12_KDF_CACHE_H
#define CM_PKCS12_KDF_CACHE_H

#include <stddef.h>
#include <stdint.h>
#include "byte-array.h"
#include "hash.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    KDF_CACHE_PKCS12 = 1,               //  pbkdf1(): the PKCS#12 KDF (id 1 key, 2 IV, 3 MAC)
    KDF_CACHE_PBKDF2 = 2,               //  pbkdf2()
    KDF_CACHE_PBKDF2_DSTU7564KMAC = 3   //  pbkdf2_dstu7564kmac() (pkcs5.c)
} KdfCacheKind;

//  The derivation of `pass` from the cache into *dk (a copy the caller frees) - 1 on a hit, 0 on a miss
//  (or with the cache off). Never computes.
int kdf_cache_get(KdfCacheKind kind, uint8_t id, HashAlg hash_alg, const ByteArray* salt,
        size_t iterations, size_t out_len, const char* pass, ByteArray** dk);

//  Stores `dk` (copied) as the derivation of `pass` - only while the calling thread has the password
//  proven (kdf_cache_proven_begin); a no-op otherwise.
void kdf_cache_put(KdfCacheKind kind, uint8_t id, HashAlg hash_alg, const ByteArray* salt,
        size_t iterations, size_t out_len, const char* pass, const ByteArray* dk);

//  Holds `dk` (copied) as this thread's one pending derivation, not yet stored: its password isn't proven.
void kdf_cache_set_pending(KdfCacheKind kind, uint8_t id, HashAlg hash_alg, const ByteArray* salt,
        size_t iterations, size_t out_len, const char* pass, const ByteArray* dk);

//  The pending derivation's password is proven: store it. kdf_cache_drop_pending discards it.
void kdf_cache_commit_pending(void);
void kdf_cache_drop_pending(void);

//  Between these, this thread's password is proven: kdf_cache_put stores.
void kdf_cache_proven_begin(void);
void kdf_cache_proven_end(void);

//  private_key_get_spki(privateKeyInfo, spki) - the public key from the cache when this private key's was
//  computed before, else computed and stored (with the cache off, just computed). *spki: the caller frees.
int kdf_cache_private_key_get_spki(const ByteArray* privateKeyInfo, ByteArray** spki);

//  With UAPKI_KDF_CACHE_DEBUG=1: one stderr line, `what` with a microsecond timestamp (no secrets).
void kdf_cache_trace(const char* what);

#ifdef __cplusplus
}
#endif

#endif
