/*
 * JNI shim: exposes per-thread, independently-sessioned DSTU4145 signing
 * (Kalyna/Kupyna or legacy GOST containers - whatever cm-pkcs12 supports)
 * for crypto-service, bypassing CmProviders' single process-wide "opened
 * storage" slot so concurrent gRPC-handler threads can each open+sign with
 * their own key file truly in parallel - matching how crypto-service uses
 * Cryptonite's KeyStore today (a fresh, independent object per call).
 *
 * Each native call here constructs its own CmStorageProxy (own CmLoader,
 * own cm-pkcs12 session, own selected key - see cm-storage-proxy.h). The
 * only thing threads share is the read-only CM_PROVIDER_API function table
 * cm-pkcs12.so exposes once dlopen'd, which is reentrant by design (every
 * call takes the session/key pointer explicitly - see cm-api.h).
 */

#include <jni.h>
#include <cstdio>
#include <string>
#include <vector>

#include "api-json-internal.h"
#include "cm-storage-proxy.h"
#include "doc-sign.h"
#include "parson.h"
#include "parson-ba-utils.h"
#include "byte-array.h"
#include "cm-api.h"
#include "uapkic-errors.h"
#include "uapki-errors.h"
#include "stacktrace.h"
#include "oids.h"
#include "oid-utils.h"
#include "uapki-ns-util.h"
#include "hash.h"
#include "global-objects.h"
#include "cer-store.h"

//  Same fixed TSP endpoint CryptoController.java's TSP_URL hardcodes,
//  regardless of which CA issued the signer's own certificate. UAPKI's own
//  default (tsp.forced=false) would instead read the TSP URI out of the
//  signer cert's own subjectInfoAccess extension - not what crypto-service
//  currently does for every customer, so this is set explicitly rather
//  than left to the library default. See setupTsp() in doc-sign.cpp.
static const char* TSP_URL = "http://acsk.privatbank.ua/services/tsp/";

//  Set once by nativeInit() from the same directory the Java side already
//  extracted every uapki .so into (see UapkiNative.java's loader) - passed
//  explicitly to every CmStorageProxy::load("cm-pkcs12", ...) call so
//  dlopen resolves it (and, in turn, its own libuapkic/libuapkif deps,
//  already resident in the process by the time this runs) by absolute
//  path, without depending on LD_LIBRARY_PATH being set correctly in
//  whatever environment this ends up deployed in.
static std::string g_nativeLibDir;

namespace {

//  Forward declarations - definitions further down are ordered for
//  readability (helpers, then the two open/select/cache building blocks,
//  then signCore which uses both), not top-to-bottom dependency order.
int openAndSelectFirstKey(JNIEnv* env, CmStorageProxy& storage, const std::string& path, const std::string& password);
int addCertToCache(const ByteArray* certBa, ByteArray** certId);

std::string jstringToStd(JNIEnv* env, jstring s) {
    if (!s) return std::string();
    const char* chars = env->GetStringUTFChars(s, nullptr);
    std::string ret(chars);
    env->ReleaseStringUTFChars(s, chars);
    return ret;
}

ByteArray* jbyteArrayToBa(JNIEnv* env, jbyteArray arr) {
    if (!arr) return nullptr;
    jsize len = env->GetArrayLength(arr);
    jbyte* bytes = env->GetByteArrayElements(arr, nullptr);
    ByteArray* ba = ba_alloc_from_uint8(reinterpret_cast<const uint8_t*>(bytes), (size_t)len);
    env->ReleaseByteArrayElements(arr, bytes, JNI_ABORT);
    return ba;
}

jbyteArray baToJbyteArray(JNIEnv* env, const ByteArray* ba) {
    if (!ba) return nullptr;
    size_t len = ba_get_len(ba);
    jbyteArray arr = env->NewByteArray((jsize)len);
    env->SetByteArrayRegion(arr, 0, (jsize)len, reinterpret_cast<const jbyte*>(ba_get_buf_const(ba)));
    return arr;
}

void throwCryptoException(JNIEnv* env, const std::string& msg) {
    jclass cls = env->FindClass("com/tarantelot/uapki/UapkiException");
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        cls = env->FindClass("java/lang/RuntimeException");
    }
    env->ThrowNew(cls, msg.c_str());
}

//  sessionSelectKey() alone only sets m_SelectedKey - it does NOT populate
//  m_SelectedKeyId/m_SelectedKeyId2, which uapki_sign_with_storage's
//  get_info_signalgo_and_keyid() requires (RET_UAPKI_GENERAL_ERROR
//  otherwise). This replicates the rest of what session-select-key.cpp's
//  JSON handler does: read the key's mechanism/public key back out, derive
//  keyId2 (Kupyna-256 over the DER-encoded public key) for DSTU4145 keys,
//  and call setSelectedKeyId(). Cert lookup/pairing is intentionally
//  skipped here - not needed while includeCert is false.
int selectKeyFully(CmStorageProxy& storage, const ByteArray* keyId) {
    int ret = storage.sessionSelectKey(keyId);
    if (ret != RET_OK) return ret;

    std::string keyInfoStr;
    ret = storage.keyGetInfo(keyInfoStr);
    if (ret != RET_OK) { storage.deselectKey(); return ret; }

    JSON_Value* jv = json_parse_string(keyInfoStr.c_str());
    JSON_Object* jo = jv ? json_value_get_object(jv) : nullptr;
    if (!jo) {
        json_value_free(jv);
        storage.deselectKey();
        return RET_UAPKI_INVALID_JSON_FORMAT;
    }

    const char* mechanismId = json_object_get_string(jo, "mechanismId");
    const char* pubKeyB64 = json_object_get_string(jo, "publicKey");

    ByteArray* keyId2 = nullptr;
    if (mechanismId && pubKeyB64 && oid_is_equal(mechanismId, OID_DSTU4145_PARAM_PB_LE)) {
        ByteArray* pubKey = ba_alloc_from_base64(pubKeyB64);
        if (pubKey) {
            ByteArray* encPubKey = nullptr;
            if (UapkiNS::Util::encodeOctetString(pubKey, &encPubKey) == RET_OK) {
                hash(HASH_ALG_DSTU7564_256, encPubKey, &keyId2);
                ba_free(encPubKey);
            }
            ba_free(pubKey);
        }
    }
    json_value_free(jv);

    ret = storage.setSelectedKeyId(keyId, keyId2);
    ba_free(keyId2);
    if (ret != RET_OK) {
        storage.deselectKey();
        return ret;
    }

    return RET_OK;
}

//  Opens storage, logs in, selects the first key. Returns RET_OK on success;
//  on failure the storage is already closed and an exception is pending.
//
//  Deliberately does NOT call storage.providerInit() here: unlike
//  storageOpen/sessionLogin/etc (genuinely per-session, safe to call once
//  per thread's own CmStorageProxy), cm-pkcs12's provider_init() sets a
//  single process-wide static (see main-cm-pkcs12.cpp's `cm_pkcs12`
//  pointer) - calling it more than once per process fails with
//  RET_CM_ALREADY_INITIALIZED. It's called exactly once in nativeInit()
//  instead. load() itself (dlopen) IS safe to repeat - POSIX reference-
//  counts it per path, every thread just gets pointers into the one
//  already-mapped library.
int openAndSelectFirstKey(JNIEnv* env, CmStorageProxy& storage, const std::string& path, const std::string& password) {
    if (!storage.load("cm-pkcs12", g_nativeLibDir)) {
        throwCryptoException(env, "Cant load cm-pkcs12 provider");
        return RET_UAPKI_GENERAL_ERROR;
    }

    int ret = storage.storageOpen(path, OPEN_MODE_RO, std::string());
    if (ret != RET_OK) {
        throwCryptoException(env, "storageOpen failed: " + std::to_string(ret));
        return ret;
    }

    ret = storage.sessionLogin(password.c_str(), nullptr);
    if (ret != RET_OK) {
        storage.storageClose();
        throwCryptoException(env, "sessionLogin failed (wrong password?): " + std::to_string(ret));
        return ret;
    }

    std::vector<ByteArray*> keyIds;
    ret = storage.sessionListKeys(keyIds);
    if (ret != RET_OK || keyIds.empty()) {
        for (auto* k : keyIds) ba_free(k);
        storage.storageClose();
        throwCryptoException(env, "No keys in storage");
        return (ret != RET_OK) ? ret : RET_UAPKI_GENERAL_ERROR;
    }
    ret = selectKeyFully(storage, keyIds[0]);
    for (auto* k : keyIds) ba_free(k);
    if (ret != RET_OK) {
        storage.storageClose();
        throwCryptoException(env, "selectKey failed: " + std::to_string(ret));
        return ret;
    }

    return RET_OK;
}

//  Shared core for nativeSignData/nativeSignAndSetData: open+select the
//  key, add the caller-supplied certificate to the cache (Cryptonite always
//  reads and passes this too, regardless of includeCert - see
//  getUserKeyCert() in CryptoController.java), sign, close. Takes
//  ownership of jvSignParams (attaches it to the request and frees it
//  together with the rest). Returns the decoded signature bytes, or
//  nullptr with a pending Java exception.
jbyteArray signCore(JNIEnv* env, const std::string& path, const std::string& password,
        jbyteArray jData, jbyteArray jCertBytes, JSON_Value* jvSignParams) {
    CmStorageProxy storage;
    if (openAndSelectFirstKey(env, storage, path, password) != RET_OK) {
        json_value_free(jvSignParams);
        return nullptr;
    }

    //  Cryptonite hardcodes DSTU4145 signing to (GOST34311 digest, the
    //  plain curve OID as signatureAlgorithm) - it never offers a hash
    //  choice. cm-pkcs12 reports every hash combo a key's curve supports
    //  (legacy GOST34311 and, for keys new enough to allow it, Kupyna/
    //  DSTU7564), and leaving "signAlgo" unset makes sign.cpp's
    //  get_info_signalgo_and_keyid() default to signAlgo[0] - which for a
    //  real legacy key came back the Kupyna combo first, not what
    //  Cryptonite itself produces for that same key (confirmed via a
    //  differential test: cross-verifying through Cryptonite's own
    //  cmsVerify() came back signStatus=INVALID from the digest/
    //  signatureAlgorithm mismatch). Prefer the legacy GOST3411 combo when
    //  the key supports it, to bit-for-bit match Cryptonite; fall back to
    //  whatever cm-pkcs12 offers otherwise - real production keys that are
    //  Kalyna/Kupyna-only (the whole reason for this migration) simply
    //  won't have this OID in their list, so this is a no-op for them.
    {
        std::string keyInfoStr;
        if (storage.keyGetInfo(keyInfoStr) == RET_OK) {
            JSON_Value* jvKeyInfo = json_parse_string(keyInfoStr.c_str());
            JSON_Object* joKeyInfo = jvKeyInfo ? json_value_get_object(jvKeyInfo) : nullptr;
            JSON_Array* jaSignAlgo = joKeyInfo ? json_object_get_array(joKeyInfo, "signAlgo") : nullptr;
            if (jaSignAlgo) {
                for (size_t i = 0; i < json_array_get_count(jaSignAlgo); ++i) {
                    const char* algo = json_array_get_string(jaSignAlgo, i);
                    if (algo && oid_is_equal(algo, OID_DSTU4145_PARAM_PB_LE)) {
                        json_object_set_string(json_value_get_object(jvSignParams), "signAlgo", algo);
                        break;
                    }
                }
            }
            json_value_free(jvKeyInfo);
        }
    }

    ByteArray* certBa = jbyteArrayToBa(env, jCertBytes);
    if (certBa) {
        ByteArray* certId = nullptr;
        int certRet = addCertToCache(certBa, &certId);
        ba_free(certBa);
        if (certRet != RET_OK) {
            storage.storageClose();
            json_value_free(jvSignParams);
            throwCryptoException(env, "addCertToCache failed: " + std::to_string(certRet));
            return nullptr;
        }
        //  See addCertToCache's comment: without this, sign.cpp's cerSigner
        //  lookup falls back to getCertByKeyId(storage->getSelectedKeyId()),
        //  which does not correlate for an externally-supplied cert.
        certRet = storage.setPairedCertId(certId);
        ba_free(certId);
        if (certRet != RET_OK) {
            storage.storageClose();
            json_value_free(jvSignParams);
            throwCryptoException(env, "setPairedCertId failed: " + std::to_string(certRet));
            return nullptr;
        }
    }

    ByteArray* baData = jbyteArrayToBa(env, jData);

    JSON_Value* jvParams = json_value_init_object();
    JSON_Object* joParams = json_value_get_object(jvParams);
    json_object_set_value(joParams, "signParams", jvSignParams);

    //  Cryptonite's TSP path never does OCSP/CRL chain validation before
    //  timestamping - it just fetches a timestamp from TSP_URL. UAPKI's
    //  CAdES-T format otherwise runs cert_validator.getStatus() first,
    //  which needs the signer's full CA chain resolvable in the cert cache
    //  (RET_UAPKI_CERT_ISSUER_NOT_FOUND otherwise, since only the leaf cert
    //  is ever added here - see addCertToCache). ignoreCertStatus skips
    //  that validation, matching Cryptonite's simpler behavior exactly.
    JSON_Value* jvOptions = json_value_init_object();
    json_object_set_boolean(json_value_get_object(jvOptions), "ignoreCertStatus", 1);
    json_object_set_value(joParams, "options", jvOptions);

    JSON_Value* jvDataTbs = json_value_init_array();
    JSON_Array* jaDataTbs = json_value_get_array(jvDataTbs);
    JSON_Value* jvDoc = json_value_init_object();
    JSON_Object* joDoc = json_value_get_object(jvDoc);
    json_object_set_string(joDoc, "id", "doc-0");
    json_object_set_base64(joDoc, "bytes", baData);
    json_array_append_value(jaDataTbs, jvDoc);
    json_object_set_value(joParams, "dataTbs", jvDataTbs);

    JSON_Value* jvResult = json_value_init_object();
    JSON_Object* joResult = json_value_get_object(jvResult);

    int ret = uapki_sign_with_storage(storage, joParams, joResult);
    if (ret != RET_OK) {
        for (const ErrorCtx* e = stacktrace_get_last(); e; e = e->next) {
            fprintf(stderr, "[uapki-jni] stacktrace: %s:%zu code=%d\n", e->file, e->line, e->error_code);
        }
    }

    jbyteArray out = nullptr;
    if (ret == RET_OK) {
        JSON_Array* jaSignatures = json_object_get_array(joResult, "signatures");
        if (jaSignatures && json_array_get_count(jaSignatures) > 0) {
            JSON_Object* joSig = json_array_get_object(jaSignatures, 0);
            ByteArray* baSig = json_object_get_base64(joSig, "bytes");
            out = baToJbyteArray(env, baSig);
            ba_free(baSig);
        }
    }

    ba_free(baData);
    json_value_free(jvParams);
    json_value_free(jvResult);
    storage.storageClose();

    if (!out) {
        throwCryptoException(env, "sign failed: " + std::to_string(ret));
        return nullptr;
    }
    return out;
}

//  Cryptonite always reads the signer's certificate from a separate .cer
//  file (getUserKeyCert()) rather than trusting anything embedded in the
//  PKCS12 container - our real-world containers don't embed certs at all.
//  Same here: the caller supplies the cert bytes, and this adds them to
//  UapkiNS::get_cerstore() (a shared, MT-safe cache per UAPKI's own docs -
//  ADD_CERT/CERT_INFO/GET_CERT are all classified MT).
//
//  Returns the cert's own certId via *certId (caller ba_free()s it) so the
//  caller can storage->setPairedCertId() it. sign.cpp's cerSigner lookup
//  prefers getCertByCertId() when a paired cert id is set, and falls back
//  to getCertByKeyId(storage->getSelectedKeyId()) otherwise - but that
//  fallback only works when the cert came from the SAME pkcs12 container
//  (via keyGetCertificates(), which correlates cm-pkcs12's own internal key
//  id with the embedded cert). For an externally-supplied .cer like this
//  one, CerStore computes its own keyId from the certificate's public key,
//  which has no reason to equal cm-pkcs12's internal key id - so relying on
//  getCertByKeyId() 404s with RET_UAPKI_CERT_NOT_FOUND even though the cert
//  was added successfully. Explicit setPairedCertId() sidesteps that.
int addCertToCache(const ByteArray* certBa, ByteArray** certId) {
    if (!certBa) return RET_UAPKI_INVALID_PARAMETER;

    //  VectorBA's destructor ba_free()s every element it holds (see
    //  uapki-ns.h) - push a copy, not the caller's own certBa, or the
    //  caller's copy gets double-freed when this VectorBA goes out of scope.
    UapkiNS::VectorBA vbaCerts;
    vbaCerts.push_back(ba_copy_with_alloc(certBa, 0, 0));

    std::vector<UapkiNS::Cert::CerStore::AddedCerItem> addedItems;
    int ret = UapkiNS::get_cerstore()->addCerts(false, false, vbaCerts, addedItems);
    if (ret != RET_OK) return ret;
    if (addedItems.empty()) return RET_UAPKI_GENERAL_ERROR;
    if (addedItems[0].errorCode != RET_OK) return addedItems[0].errorCode;
    if (certId) *certId = ba_copy_with_alloc(addedItems[0].cerItem->getCertId(), 0, 0);
    return RET_OK;
}

}  // namespace

extern "C" {

//  Must be called exactly once per process before nativeSignData - it sets
//  up the process-wide LibraryConfig/CerStore/CrlStore that CertValidator
//  (and therefore uapki_sign_with_storage) requires to be initialized, even
//  when includeCert=false. This is the one genuinely single-instance,
//  call-once-at-startup step (matches UAPKI's own "ST" classification for
//  INIT) - it does not touch CmProviders' storage slot, so it doesn't
//  conflict with per-thread signing sessions.
JNIEXPORT jboolean JNICALL Java_com_tarantelot_uapki_UapkiNative_nativeInit0(
        JNIEnv* env, jclass, jstring jCertCacheDir, jstring jCrlCacheDir, jstring jNativeLibDir) {
    std::string certCacheDir = jstringToStd(env, jCertCacheDir);
    std::string crlCacheDir = jstringToStd(env, jCrlCacheDir);
    g_nativeLibDir = jstringToStd(env, jNativeLibDir);
    //  CmLoader::load() does `dir + getLibName(libName)` with no separator
    //  inserted - g_nativeLibDir must end in one for that concatenation to
    //  produce a valid path.
    if (!g_nativeLibDir.empty() && g_nativeLibDir.back() != '/') {
        g_nativeLibDir += '/';
    }

    JSON_Value* jvParams = json_value_init_object();
    JSON_Object* joParams = json_value_get_object(jvParams);
    //  offline=false: TSP timestamping (nativeSignData's withTimestamp) needs
    //  an actual network call to TSP_URL. offline=true would make sign.cpp
    //  reject any includeContentTS/includeSignatureTS request outright
    //  (RET_UAPKI_OFFLINE_MODE) before it ever reached the network.
    json_object_set_boolean(joParams, "offline", 0);

    JSON_Value* jvCertCache = json_value_init_object();
    json_object_set_string(json_value_get_object(jvCertCache), "path", certCacheDir.c_str());
    json_object_set_value(joParams, "certCache", jvCertCache);

    JSON_Value* jvCrlCache = json_value_init_object();
    json_object_set_string(json_value_get_object(jvCrlCache), "path", crlCacheDir.c_str());
    json_object_set_value(joParams, "crlCache", jvCrlCache);

    //  Force the same fixed TSP endpoint Cryptonite always uses (see
    //  TSP_URL comment above) rather than UAPKI's default of trusting the
    //  signer cert's own subjectInfoAccess TSP URI.
    JSON_Value* jvTsp = json_value_init_object();
    JSON_Object* joTsp = json_value_get_object(jvTsp);
    json_object_set_boolean(joTsp, "forced", 1);
    json_object_set_string(joTsp, "url", TSP_URL);
    //  certReq=true: ask the TSA to embed its signing cert in the response.
    //  Without it, doc-sign.cpp's verifySignedData() adds zero certs from
    //  an empty response cert list, and the subsequent SID-based
    //  getCertByKeyId() lookup 404s with RET_UAPKI_CERT_NOT_FOUND - not a
    //  lookup bug, just nothing was ever added to look up.
    json_object_set_boolean(joTsp, "certReq", 1);
    json_object_set_value(joParams, "tsp", jvTsp);

    //  cm-pkcs12's provider_init() sets a single process-wide static (see
    //  openAndSelectFirstKey's comment) - call it exactly once here, via a
    //  proxy that's deliberately leaked for the process's lifetime rather
    //  than closed, since there's no matching nativeDeinit (crypto-service
    //  is a long-lived daemon, not something that tears this down).
    CmStorageProxy* bootstrapProxy = new CmStorageProxy();
    if (!bootstrapProxy->load("cm-pkcs12", g_nativeLibDir)) {
        json_value_free(jvParams);
        throwCryptoException(env, "Cant load cm-pkcs12 provider");
        return JNI_FALSE;
    }
    int providerInitRet = bootstrapProxy->providerInit(std::string());
    if (providerInitRet != RET_OK) {
        json_value_free(jvParams);
        throwCryptoException(env, "cm-pkcs12 providerInit failed: " + std::to_string(providerInitRet));
        return JNI_FALSE;
    }

    JSON_Value* jvResult = json_value_init_object();
    JSON_Object* joResult = json_value_get_object(jvResult);

    int ret = uapki_init(joParams, joResult);

    json_value_free(jvParams);
    json_value_free(jvResult);

    if (ret != RET_OK) {
        throwCryptoException(env, "uapki_init failed: " + std::to_string(ret));
        return JNI_FALSE;
    }
    return JNI_TRUE;
}

JNIEXPORT jboolean JNICALL Java_com_tarantelot_uapki_UapkiNative_nativeIsKeyPasswordCorrect(
        JNIEnv* env, jclass, jstring jPath, jstring jPassword) {
    std::string path = jstringToStd(env, jPath);
    std::string password = jstringToStd(env, jPassword);

    CmStorageProxy storage;
    int ret = openAndSelectFirstKey(env, storage, path, password);
    storage.storageClose();

    //  This method reports pass/fail as a boolean, not an exception - any
    //  failure openAndSelectFirstKey threw for (bad password, no keys, etc)
    //  is exactly a "false" result here, so clear it rather than propagate.
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
    }
    return (ret == RET_OK) ? JNI_TRUE : JNI_FALSE;
}

//  Matches CryptoController.signData()'s exact parameter set and behavior:
//  - Always uses CAdES-T (always fetches a real TSP timestamp), regardless
//    of withTimestamp. This looks wrong until you read cmsSignData's own
//    body (CryptoniteX.java): TSP only gates on `tspURL != null`, and
//    signData() always passes the hardcoded TSP_URL - `withTimestamp`
//    (Cryptonite's `includeSignTime`) only controls a SEPARATE, minor
//    local signingTime signed attribute, unrelated to whether a TSP
//    network call happens. Confirmed against the real crypto-service
//    Cryptonite build in a differential test: production's two signData()
//    call sites (SfsDocService.signData/createReceiptAndSign) both pass
//    withTimestamp=false yet cmsVerify() on their own output still showed
//    a populated TSP token - i.e. every signData() call in production
//    already does a real TSP round-trip today. Matching "withTimestamp
//    disables TSP" (the obvious-looking reading) would have silently
//    changed production behavior instead of preserving it.
//  - certBytes is read (by the Java caller, from certificateKeyPath) and
//    passed through unconditionally, exactly like getUserKeyCert() does -
//    Cryptonite always loads the cert file regardless of includeCertificate.
JNIEXPORT jbyteArray JNICALL Java_com_tarantelot_uapki_UapkiNative_nativeSignData(
        JNIEnv* env, jclass,
        jstring jPath, jstring jPassword, jbyteArray jData,
        jboolean includeData, jboolean withTimestamp,
        jbyteArray jCertBytes, jboolean includeCertificate) {

    std::string path = jstringToStd(env, jPath);
    std::string password = jstringToStd(env, jPassword);
    (void)withTimestamp;

    JSON_Value* jvSignParams = json_value_init_object();
    JSON_Object* joSignParams = json_value_get_object(jvSignParams);
    json_object_set_string(joSignParams, "signatureFormat", "CAdES-T");
    json_object_set_boolean(joSignParams, "detachedData", !includeData);
    json_object_set_boolean(joSignParams, "includeCert", includeCertificate);

    return signCore(env, path, password, jData, jCertBytes, jvSignParams);
}

//  Diagnostic only, not part of CryptoController's contract: the exact
//  detached signature nativeSignAndSetData produces internally, before its
//  modify_cms reattachment step - lets a differential test tell apart "base
//  signing is wrong" from "modify_cms's content-reattachment corrupts
//  something".
JNIEXPORT jbyteArray JNICALL Java_com_tarantelot_uapki_UapkiNative_nativeSignDetachedNoTsp(
        JNIEnv* env, jclass,
        jstring jPath, jstring jPassword, jbyteArray jData, jbyteArray jCertBytes) {
    std::string path = jstringToStd(env, jPath);
    std::string password = jstringToStd(env, jPassword);

    //  "CMS" maps to SignatureFormat::CMS_SID_KEYID, which sets
    //  sidUseKeyId=true (SubjectKeyIdentifier SID) - Cryptonite's own
    //  signatures always use IssuerAndSerialNumber SID instead, and its
    //  verifier can't extract a signerId at all from a SubjectKeyIdentifier
    //  SID (confirmed via a differential test: cross-verifying this output
    //  through Cryptonite's own cmsVerify() came back signStatus=INVALID,
    //  with SignInfo.getSignerId() null). "CAdES-BES" sets sidUseKeyId=false
    //  (IssuerAndSerialNumber, matching Cryptonite) without adding TSP -
    //  only CAdES-T turns TSP on, per paramsBySignatureFormat()'s fallthrough.
    JSON_Value* jvSignParams = json_value_init_object();
    JSON_Object* joSignParams = json_value_get_object(jvSignParams);
    json_object_set_string(joSignParams, "signatureFormat", "CAdES-BES");
    json_object_set_boolean(joSignParams, "detachedData", true);
    json_object_set_boolean(joSignParams, "includeCert", true);

    return signCore(env, path, password, jData, jCertBytes, jvSignParams);
}

//  Matches CryptoController.signAndSetData()'s exact (hardcoded) behavior:
//  sign detached with the cert embedded and no TSP - despite the Java
//  method's local `withTimeStamp = true`, it passes a null TSP URL to
//  CryptoniteX.cmsSignData specifically "in order to omit setting
//  timestamp on data" (see that method's comment), so the actual signature
//  here carries no timestamp either. Then attach the plaintext content via
//  MODIFY_CMS (add.content), matching CryptoniteX.cmsSetData(sign, data) -
//  it verifies the digest matches before rebuilding, same as that call.
JNIEXPORT jbyteArray JNICALL Java_com_tarantelot_uapki_UapkiNative_nativeSignAndSetData(
        JNIEnv* env, jclass,
        jstring jPath, jstring jPassword, jbyteArray jData, jbyteArray jCertBytes) {

    std::string path = jstringToStd(env, jPath);
    std::string password = jstringToStd(env, jPassword);

    //  See nativeSignDetachedNoTsp's comment: "CMS" (sidUseKeyId=true,
    //  SubjectKeyIdentifier SID) is what Cryptonite's own verifier can't
    //  cross-verify - "CAdES-BES" (IssuerAndSerialNumber SID) matches
    //  Cryptonite's own convention while still adding no TSP.
    JSON_Value* jvSignParams = json_value_init_object();
    JSON_Object* joSignParams = json_value_get_object(jvSignParams);
    json_object_set_string(joSignParams, "signatureFormat", "CAdES-BES");
    json_object_set_boolean(joSignParams, "detachedData", true);
    json_object_set_boolean(joSignParams, "includeCert", true);

    jbyteArray detachedSig = signCore(env, path, password, jData, jCertBytes, jvSignParams);
    if (!detachedSig) {
        return nullptr;
    }

    ByteArray* baSig = jbyteArrayToBa(env, detachedSig);
    ByteArray* baData = jbyteArrayToBa(env, jData);

    JSON_Value* jvParams = json_value_init_object();
    JSON_Object* joParams = json_value_get_object(jvParams);
    json_object_set_base64(joParams, "bytes", baSig);
    JSON_Value* jvAdd = json_value_init_object();
    json_object_set_base64(json_value_get_object(jvAdd), "content", baData);
    json_object_set_value(joParams, "add", jvAdd);

    JSON_Value* jvResult = json_value_init_object();
    JSON_Object* joResult = json_value_get_object(jvResult);

    int ret = uapki_modify_cms(joParams, joResult);

    jbyteArray out = nullptr;
    if (ret == RET_OK) {
        ByteArray* baOut = json_object_get_base64(joResult, "bytes");
        out = baToJbyteArray(env, baOut);
        ba_free(baOut);
    }

    ba_free(baSig);
    ba_free(baData);
    json_value_free(jvParams);
    json_value_free(jvResult);

    if (!out) {
        throwCryptoException(env, "modify_cms (attach content) failed: " + std::to_string(ret));
        return nullptr;
    }
    return out;
}

//  Matches CryptoController.getRawData()'s exact behavior (CryptoniteX.
//  cmsGetData): extract the encapsulated content from an already-signed
//  CMS/CAdES structure - read-only, no key/storage involved at all.
//  uapki_modify_cms with no "add"/"remove" and options.returnContent=true
//  parses the structure and returns the content bytes without rebuilding
//  anything.
JNIEXPORT jbyteArray JNICALL Java_com_tarantelot_uapki_UapkiNative_nativeGetRawData(
        JNIEnv* env, jclass, jbyteArray jSignedData) {
    ByteArray* baSignedData = jbyteArrayToBa(env, jSignedData);

    JSON_Value* jvParams = json_value_init_object();
    JSON_Object* joParams = json_value_get_object(jvParams);
    json_object_set_base64(joParams, "bytes", baSignedData);
    JSON_Value* jvOptions = json_value_init_object();
    json_object_set_boolean(json_value_get_object(jvOptions), "returnContent", true);
    json_object_set_value(joParams, "options", jvOptions);

    JSON_Value* jvResult = json_value_init_object();
    JSON_Object* joResult = json_value_get_object(jvResult);

    int ret = uapki_modify_cms(joParams, joResult);

    jbyteArray out = nullptr;
    if (ret == RET_OK) {
        JSON_Object* joContent = json_object_get_object(joResult, "content");
        ByteArray* baOut = joContent ? json_object_get_base64(joContent, "bytes") : nullptr;
        out = baToJbyteArray(env, baOut);
        ba_free(baOut);
    }

    ba_free(baSignedData);
    json_value_free(jvParams);
    json_value_free(jvResult);

    if (!out) {
        throwCryptoException(env, "getRawData (modify_cms returnContent) failed: " + std::to_string(ret));
        return nullptr;
    }
    return out;
}

}  // extern "C"
