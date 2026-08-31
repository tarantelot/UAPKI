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

namespace {

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
    if (!storage.load("cm-pkcs12")) {
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

}  // namespace

extern "C" {

//  Must be called exactly once per process before nativeSignData - it sets
//  up the process-wide LibraryConfig/CerStore/CrlStore that CertValidator
//  (and therefore uapki_sign_with_storage) requires to be initialized, even
//  when includeCert=false. This is the one genuinely single-instance,
//  call-once-at-startup step (matches UAPKI's own "ST" classification for
//  INIT) - it does not touch CmProviders' storage slot, so it doesn't
//  conflict with per-thread signing sessions.
JNIEXPORT jboolean JNICALL Java_com_tarantelot_uapki_UapkiNative_nativeInit(
        JNIEnv* env, jclass, jstring jCertCacheDir, jstring jCrlCacheDir) {
    std::string certCacheDir = jstringToStd(env, jCertCacheDir);
    std::string crlCacheDir = jstringToStd(env, jCrlCacheDir);

    JSON_Value* jvParams = json_value_init_object();
    JSON_Object* joParams = json_value_get_object(jvParams);
    json_object_set_boolean(joParams, "offline", 1);

    JSON_Value* jvCertCache = json_value_init_object();
    json_object_set_string(json_value_get_object(jvCertCache), "path", certCacheDir.c_str());
    json_object_set_value(joParams, "certCache", jvCertCache);

    JSON_Value* jvCrlCache = json_value_init_object();
    json_object_set_string(json_value_get_object(jvCrlCache), "path", crlCacheDir.c_str());
    json_object_set_value(joParams, "crlCache", jvCrlCache);

    //  cm-pkcs12's provider_init() sets a single process-wide static (see
    //  openAndSelectFirstKey's comment) - call it exactly once here, via a
    //  proxy that's deliberately leaked for the process's lifetime rather
    //  than closed, since there's no matching nativeDeinit (crypto-service
    //  is a long-lived daemon, not something that tears this down).
    CmStorageProxy* bootstrapProxy = new CmStorageProxy();
    if (!bootstrapProxy->load("cm-pkcs12")) {
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

JNIEXPORT jbyteArray JNICALL Java_com_tarantelot_uapki_UapkiNative_nativeSignData(
        JNIEnv* env, jclass,
        jstring jPath, jstring jPassword, jbyteArray jData,
        jboolean includeData, jboolean includeCert, jboolean includeTime) {

    std::string path = jstringToStd(env, jPath);
    std::string password = jstringToStd(env, jPassword);

    CmStorageProxy storage;
    if (openAndSelectFirstKey(env, storage, path, password) != RET_OK) {
        return nullptr;
    }

    ByteArray* baData = jbyteArrayToBa(env, jData);

    JSON_Value* jvParams = json_value_init_object();
    JSON_Object* joParams = json_value_get_object(jvParams);
    JSON_Value* jvSignParams = json_value_init_object();
    JSON_Object* joSignParams = json_value_get_object(jvSignParams);
    json_object_set_string(joSignParams, "signatureFormat", "CMS");
    json_object_set_boolean(joSignParams, "detachedData", !includeData);
    json_object_set_boolean(joSignParams, "includeCert", includeCert);
    json_object_set_boolean(joSignParams, "includeTime", includeTime);
    json_object_set_boolean(joSignParams, "includeContentTS", 0);
    json_object_set_value(joParams, "signParams", jvSignParams);

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

}  // extern "C"
