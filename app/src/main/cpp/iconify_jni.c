/*
 * Iconify native JNI layer
 *
 * Provides C implementations of three hot-path operations:
 *   1. BitmapSubjectSegmenter — per-pixel confidence-mask application
 *   2. ZipUtils              — ZIP End-of-Central-Directory scan
 *   3. ApkSignerV2           — APK v2 content-digest computation (SHA-256 / SHA-512)
 */

#include <jni.h>
#include <android/bitmap.h>
#include <android/log.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "sha256.h"
#include "sha512.h"

#define LOG_TAG "IconifyNative"
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

/* ═══════════════════════════════════════════════════════════════════════════
 * 1. BitmapSubjectSegmenter — apply foreground confidence mask
 *
 * Java declaration (in BitmapSubjectSegmenter.kt):
 *   private external fun nativeApplyMask(bitmap: Bitmap, mask: FloatBuffer)
 * ═══════════════════════════════════════════════════════════════════════════ */

JNIEXPORT void JNICALL
Java_com_drdisagree_iconify_xposed_modules_extras_utils_misc_BitmapSubjectSegmenter_nativeApplyMask(
        JNIEnv *env, jobject thiz, jobject bitmap, jobject floatBuffer)
{
    (void)thiz;

    AndroidBitmapInfo info;
    if (AndroidBitmap_getInfo(env, bitmap, &info) < 0) {
        LOGE("nativeApplyMask: getInfo failed");
        return;
    }
    if (info.format != ANDROID_BITMAP_FORMAT_RGBA_8888) {
        LOGE("nativeApplyMask: expected RGBA_8888, got %d", info.format);
        return;
    }

    void *pixels;
    if (AndroidBitmap_lockPixels(env, bitmap, &pixels) < 0) {
        LOGE("nativeApplyMask: lockPixels failed");
        return;
    }

    const int total  = (int)(info.width * info.height);
    uint32_t *px     = (uint32_t *)pixels;

    /* Try the fast path: direct buffer (MLKit always returns one) */
    const float *mask = (const float *)(*env)->GetDirectBufferAddress(env, floatBuffer);
    jlong maskCap = mask ? (*env)->GetDirectBufferCapacity(env, floatBuffer) / (jlong)sizeof(float) : 0;

    if (mask && maskCap >= total) {
        /* Hot loop — compiler can auto-vectorise with -O3 */
        for (int i = 0; i < total; i++) {
            if (mask[i] < 0.5f) px[i] = 0u;
        }
    } else {
        /* Fallback: call FloatBuffer.get() via JNI */
        jclass  bufClass  = (*env)->GetObjectClass(env, floatBuffer);
        jmethodID getMid  = (*env)->GetMethodID(env, bufClass, "get", "()F");
        jmethodID rewMid  = (*env)->GetMethodID(env, bufClass, "rewind", "()Ljava/nio/Buffer;");
        if (!getMid) {
            LOGE("nativeApplyMask: FloatBuffer.get() not found");
            AndroidBitmap_unlockPixels(env, bitmap);
            return;
        }
        if (rewMid) (*env)->CallObjectMethod(env, floatBuffer, rewMid);
        for (int i = 0; i < total; i++) {
            if ((*env)->CallFloatMethod(env, floatBuffer, getMid) < 0.5f)
                px[i] = 0u;
        }
    }

    AndroidBitmap_unlockPixels(env, bitmap);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 2. ZipUtils — find ZIP End-of-Central-Directory record
 *
 * Java declaration (in ZipUtils.java):
 *   private static native int nativeFindEocd(byte[] data, int size);
 * ═══════════════════════════════════════════════════════════════════════════ */

#define EOCD_MIN_SIZE       22
#define EOCD_SIG            0x06054b50u
#define EOCD_COMMENT_OFFSET 20
#define UINT16_MAX_VAL      0xffff

JNIEXPORT jint JNICALL
Java_com_drdisagree_iconify_core_utils_apksigner_ZipUtils_nativeFindEocd(
        JNIEnv *env, jclass clazz, jbyteArray data, jint size)
{
    (void)clazz;
    if (size < EOCD_MIN_SIZE) return -1;

    jbyte *buf = (*env)->GetByteArrayElements(env, data, NULL);
    if (!buf) return -1;

    const uint8_t *b = (const uint8_t *)buf;
    int maxComment   = size - EOCD_MIN_SIZE;
    if (maxComment > UINT16_MAX_VAL) maxComment = UINT16_MAX_VAL;
    int base = size - EOCD_MIN_SIZE;
    int found = -1;

    for (int exp = 0; exp <= maxComment; exp++) {
        int pos = base - exp;
        /* little-endian 4-byte signature */
        uint32_t sig = (uint32_t)b[pos]
                     | ((uint32_t)b[pos+1] << 8)
                     | ((uint32_t)b[pos+2] << 16)
                     | ((uint32_t)b[pos+3] << 24);
        if (sig == EOCD_SIG) {
            uint16_t commentLen = (uint16_t)b[pos + EOCD_COMMENT_OFFSET]
                                | ((uint16_t)b[pos + EOCD_COMMENT_OFFSET + 1] << 8);
            if (commentLen == (uint16_t)exp) {
                found = pos;
                break;
            }
        }
    }

    (*env)->ReleaseByteArrayElements(env, data, buf, JNI_ABORT);
    return found;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 3. ApkSignerV2 — full APK v2 content-digest (SHA-256 or SHA-512)
 *
 * Implements the Merkle-like structure from the APK Signature Scheme v2 spec:
 *   • Split each segment into 1 MB chunks.
 *   • Each chunk digest = SHA(0xa5 || chunkLen-LE32 || chunkData).
 *   • Final digest     = SHA(0x5a || chunkCount-LE32 || concat(chunkDigests)).
 *
 * Java declaration (in ApkSignerV2.java):
 *   private static native byte[] nativeComputeContentDigest(
 *       int algorithm, byte[][] segments);
 *   algorithm: 0 = SHA-256 (32-byte result), 1 = SHA-512 (64-byte result)
 * ═══════════════════════════════════════════════════════════════════════════ */

#define DIGEST_SHA256   0
#define DIGEST_SHA512   1
#define CHUNK_MAX       (1024 * 1024)

static inline void le32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static void chunk_digest_sha256(const uint8_t *data, int len, uint8_t *out)
{
    uint8_t prefix[5];
    prefix[0] = 0xa5;
    le32(prefix + 1, (uint32_t)len);
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, prefix, 5);
    sha256_update(&ctx, data, (size_t)len);
    sha256_final(&ctx, out);
}

static void chunk_digest_sha512(const uint8_t *data, int len, uint8_t *out)
{
    uint8_t prefix[5];
    prefix[0] = 0xa5;
    le32(prefix + 1, (uint32_t)len);
    SHA512_CTX ctx;
    sha512_init(&ctx);
    sha512_update(&ctx, prefix, 5);
    sha512_update(&ctx, data, (size_t)len);
    sha512_final(&ctx, out);
}

JNIEXPORT jbyteArray JNICALL
Java_com_drdisagree_iconify_core_utils_apksigner_ApkSignerV2_nativeComputeContentDigest(
        JNIEnv *env, jclass clazz, jint algorithm, jobjectArray segments)
{
    (void)clazz;

    const int digestSize = (algorithm == DIGEST_SHA256) ? 32 : 64;
    jsize segCount = (*env)->GetArrayLength(env, segments);

    /* ── Pass 1: count total chunks ──────────────────────────────────────── */
    int totalChunks = 0;
    for (jsize s = 0; s < segCount; s++) {
        jbyteArray seg = (jbyteArray)(*env)->GetObjectArrayElement(env, segments, s);
        jsize len = (*env)->GetArrayLength(env, seg);
        if (len > 0) totalChunks += (int)((len + CHUNK_MAX - 1) / CHUNK_MAX);
        (*env)->DeleteLocalRef(env, seg);
    }

    /* ── Allocate concatenation buffer ───────────────────────────────────── */
    /* Layout: [0x5a, chunkCount-LE32, chunkDigest0, chunkDigest1, ...] */
    int concatLen = 5 + totalChunks * digestSize;
    uint8_t *concat = (uint8_t *)malloc((size_t)concatLen);
    if (!concat) {
        LOGE("nativeComputeContentDigest: malloc failed (%d bytes)", concatLen);
        return NULL;
    }
    concat[0] = 0x5a;
    le32(concat + 1, (uint32_t)totalChunks);

    /* ── Pass 2: compute per-chunk digests ───────────────────────────────── */
    int chunkIdx = 0;
    for (jsize s = 0; s < segCount; s++) {
        jbyteArray seg = (jbyteArray)(*env)->GetObjectArrayElement(env, segments, s);
        jsize segLen   = (*env)->GetArrayLength(env, seg);
        if (segLen == 0) { (*env)->DeleteLocalRef(env, seg); continue; }

        jbyte *segData = (*env)->GetByteArrayElements(env, seg, NULL);
        if (!segData) { (*env)->DeleteLocalRef(env, seg); continue; }

        const uint8_t *ptr = (const uint8_t *)segData;
        int remaining = (int)segLen;

        while (remaining > 0) {
            int chunkLen = remaining < CHUNK_MAX ? remaining : CHUNK_MAX;
            uint8_t *dest = concat + 5 + chunkIdx * digestSize;

            if (algorithm == DIGEST_SHA256)
                chunk_digest_sha256(ptr, chunkLen, dest);
            else
                chunk_digest_sha512(ptr, chunkLen, dest);

            ptr       += chunkLen;
            remaining -= chunkLen;
            chunkIdx++;
        }

        (*env)->ReleaseByteArrayElements(env, seg, segData, JNI_ABORT);
        (*env)->DeleteLocalRef(env, seg);
    }

    /* ── Final digest over the concatenation ─────────────────────────────── */
    uint8_t finalDigest[64];
    if (algorithm == DIGEST_SHA256) {
        SHA256_CTX ctx; sha256_init(&ctx);
        sha256_update(&ctx, concat, (size_t)concatLen);
        sha256_final(&ctx, finalDigest);
    } else {
        SHA512_CTX ctx; sha512_init(&ctx);
        sha512_update(&ctx, concat, (size_t)concatLen);
        sha512_final(&ctx, finalDigest);
    }
    free(concat);

    jbyteArray result = (*env)->NewByteArray(env, digestSize);
    if (result)
        (*env)->SetByteArrayRegion(env, result, 0, digestSize, (const jbyte *)finalDigest);
    return result;
}
