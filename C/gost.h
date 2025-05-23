#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

// ======== Attribute Macros ========
#if defined(__GNUC__) || defined(__clang__)
#define __attr_nodiscard __attribute__((warn_unused_result))
#define __attr_malloc __attribute__((malloc))
#define __attr_hot __attribute__((hot))
#define __attr_cold __attribute__((cold))
#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#else
#define __attr_nodiscard
#define __attr_malloc
#define __attr_hot
#define __attr_cold
#define likely(x)   (x)
#define unlikely(x) (x)
#endif

#ifdef __cplusplus
#define __restrict__ __restrict
#else
#define __restrict__ restrict
#endif

#ifdef __cplusplus
#define __noexcept noexcept
#define __const_noexcept const noexcept
#else
#define __noexcept
#define __const_noexcept
#endif

#define GOST_KEY_SIZE 32
#define GOST_BLOCK_SIZE 8
#define GOST_SUBKEY_COUNT 8
#define GOST_NUM_ROUNDS 32

static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char b64_pad = '=';

// ========== Utility Functions ==========

__attr_cold
void gost_fail(const char* msg) {
    fprintf(stderr, "GOST error: %s\n", msg);
    exit(1);
}

// Hex encoding
__attr_nodiscard __attr_malloc
char* gost_to_hex(const uint8_t* data, size_t len) {
    static const char hex[] = "0123456789abcdef";
    char* out = (char*)malloc(len * 2 + 1);
    if (!out) gost_fail("malloc failed in gost_to_hex");
    for (size_t i = 0; i < len; ++i) {
        out[i*2] = hex[data[i] >> 4];
        out[i*2+1] = hex[data[i] & 0xF];
    }
    out[len*2] = 0;
    return out;
}

__attr_nodiscard __attr_malloc
uint8_t* gost_from_hex(const char* hexstr, size_t* outlen) {
    size_t len = strlen(hexstr);
    if (len % 2 != 0)
        gost_fail("Odd length hex string");
    *outlen = len / 2;
    uint8_t* out = (uint8_t*)malloc(*outlen);
    if (!out) gost_fail("malloc failed in gost_from_hex");
    for (size_t i = 0; i < *outlen; ++i) {
        sscanf(hexstr + 2*i, "%2hhx", &out[i]);
    }
    return out;
}

__attr_nodiscard __attr_malloc
char* gost_to_base64(const uint8_t* data, size_t len) {
    size_t out_len = 4 * ((len + 2) / 3);
    char* out = (char*)malloc(out_len + 1);
    if (!out) gost_fail("malloc failed in gost_to_base64");
    size_t j = 0;
    int val = 0, valb = -6;
    for (size_t i = 0; i < len; ++i) {
        val = (val << 8) + data[i];
        valb += 8;
        while (valb >= 0) {
            out[j++] = b64_table[(val >> valb) & 0x3F];
            valb -= 6;
        }
    }
    if (valb > -6) out[j++] = b64_table[((val << 8) >> (valb + 8)) & 0x3F];
    while (j % 4) out[j++] = b64_pad;
    out[j] = 0;
    return out;
}

__attr_nodiscard __attr_malloc
uint8_t* gost_from_base64(const char* b64, size_t* outlen) {
    int val = 0, valb = -8;
    size_t len = strlen(b64);
    uint8_t* out = (uint8_t*)malloc(len * 3 / 4 + 1);
    if (!out) gost_fail("malloc failed in gost_from_base64");
    size_t j = 0;
    for (size_t i = 0; i < len; ++i) {
        char c = b64[i];
        if (c == b64_pad) break;
        const char* p = strchr(b64_table, c);
        if (!p) break;
        val = (val << 6) + (p - b64_table);
        valb += 6;
        if (valb >= 0) {
            out[j++] = (uint8_t)((val >> valb) & 0xFF);
            valb -= 8;
        }
    }
    *outlen = j;
    return out;
}

// PKCS7 Padding
__attr_hot
void gost_pkcs7_pad(const uint8_t* data, size_t datalen, uint8_t** out, size_t* outlen) {
    size_t pad_len = GOST_BLOCK_SIZE - (datalen % GOST_BLOCK_SIZE);
    if (pad_len == 0) pad_len = GOST_BLOCK_SIZE;
    *outlen = datalen + pad_len;
    *out = (uint8_t*)malloc(*outlen);
    if (!*out) gost_fail("malloc failed in gost_pkcs7_pad");
    memcpy(*out, data, datalen);
    memset(*out + datalen, pad_len, pad_len);
}

__attr_nodiscard __attr_malloc __attr_hot
uint8_t* gost_pkcs7_unpad(const uint8_t* data, size_t datalen, size_t* outlen) {
    if (datalen == 0 || datalen % GOST_BLOCK_SIZE != 0)
        gost_fail("Invalid padding size");
    uint8_t pad_len = data[datalen-1];
    if (pad_len == 0 || pad_len > GOST_BLOCK_SIZE)
        gost_fail("Invalid padding value");
    for (size_t i = datalen - pad_len; i < datalen; ++i)
        if (data[i] != pad_len)
            gost_fail("Invalid padding content");
    *outlen = datalen - pad_len;
    uint8_t* out = (uint8_t*)malloc(*outlen);
    if (!out) gost_fail("malloc failed in gost_pkcs7_unpad");
    memcpy(out, data, *outlen);
    return out;
}

// XOR utility
__attr_hot
void gost_xor(uint8_t* __restrict__ out, const uint8_t* __restrict__ a, const uint8_t* __restrict__ b, size_t len) {
    for (size_t i = 0; i < len; ++i)
        out[i] = a[i] ^ b[i];
}

// Increment counter (CTR)
__attr_hot
void gost_increment_counter(uint8_t* counter) {
    for (int i = GOST_BLOCK_SIZE - 1; i >= 0; --i) {
        if (++counter[i] != 0) break;
    }
}

// ========== GOST Key/IV Generation ==========

__attr_hot
void gost_random_bytes(uint8_t* buf, size_t n) {
    srand((unsigned)time(NULL));
    for (size_t i = 0; i < n; ++i) {
        buf[i] = rand() & 0xFF;
    }
}

__attr_hot
void gost_generate_key(uint8_t* key) {
    gost_random_bytes(key, GOST_KEY_SIZE);
}

__attr_hot
void gost_generate_iv(uint8_t* iv, size_t ivsize) {
    gost_random_bytes(iv, ivsize);
}

// ========== GOST S-box ==========

static const uint8_t GOST_SBOX[8][16] = {
    {4,10,9,2,13,8,0,14,6,11,1,12,7,15,5,3},
    {14,11,4,12,6,13,15,10,2,3,8,1,0,7,5,9},
    {5,8,1,13,10,3,4,2,14,15,12,7,6,0,9,11},
    {7,13,10,1,0,8,9,15,14,4,6,12,11,2,5,3},
    {6,12,7,1,5,15,13,8,4,10,9,14,0,3,11,2},
    {4,11,10,0,7,2,1,13,3,6,8,5,9,12,15,14},
    {13,11,4,1,3,15,5,9,0,10,14,7,6,8,2,12},
    {1,15,13,0,5,10,3,14,9,7,6,8,2,11,4,12}
};

// ========== GOST Core ==========

__attr_hot
static uint32_t gost_get32le(const uint8_t* p) {
    return ((uint32_t)p[0]) | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

__attr_hot
static void gost_put32le(uint8_t* p, uint32_t v) {
    p[0] = v & 0xFF;
    p[1] = (v >> 8) & 0xFF;
    p[2] = (v >> 16) & 0xFF;
    p[3] = (v >> 24) & 0xFF;
}

__attr_hot
static uint32_t gost_f(uint32_t data, const uint32_t* k) {
    uint32_t x = data + *k;
    uint32_t y = 0;
    for (int i = 0; i < 8; ++i)
        y |= GOST_SBOX[i][(x >> (4 * i)) & 0xF] << (4 * i);
    return (y << 11) | (y >> (32 - 11));
}

// Key schedule
__attr_hot
static void gost_key_schedule(uint32_t* key, const uint8_t* userkey) {
    for (size_t i = 0; i < GOST_SUBKEY_COUNT; ++i)
        key[i] = gost_get32le(userkey + i * 4);
}

// Encrypt a single block (8 bytes)
__attr_hot
static void gost_encrypt_block(const uint8_t* in, uint8_t* out, const uint32_t* key) {
    uint32_t n1 = gost_get32le(in);
    uint32_t n2 = gost_get32le(in + 4);

    for (int i = 0; i < 24; ++i) {
        uint32_t tmp = n1;
        n1 = n2 ^ gost_f(n1, &key[i % 8]);
        n2 = tmp;
    }
    for (int i = 0; i < 8; ++i) {
        uint32_t tmp = n1;
        n1 = n2 ^ gost_f(n1, &key[7 - (i % 8)]);
        n2 = tmp;
    }
    gost_put32le(out, n2);
    gost_put32le(out + 4, n1);
}

// Decrypt a single block
__attr_hot
static void gost_decrypt_block(const uint8_t* in, uint8_t* out, const uint32_t* key) {
    uint32_t n1 = gost_get32le(in);
    uint32_t n2 = gost_get32le(in + 4);

    for (int i = 0; i < 8; ++i) {
        uint32_t tmp = n1;
        n1 = n2 ^ gost_f(n1, &key[i % 8]);
        n2 = tmp;
    }
    for (int i = 0; i < 24; ++i) {
        uint32_t tmp = n1;
        n1 = n2 ^ gost_f(n1, &key[7 - (i % 8)]);
        n2 = tmp;
    }
    gost_put32le(out, n2);
    gost_put32le(out + 4, n1);
}

// ========== Mode Implementations ==========

// ECB mode
__attr_hot
void gost_ecb_encrypt(const uint8_t* plaintext, size_t len, const uint8_t* key, uint8_t** ciphertext, size_t* outlen) {
    uint8_t* padded;
    gost_pkcs7_pad(plaintext, len, &padded, outlen);
    *ciphertext = (uint8_t*)malloc(*outlen);
    if (!*ciphertext) gost_fail("malloc failed in gost_ecb_encrypt");
    uint32_t k[GOST_SUBKEY_COUNT];
    gost_key_schedule(k, key);
    for (size_t i = 0; i < *outlen; i += GOST_BLOCK_SIZE)
        gost_encrypt_block(padded + i, *ciphertext + i, k);
    free(padded);
}

__attr_hot
void gost_ecb_decrypt(const uint8_t* ciphertext, size_t len, const uint8_t* key, uint8_t** plaintext, size_t* outlen) {
    if (len == 0 || len % GOST_BLOCK_SIZE != 0)
        gost_fail("ECB: Ciphertext size invalid");
    uint8_t* padded = (uint8_t*)malloc(len);
    if (!padded) gost_fail("malloc failed in gost_ecb_decrypt");
    uint32_t k[GOST_SUBKEY_COUNT];
    gost_key_schedule(k, key);
    for (size_t i = 0; i < len; i += GOST_BLOCK_SIZE)
        gost_decrypt_block(ciphertext + i, padded + i, k);
    *plaintext = gost_pkcs7_unpad(padded, len, outlen);
    free(padded);
}

// CBC mode
__attr_hot
void gost_cbc_encrypt(const uint8_t* plaintext, size_t len, const uint8_t* key, const uint8_t* iv, uint8_t** ciphertext, size_t* outlen) {
    uint8_t* padded;
    gost_pkcs7_pad(plaintext, len, &padded, outlen);
    *ciphertext = (uint8_t*)malloc(*outlen);
    if (!*ciphertext) gost_fail("malloc failed in gost_cbc_encrypt");
    uint32_t k[GOST_SUBKEY_COUNT];
    gost_key_schedule(k, key);
    uint8_t prev[GOST_BLOCK_SIZE];
    memcpy(prev, iv, GOST_BLOCK_SIZE);
    for (size_t i = 0; i < *outlen; i += GOST_BLOCK_SIZE) {
        uint8_t block[GOST_BLOCK_SIZE];
        gost_xor(block, padded + i, prev, GOST_BLOCK_SIZE);
        gost_encrypt_block(block, *ciphertext + i, k);
        memcpy(prev, *ciphertext + i, GOST_BLOCK_SIZE);
    }
    free(padded);
}

__attr_hot
void gost_cbc_decrypt(const uint8_t* ciphertext, size_t len, const uint8_t* key, const uint8_t* iv, uint8_t** plaintext, size_t* outlen) {
    if (len == 0 || len % GOST_BLOCK_SIZE != 0)
        gost_fail("CBC: Ciphertext size invalid");
    uint8_t* padded = (uint8_t*)malloc(len);
    if (!padded) gost_fail("malloc failed in gost_cbc_decrypt");
    uint32_t k[GOST_SUBKEY_COUNT];
    gost_key_schedule(k, key);
    uint8_t prev[GOST_BLOCK_SIZE];
    memcpy(prev, iv, GOST_BLOCK_SIZE);
    for (size_t i = 0; i < len; i += GOST_BLOCK_SIZE) {
        gost_decrypt_block(ciphertext + i, padded + i, k);
        for (size_t j = 0; j < GOST_BLOCK_SIZE; ++j)
            padded[i + j] ^= prev[j];
        memcpy(prev, ciphertext + i, GOST_BLOCK_SIZE);
    }
    *plaintext = gost_pkcs7_unpad(padded, len, outlen);
    free(padded);
}

// CFB mode
__attr_hot
void gost_cfb_encrypt(const uint8_t* plaintext, size_t len, const uint8_t* key, const uint8_t* iv, uint8_t** ciphertext) {
    *ciphertext = (uint8_t*)malloc(len);
    if (!*ciphertext) gost_fail("malloc failed in gost_cfb_encrypt");
    uint32_t k[GOST_SUBKEY_COUNT];
    gost_key_schedule(k, key);
    uint8_t prev[GOST_BLOCK_SIZE];
    memcpy(prev, iv, GOST_BLOCK_SIZE);
    for (size_t i = 0; i < len; i += GOST_BLOCK_SIZE) {
        uint8_t enc[GOST_BLOCK_SIZE];
        gost_encrypt_block(prev, enc, k);
        size_t chunk = ((len - i) < GOST_BLOCK_SIZE) ? (len - i) : GOST_BLOCK_SIZE;
        for (size_t j = 0; j < chunk; ++j)
            (*ciphertext)[i + j] = plaintext[i + j] ^ enc[j];
        memcpy(prev, (*ciphertext) + i, chunk);
        if (chunk < GOST_BLOCK_SIZE)
            memcpy(prev + chunk, prev + chunk, GOST_BLOCK_SIZE - chunk);
    }
}

__attr_hot
void gost_cfb_decrypt(const uint8_t* ciphertext, size_t len, const uint8_t* key, const uint8_t* iv, uint8_t** plaintext) {
    *plaintext = (uint8_t*)malloc(len);
    if (!*plaintext) gost_fail("malloc failed in gost_cfb_decrypt");
    uint32_t k[GOST_SUBKEY_COUNT];
    gost_key_schedule(k, key);
    uint8_t prev[GOST_BLOCK_SIZE];
    memcpy(prev, iv, GOST_BLOCK_SIZE);
    for (size_t i = 0; i < len; i += GOST_BLOCK_SIZE) {
        uint8_t enc[GOST_BLOCK_SIZE];
        gost_encrypt_block(prev, enc, k);
        size_t chunk = ((len - i) < GOST_BLOCK_SIZE) ? (len - i) : GOST_BLOCK_SIZE;
        for (size_t j = 0; j < chunk; ++j)
            (*plaintext)[i + j] = ciphertext[i + j] ^ enc[j];
        memcpy(prev, ciphertext + i, chunk);
        if (chunk < GOST_BLOCK_SIZE)
            memcpy(prev + chunk, prev + chunk, GOST_BLOCK_SIZE - chunk);
    }
}

// OFB mode
__attr_hot
void gost_ofb_crypt(const uint8_t* input, size_t len, const uint8_t* key, const uint8_t* iv, uint8_t** output) {
    *output = (uint8_t*)malloc(len);
    if (!*output) gost_fail("malloc failed in gost_ofb_crypt");
    uint32_t k[GOST_SUBKEY_COUNT];
    gost_key_schedule(k, key);
    uint8_t ofb[GOST_BLOCK_SIZE];
    memcpy(ofb, iv, GOST_BLOCK_SIZE);
    for (size_t i = 0; i < len; i += GOST_BLOCK_SIZE) {
        uint8_t outblock[GOST_BLOCK_SIZE];
        gost_encrypt_block(ofb, outblock, k);
        size_t chunk = ((len - i) < GOST_BLOCK_SIZE) ? (len - i) : GOST_BLOCK_SIZE;
        for (size_t j = 0; j < chunk; ++j)
            (*output)[i + j] = input[i + j] ^ outblock[j];
        memcpy(ofb, outblock, GOST_BLOCK_SIZE);
    }
}

// CTR mode
__attr_hot
void gost_ctr_crypt(const uint8_t* input, size_t len, const uint8_t* key, const uint8_t* nonce, uint8_t** output) {
    *output = (uint8_t*)malloc(len);
    if (!*output) gost_fail("malloc failed in gost_ctr_crypt");
    uint32_t k[GOST_SUBKEY_COUNT];
    gost_key_schedule(k, key);
    uint8_t counter[GOST_BLOCK_SIZE];
    memcpy(counter, nonce, GOST_BLOCK_SIZE);
    for (size_t i = 0; i < len; i += GOST_BLOCK_SIZE) {
        uint8_t keystream[GOST_BLOCK_SIZE];
        gost_encrypt_block(counter, keystream, k);
        size_t chunk = ((len - i) < GOST_BLOCK_SIZE) ? (len - i) : GOST_BLOCK_SIZE;
        for (size_t j = 0; j < chunk; ++j)
            (*output)[i + j] = input[i + j] ^ keystream[j];
        gost_increment_counter(counter);
    }
}
