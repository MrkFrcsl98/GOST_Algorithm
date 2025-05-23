#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

// ========== Attribute Macros ==========
#if defined(__GNUC__) || defined(__clang__)
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#else
#define likely(x) (x)
#define unlikely(x) (x)
#endif

#ifdef __cplusplus
#define __restrict__ __restrict
#define __noexcept noexcept
#define __const_noexcept noexcept
#else
#define __restrict__ restrict
#define __noexcept
#define __const_noexcept
#endif

enum class GOST_KEY_SIZE : size_t
{
    BITS_256 = 32
};

struct GOST_ECB_Mode {};
struct GOST_CBC_Mode {};
struct GOST_CFB_Mode {};
struct GOST_OFB_Mode {};
struct GOST_CTR_Mode {};

namespace gost_detail
{
[[noreturn]] inline void fail(const char *msg)
{
    throw std::runtime_error(msg);
}
}

namespace gost_util
{
static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char b64_pad = '=';

inline std::string toHex(const std::string &data)
{
    static const char hex[] = "0123456789abcdef";
    std::string out;
    out.reserve(data.size() * 2);
    for (uint8_t b : data)
    {
        out.push_back(hex[b >> 4]);
        out.push_back(hex[b & 0xF]);
    }
    return out;
}

inline std::string fromHex(const std::string &hexStr)
{
    std::string out;
    if (hexStr.size() % 2 != 0) {
        gost_detail::fail("Odd length hex string");
    }
    out.reserve(hexStr.size() / 2);
    for (size_t i = 0; i < hexStr.size(); i += 2)
    {
        uint8_t hi = static_cast<uint8_t>(std::stoi(hexStr.substr(i, 1), nullptr, 16));
        uint8_t lo = static_cast<uint8_t>(std::stoi(hexStr.substr(i + 1, 1), nullptr, 16));
        out.push_back((hi << 4) | lo);
    }
    return out;
}

inline std::string toBase64(const std::string &data)
{
    std::string out;
    int val = 0, valb = -6;
    for (uint8_t c : data)
    {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0)
        {
            out.push_back(b64_table[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6)
        out.push_back(b64_table[((val << 8) >> (valb + 8)) & 0x3F]);
    while (out.size() % 4)
        out.push_back(b64_pad);
    return out;
}

inline std::string fromBase64(const std::string &b64)
{
    int val = 0, valb = -8;
    std::string out;
    for (uint8_t c : b64)
    {
        if (c == b64_pad)
            break;
        const char *p = std::find(b64_table, b64_table + 64, c);
        if (p == b64_table + 64)
            break;
        val = (val << 6) + (p - b64_table);
        valb += 6;
        if (valb >= 0)
        {
            out.push_back(char((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return out;
}
}

class GOSTKeyIVGenerator
{
public:
    static std::string generateKey(GOST_KEY_SIZE keySize = GOST_KEY_SIZE::BITS_256)
    {
        size_t size = static_cast<size_t>(keySize);
        std::string key(size, '\0');
        randomFill(reinterpret_cast<uint8_t *>(&key[0]), size);
        return key;
    }
    static std::string generateIV(size_t ivSize = 8)
    {
        std::string iv(ivSize, '\0');
        randomFill(reinterpret_cast<uint8_t *>(&iv[0]), ivSize);
        return iv;
    }

private:
    static void randomFill(uint8_t *buf, size_t n)
    {
        std::random_device rd;
        for (size_t i = 0; i < n; ++i)
        {
            buf[i] = static_cast<uint8_t>(rd());
        }
    }
};

class GOSTResult
{
    std::string data_;
public:
    GOSTResult(const std::string &data) : data_(data) {}
    GOSTResult toHex() const { return GOSTResult(gost_util::toHex(data_)); }
    GOSTResult fromHex() const { return GOSTResult(gost_util::fromHex(data_)); }
    GOSTResult toBase64() const { return GOSTResult(gost_util::toBase64(data_)); }
    GOSTResult fromBase64() const { return GOSTResult(gost_util::fromBase64(data_)); }
    std::string asString() const { return data_; }
    operator std::string() const { return data_; }
};

template <GOST_KEY_SIZE KEY_SZ = GOST_KEY_SIZE::BITS_256>
class GOST
{
public:
    using uint = uint32_t;
    using uchar = uint8_t;
    static constexpr size_t BlockSize = 8;
    static constexpr size_t KeySize = static_cast<size_t>(KEY_SZ);

    struct ECB
    {
        static GOSTResult Encrypt(const std::string &plaintext, const std::string &key)
        {
            GOST cipher;
            return GOSTResult(cipher.encryptECB(plaintext, key));
        }
        static GOSTResult Decrypt(const std::string &ciphertext, const std::string &key)
        {
            GOST cipher;
            return GOSTResult(cipher.decryptECB(ciphertext, key));
        }
    };
    struct CBC
    {
        static GOSTResult Encrypt(const std::string &plaintext, const std::string &key, const std::string &iv)
        {
            GOST cipher;
            return GOSTResult(cipher.encryptCBC(plaintext, key, iv));
        }
        static GOSTResult Decrypt(const std::string &ciphertext, const std::string &key, const std::string &iv)
        {
            GOST cipher;
            return GOSTResult(cipher.decryptCBC(ciphertext, key, iv));
        }
    };
    struct CFB
    {
        static GOSTResult Encrypt(const std::string &plaintext, const std::string &key, const std::string &iv)
        {
            GOST cipher;
            return GOSTResult(cipher.encryptCFB(plaintext, key, iv));
        }
        static GOSTResult Decrypt(const std::string &ciphertext, const std::string &key, const std::string &iv)
        {
            GOST cipher;
            return GOSTResult(cipher.decryptCFB(ciphertext, key, iv));
        }
    };
    struct OFB
    {
        static GOSTResult Encrypt(const std::string &plaintext, const std::string &key, const std::string &iv)
        {
            GOST cipher;
            return GOSTResult(cipher.encryptOFB(plaintext, key, iv));
        }
        static GOSTResult Decrypt(const std::string &ciphertext, const std::string &key, const std::string &iv)
        {
            GOST cipher;
            return GOSTResult(cipher.decryptOFB(ciphertext, key, iv));
        }
    };
    struct CTR
    {
        static GOSTResult Encrypt(const std::string &plaintext, const std::string &key, const std::string &nonce)
        {
            GOST cipher;
            return GOSTResult(cipher.encryptCTR(plaintext, key, nonce));
        }
        static GOSTResult Decrypt(const std::string &ciphertext, const std::string &key, const std::string &nonce)
        {
            GOST cipher;
            return GOSTResult(cipher.decryptCTR(ciphertext, key, nonce));
        }
    };

private:
    static constexpr size_t NumRounds = 32;
    static constexpr size_t SubkeyCount = 8;

    static constexpr uint8_t SBOX[8][16] = {
        {4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3},
        {14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9},
        {5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11},
        {7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3},
        {6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2},
        {4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14},
        {13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12},
        {1, 15, 13, 0, 5, 10, 3, 14, 9, 7, 6, 8, 2, 11, 4, 12}
    };

    std::string pkcs7Pad(const std::string &data) const __noexcept
    {
        size_t padLen = BlockSize - (data.size() % BlockSize);
        if (padLen == 0) padLen = BlockSize;
        std::string padded = data;
        padded.append(padLen, static_cast<char>(padLen));
        return padded;
    }
    std::string pkcs7Unpad(const std::string &data) const
    {
        if (unlikely(data.empty() || data.size() % BlockSize != 0))
        {
            gost_detail::fail("GOST: pkcs7Unpad: Invalid padding size.");
        }
        uchar padLen = static_cast<uchar>(data.back());
        if (unlikely(padLen == 0 || padLen > BlockSize))
        {
            gost_detail::fail("GOST: pkcs7Unpad: Invalid padding value.");
        }
        for (size_t i = data.size() - padLen; i < data.size(); ++i)
        {
            if (unlikely(static_cast<uchar>(data[i]) != padLen))
            {
                gost_detail::fail("GOST: pkcs7Unpad: Invalid padding content.");
            }
        }
        std::string result = data.substr(0, data.size() - padLen);
        return result;
    }

    static std::string xorStrings(const std::string &a, const std::string &b) __noexcept
    {
        if (unlikely(a.size() != b.size()))
        {
            gost_detail::fail("GOST: xorStrings: Inputs must have equal size.");
        }
        std::string out(a.size(), '\0');
        for (size_t i = 0; i < a.size(); ++i)
            out[i] = a[i] ^ b[i];
        return out;
    }

    static void incrementCounter(std::string &counter) __noexcept
    {
        for (int i = BlockSize - 1; i >= 0; --i)
        {
            uint8_t &b = reinterpret_cast<uint8_t &>(counter[i]);
            if (++b != 0)
                break;
        }
    }

    static uint32_t f(uint32_t data, const uint32_t *k)
    {
        uint32_t x = data + *k;
        uint32_t y = 0;
        for (int i = 0; i < 8; ++i)
            y |= SBOX[i][(x >> (4 * i)) & 0xF] << (4 * i);
        // 11-bit left rotation
        return (y << 11) | (y >> (32 - 11));
    }

void encryptBlock(const uchar *in, uchar *out, const uint32_t *key) const
{
    uint32_t n1 = get32le(in);
    uint32_t n2 = get32le(in + 4);

    for (int i = 0; i < 24; ++i)
    {
        uint32_t tmp = n1;
        n1 = n2 ^ f(n1, &key[i % 8]);
        n2 = tmp;
    }
    for (int i = 0; i < 8; ++i)
    {
        uint32_t tmp = n1;
        n1 = n2 ^ f(n1, &key[7 - (i % 8)]);
        n2 = tmp;
    }
    // OUTPUT SWAP HERE!
    put32le(out, n2);
    put32le(out + 4, n1);
}

void decryptBlock(const uchar *in, uchar *out, const uint32_t *key) const
{
    uint32_t n1 = get32le(in);
    uint32_t n2 = get32le(in + 4);
    for (int i = 0; i < 8; ++i) {
        uint32_t tmp = n1;
        n1 = n2 ^ f(n1, &key[i % 8]);
        n2 = tmp;
    }
    for (int i = 0; i < 24; ++i) {
        uint32_t tmp = n1;
        n1 = n2 ^ f(n1, &key[7 - (i % 8)]);
        n2 = tmp;
    }
    // OUTPUT SWAP HERE!
    put32le(out, n2);
    put32le(out + 4, n1);
}

    static uint32_t get32le(const uchar *p)
    {
        return uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
    }
    static void put32le(uchar *p, uint32_t v)
    {
        p[0] = v & 0xFF;
        p[1] = (v >> 8) & 0xFF;
        p[2] = (v >> 16) & 0xFF;
        p[3] = (v >> 24) & 0xFF;
    }

    void keySchedule(std::array<uint32_t, SubkeyCount> &key, const std::string &userKey) const
    {
        if (userKey.size() != KeySize) {
            gost_detail::fail("GOST: keySchedule: Key must be 32 bytes.");
        }
        for (size_t i = 0; i < SubkeyCount; ++i)
            key[i] = get32le(reinterpret_cast<const uchar *>(&userKey[i * 4]));
    }

    std::string encryptECB(const std::string &plaintext, const std::string &keystr) const __const_noexcept
    {
        auto padded = pkcs7Pad(plaintext);
        std::string ciphertext;
        ciphertext.resize(padded.size());
        std::array<uint32_t, SubkeyCount> key;
        keySchedule(key, keystr);

        for (size_t i = 0; i < padded.size(); i += BlockSize) {
            encryptBlock(reinterpret_cast<const uchar *>(&padded[i]), reinterpret_cast<uchar *>(&ciphertext[i]), key.data());
        }

        return ciphertext;
    }

    std::string decryptECB(const std::string &ciphertext, const std::string &keystr) const __const_noexcept
    {
        if (unlikely(ciphertext.empty() || (ciphertext.size() % BlockSize) != 0)) {
            gost_detail::fail("GOST: decryptECB: Ciphertext size must be a positive multiple of 8 bytes.");
        }
        std::string padded;
        padded.resize(ciphertext.size());
        std::array<uint32_t, SubkeyCount> key;
        keySchedule(key, keystr);

        for (size_t i = 0; i < ciphertext.size(); i += BlockSize) {
            decryptBlock(reinterpret_cast<const uchar *>(&ciphertext[i]), reinterpret_cast<uchar *>(&padded[i]), key.data());
        }

        std::string result = pkcs7Unpad(padded);
        return result;
    }

    std::string encryptCBC(const std::string &plaintext, const std::string &keystr, const std::string &iv) const __const_noexcept
    {
        if (unlikely(iv.size() != BlockSize)) {
            gost_detail::fail("GOST: encryptCBC: IV must be 8 bytes.");
        }
        auto padded = pkcs7Pad(plaintext);
        std::string ciphertext;
        ciphertext.resize(padded.size());
        std::array<uint32_t, SubkeyCount> key;
        keySchedule(key, keystr);

        std::string prev = iv;
        for (size_t i = 0; i < padded.size(); i += BlockSize)
        {
            std::string block = xorStrings(padded.substr(i, BlockSize), prev);
            encryptBlock(reinterpret_cast<const uchar *>(block.data()), reinterpret_cast<uchar *>(&ciphertext[i]), key.data());
            prev = ciphertext.substr(i, BlockSize);
        }
        return ciphertext;
    }

    std::string decryptCBC(const std::string &ciphertext, const std::string &keystr, const std::string &iv) const __const_noexcept
    {
        if (unlikely(iv.size() != BlockSize)) {
            gost_detail::fail("GOST: decryptCBC: IV must be 8 bytes.");
        }
        if (unlikely(ciphertext.empty() || (ciphertext.size() % BlockSize) != 0)) {
            gost_detail::fail("GOST: decryptCBC: Ciphertext size must be a positive multiple of 8 bytes.");
        }
        std::string padded;
        padded.resize(ciphertext.size());
        std::array<uint32_t, SubkeyCount> key;
        keySchedule(key, keystr);

        std::string prev = iv;
        for (size_t i = 0; i < ciphertext.size(); i += BlockSize)
        {
            decryptBlock(reinterpret_cast<const uchar *>(&ciphertext[i]), reinterpret_cast<uchar *>(&padded[i]), key.data());
            for (size_t j = 0; j < BlockSize; ++j)
                padded[i + j] ^= prev[j];
            prev = ciphertext.substr(i, BlockSize);
        }
        std::string result = pkcs7Unpad(padded);
        return result;
    }

    std::string encryptCFB(const std::string &plaintext, const std::string &keystr, const std::string &iv) const __const_noexcept
    {
        if (unlikely(iv.size() != BlockSize)) {
            gost_detail::fail("GOST: encryptCFB: IV must be 8 bytes.");
        }
        std::string ciphertext;
        ciphertext.resize(plaintext.size());
        std::array<uint32_t, SubkeyCount> key;
        keySchedule(key, keystr);

        std::string prev = iv;
        for (size_t i = 0; i < plaintext.size(); i += BlockSize)
        {
            uchar enc[BlockSize];
            encryptBlock(reinterpret_cast<const uchar *>(prev.data()), enc, key.data());
            size_t chunk = std::min(BlockSize, plaintext.size() - i);
            for (size_t j = 0; j < chunk; ++j)
                ciphertext[i + j] = plaintext[i + j] ^ enc[j];
            prev = ciphertext.substr(i, chunk) + prev.substr(chunk, BlockSize - chunk);
        }
        return ciphertext;
    }

    std::string decryptCFB(const std::string &ciphertext, const std::string &keystr, const std::string &iv) const __const_noexcept
    {
        if (unlikely(iv.size() != BlockSize)) {
            gost_detail::fail("GOST: decryptCFB: IV must be 8 bytes.");
        }
        std::string plaintext;
        plaintext.resize(ciphertext.size());
        std::array<uint32_t, SubkeyCount> key;
        keySchedule(key, keystr);

        std::string prev = iv;
        for (size_t i = 0; i < ciphertext.size(); i += BlockSize)
        {
            uchar enc[BlockSize];
            encryptBlock(reinterpret_cast<const uchar *>(prev.data()), enc, key.data());
            size_t chunk = std::min(BlockSize, ciphertext.size() - i);
            for (size_t j = 0; j < chunk; ++j)
                plaintext[i + j] = ciphertext[i + j] ^ enc[j];
            prev = ciphertext.substr(i, chunk) + prev.substr(chunk, BlockSize - chunk);
        }
        return plaintext;
    }

    std::string encryptOFB(const std::string &plaintext, const std::string &keystr, const std::string &iv) const __const_noexcept
    {
        if (unlikely(iv.size() != BlockSize)) {
            gost_detail::fail("GOST: encryptOFB: IV must be 8 bytes.");
        }
        std::string ciphertext;
        ciphertext.resize(plaintext.size());
        std::array<uint32_t, SubkeyCount> key;
        keySchedule(key, keystr);

        std::string ofb = iv;
        for (size_t i = 0; i < plaintext.size(); i += BlockSize)
        {
            uchar outblock[BlockSize];
            encryptBlock(reinterpret_cast<const uchar *>(ofb.data()), outblock, key.data());
            size_t chunk = std::min(BlockSize, plaintext.size() - i);
            for (size_t j = 0; j < chunk; ++j)
                ciphertext[i + j] = plaintext[i + j] ^ outblock[j];
            ofb.assign(reinterpret_cast<const char *>(outblock), BlockSize);
        }
        return ciphertext;
    }

    std::string decryptOFB(const std::string &ciphertext, const std::string &keystr, const std::string &iv) const __const_noexcept
    {
        return encryptOFB(ciphertext, keystr, iv);
    }

    std::string encryptCTR(const std::string &plaintext, const std::string &keystr, const std::string &nonce) const __const_noexcept
    {
        if (unlikely(nonce.size() != BlockSize)) {
            gost_detail::fail("GOST: encryptCTR: Nonce must be 8 bytes.");
        }
        std::string ciphertext;
        ciphertext.resize(plaintext.size());
        std::array<uint32_t, SubkeyCount> key;
        keySchedule(key, keystr);

        std::string counter = nonce;
        for (size_t i = 0; i < plaintext.size(); i += BlockSize)
        {
            uchar keystream[BlockSize];
            encryptBlock(reinterpret_cast<const uchar *>(counter.data()), keystream, key.data());
            size_t chunk = std::min(BlockSize, plaintext.size() - i);
            for (size_t j = 0; j < chunk; ++j)
                ciphertext[i + j] = plaintext[i + j] ^ keystream[j];
            incrementCounter(counter);
        }
        return ciphertext;
    }

    std::string decryptCTR(const std::string &ciphertext, const std::string &keystr, const std::string &nonce) const __const_noexcept
    {
        return encryptCTR(ciphertext, keystr, nonce);
    }
};
