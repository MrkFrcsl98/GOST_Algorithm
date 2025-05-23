# GOST Block Cipher

[![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![C/C++ Ready](https://img.shields.io/badge/C%2B%2B-C%2FC%2B%2B-blue.svg)](https://en.wikipedia.org/wiki/C_and_C%2B%2B)
[![GOST Algorithm](https://img.shields.io/badge/algorithm-GOST-lightgrey.svg)](https://en.wikipedia.org/wiki/GOST_(block_cipher))
[![Block Size: 64 bits](https://img.shields.io/badge/block%20size-64%20bits-orange.svg)](https://en.wikipedia.org/wiki/GOST_(block_cipher))
[![Key Size: 256 bits](https://img.shields.io/badge/key%20size-256%20bits-green.svg)](https://en.wikipedia.org/wiki/GOST_(block_cipher))
[![Modes: ECB, CBC, CFB, OFB, CTR](https://img.shields.io/badge/modes-ECB%2C%20CBC%2C%20CFB%2C%20OFB%2C%20CTR-lightblue.svg)](#modes-of-operation)
[![Status: Educational](https://img.shields.io/badge/status-educational-important.svg)](#security-notes-and-disclaimer)

---

## Table of Contents

- [Overview](#overview)
- [Historical Background](#historical-background)
- [Mathematics Behind GOST](#mathematics-behind-gost)
- [Modes of Operation](#modes-of-operation)
- [Key Sizes Supported](#key-sizes-supported)
- [C and C++ Variants](#c-and-c-variants)
- [Usage Examples (C)](#usage-examples-c)
- [Usage Examples (C++)](#usage-examples-c)
- [Security Notes and Disclaimer](#security-notes-and-disclaimer)
- [Performance](#performance)
- [License](#license)
- [References](#references)

---

## Overview

This repository provides C and C++ implementations of the [GOST Block Cipher](https://en.wikipedia.org/wiki/GOST_(block_cipher)), a symmetric-key cryptographic algorithm standardized in the former Soviet Union and Russia.  
Both implementations offer support for multiple modes of operation and conversion utilities.  
**This project is intended for educational and research purposes only.**

**Repository:** [MrkFrcsl98/GOST_Algorithm](https://github.com/MrkFrcsl98/GOST_Algorithm)  
**Author:** MrkFrcsl98

---

## Historical Background

GOST 28147-89 was developed in the Soviet Union in 1989 and standardized as a national encryption standard for decades.  
It features a Feistel network structure with 32 rounds and a 256-bit key.

- **Block size:** 64 bits (8 bytes)
- **Number of rounds:** 32
- **Key size:** 256 bits (32 bytes)

GOST is notable for its simplicity, custom S-boxes, and flexibility, and has influenced several modern block ciphers.

---

## Mathematics Behind GOST

GOST is a 32-round Feistel cipher:

- **Round Function:**  
  Each round uses modular addition, 8 custom 4-bit S-boxes, and a cyclic left rotation.
- **Key Schedule:**  
  The 256-bit key is split into eight 32-bit subkeys, repeated in a fixed pattern.

**Encryption round:**
1. Add subkey to left word (mod 2^32)
2. Substitute result using S-boxes
3. Circular left shift by 11 bits
4. XOR with right word, swap halves

**Decryption reverses this process with subkeys in reverse order.**

---

## Modes of Operation

Both C and C++ implementations support the following standard block cipher modes:

| Mode Name | Description              | Padding Needed? | IV/Nonce Required? | Secure for Messages Larger Than Block? |
|-----------|-------------------------|-----------------|--------------------|----------------------------------------|
| **ECB**   | Electronic Codebook     | Yes (PKCS#7)    | No                 | ❌ (not recommended)                   |
| **CBC**   | Cipher Block Chaining   | Yes (PKCS#7)    | Yes (IV)           | ✔️                                     |
| **CFB**   | Cipher Feedback         | No              | Yes (IV)           | ✔️                                     |
| **OFB**   | Output Feedback         | No              | Yes (IV)           | ✔️                                     |
| **CTR**   | Counter                 | No              | Yes (Nonce)        | ✔️                                     |

> **Note:**  
> - IVs/Nonces must be unique and random for each encryption in CBC/CFB/OFB/CTR.
> - ECB mode should only be used for single-block messages or educational demos.

---

## Key Sizes Supported

| Option         | Symbol              | Key Length (bytes) | Key Length (bits) |
|----------------|--------------------|--------------------|-------------------|
| 256 bits       | `GOST_KEY_SIZE`    | 32                 | 256               |

---

## C and C++ Variants

This repository contains two main implementations:

- **C version:**  
  *Files*: [`gost.c`](gost.c), [`gost.h`](gost.h)  
  This version is portable, standard C, suitable for integration with C projects and for educational study.

- **C++ version:**  
  *File*: [`gost.hpp`](gost.hpp)  
  This version uses modern C++ and offers a class-based, header-only design for ease of use in C++ projects, with utility functions and result wrappers.

**You can use either implementation independently, depending on your project needs.**

---

## Usage Examples (C)

### Include & Typedefs

```c
#include "gost.h"
// All functions are prefixed with gost_
```

### Key and IV Generation

```c
uint8_t key[GOST_KEY_SIZE];
uint8_t iv[GOST_BLOCK_SIZE];
gost_generate_key(key);
gost_generate_iv(iv, GOST_BLOCK_SIZE);
```

### ECB Mode

```c
const char* plaintext = "Hello, GOST block cipher!";
size_t pt_len = strlen(plaintext);

uint8_t* ciphertext = NULL;
size_t ciphertext_len = 0;
gost_ecb_encrypt((const uint8_t*)plaintext, pt_len, key, &ciphertext, &ciphertext_len);

uint8_t* decrypted = NULL;
size_t decrypted_len = 0;
gost_ecb_decrypt(ciphertext, ciphertext_len, key, &decrypted, &decrypted_len);

char* hexstr = gost_to_hex(ciphertext, ciphertext_len);
printf("Ciphertext (hex): %s\n", hexstr);
printf("Decrypted: %.*s\n", (int)decrypted_len, (char*)decrypted);

free(ciphertext);
free(decrypted);
free(hexstr);
```

### CBC Mode

```c
uint8_t* cbc_cipher = NULL;
size_t cbc_cipher_len = 0;
gost_cbc_encrypt((const uint8_t*)plaintext, pt_len, key, iv, &cbc_cipher, &cbc_cipher_len);

uint8_t* cbc_plain = NULL;
size_t cbc_plain_len = 0;
gost_cbc_decrypt(cbc_cipher, cbc_cipher_len, key, iv, &cbc_plain, &cbc_plain_len);

// Don't forget to free!
free(cbc_cipher);
free(cbc_plain);
```

### CFB/OFB/CTR Modes

```c
uint8_t* cfb_cipher = NULL;
gost_cfb_encrypt((const uint8_t*)plaintext, pt_len, key, iv, &cfb_cipher);

uint8_t* ofb_cipher = NULL;
gost_ofb_crypt((const uint8_t*)plaintext, pt_len, key, iv, &ofb_cipher);

uint8_t* ctr_cipher = NULL;
gost_ctr_crypt((const uint8_t*)plaintext, pt_len, key, iv, &ctr_cipher);

// Free after use
free(cfb_cipher); free(ofb_cipher); free(ctr_cipher);
```

### Encoding and Conversion Utilities

```c
char* hexstr = gost_to_hex(ciphertext, ciphertext_len);
size_t outlen;
uint8_t* fromhex = gost_from_hex(hexstr, &outlen);

char* b64 = gost_to_base64(ciphertext, ciphertext_len);
uint8_t* fromb64 = gost_from_base64(b64, &outlen);

free(hexstr); free(fromhex); free(b64); free(fromb64);
```

---

## Usage Examples (C++)

### Include & Typedefs

```cpp
#include "gost.hpp"
using gost256 = GOST<GOST_KEY_SIZE::BITS_256>;
```

### Key and IV Generation

```cpp
std::string key = GOSTKeyIVGenerator::generateKey(GOST_KEY_SIZE::BITS_256);
std::string iv  = GOSTKeyIVGenerator::generateIV(); // 8 bytes
```

### ECB Mode

```cpp
std::string plaintext = "Hello, GOST block cipher!";
auto ciphertext = gost256::ECB::Encrypt(plaintext, key);
// To hex
std::cout << "Ciphertext (hex): " << ciphertext.toHex().asString() << "\n";
auto decrypted = gost256::ECB::Decrypt(ciphertext.asString(), key);
std::cout << "Decrypted: " << decrypted.asString() << std::endl;
```

### CBC/CFB/OFB/CTR Modes

```cpp
auto cbc_cipher = gost256::CBC::Encrypt(plaintext, key, iv);
auto cbc_plain  = gost256::CBC::Decrypt(cbc_cipher.asString(), key, iv);

auto cfb_cipher = gost256::CFB::Encrypt(plaintext, key, iv);
auto cfb_plain  = gost256::CFB::Decrypt(cfb_cipher.asString(), key, iv);

auto ofb_cipher = gost256::OFB::Encrypt(plaintext, key, iv);
auto ofb_plain  = gost256::OFB::Decrypt(ofb_cipher.asString(), key, iv);

auto ctr_cipher = gost256::CTR::Encrypt(plaintext, key, iv); // IV acts as nonce
auto ctr_plain  = gost256::CTR::Decrypt(ctr_cipher.asString(), key, iv);
```

### Encoding and Conversion Utilities

```cpp
auto base64 = ciphertext.toBase64().asString();
auto from64 = GOSTResult(base64).fromBase64().asString();
auto hexstr = ciphertext.toHex().asString();
auto orig   = GOSTResult(hexstr).fromHex().asString();
```

---

## Security Notes and Disclaimer

> :warning: **Educational Use Only!**
>
> - This code is provided for learning, academic, and research purposes.
> - It has **not** been security audited or tested for use in production.
> - Cryptographic code is easy to get wrong.
> - Do **NOT** use this implementation to protect sensitive or confidential data.
> - Use only after a full, independent security review.

---

## Performance

- Written in portable standard C and modern C++.
- Simple and clear for study and experimentation.
- Not optimized for high-throughput production use.

---

## License

This project is licensed under the MIT License.

---

## References

- [Wikipedia: GOST (block cipher)](https://en.wikipedia.org/wiki/GOST_(block_cipher))
- [GOST 28147-89 Standard (RFC 5830)](https://datatracker.ietf.org/doc/html/rfc5830)
- [GOST Algorithm (Rosstandart)](https://www.tc26.ru/en/)
- [Cryptography Stack Exchange: GOST](https://crypto.stackexchange.com/questions/tagged/gost)
- [Feistel Network](https://en.wikipedia.org/wiki/Feistel_cipher)
- [Block Cipher Modes](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation)
- [Serpent Algorithm by MrkFrcsl98](https://github.com/MrkFrcsl98/Serpent_Algorithm)

---

## Authors

- [MrkFrcsl98](https://github.com/MrkFrcsl98)
