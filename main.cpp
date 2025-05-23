#include <iostream>
#include "gost.hpp"

int main() {
    using GOST256 = GOST<GOST_KEY_SIZE::BITS_256>;

    // Generate random key (32 bytes) and IV (8 bytes)
    std::string key = GOSTKeyIVGenerator::generateKey();
    std::string iv  = GOSTKeyIVGenerator::generateIV();

    std::string plaintext = "Hello, world! This is a test of GOST ECB and CBC modes.";

    // --- ECB Mode Demo ---
    auto encrypted_ecb = GOST256::ECB::Encrypt(plaintext, key).asString();
    auto decrypted_ecb = GOST256::ECB::Decrypt(encrypted_ecb, key).asString();

    std::cout << "[ECB] Original:  " << plaintext << std::endl;
    std::cout << "[ECB] Decrypted: " << decrypted_ecb << std::endl;

    // --- CBC Mode Demo ---
    auto encrypted_cbc = GOST256::CBC::Encrypt(plaintext, key, iv).asString();
    auto decrypted_cbc = GOST256::CBC::Decrypt(encrypted_cbc, key, iv).asString();

    std::cout << "[CBC] Original:  " << plaintext << std::endl;
    std::cout << "[CBC] Decrypted: " << decrypted_cbc << std::endl;

    // Check correctness
    if (plaintext == decrypted_ecb && plaintext == decrypted_cbc) {
        std::cout << "Success: ECB and CBC roundtrip OK!" << std::endl;
    } else {
        std::cout << "Error: Decryption mismatch!" << std::endl;
    }

    return 0;
}

