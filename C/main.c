#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "gost.h"  

int main() {
    // 1. Prepare key and IV
    uint8_t key[GOST_KEY_SIZE];
    uint8_t iv[GOST_BLOCK_SIZE];
    gost_generate_key(key);
    gost_generate_iv(iv, GOST_BLOCK_SIZE);

    // 2. Prepare plaintext
    const char* plaintext = "Hello, GOST block cipher in C!   "; // len = 31
    size_t pt_len = strlen(plaintext);

    // 3. ECB encryption + decryption
    uint8_t* ecb_cipher = NULL;
    size_t ecb_cipher_len = 0;
    gost_ecb_encrypt((const uint8_t*)plaintext, pt_len, key, &ecb_cipher, &ecb_cipher_len);

    uint8_t* ecb_decrypted = NULL;
    size_t ecb_decrypted_len = 0;
    gost_ecb_decrypt(ecb_cipher, ecb_cipher_len, key, &ecb_decrypted, &ecb_decrypted_len);

    char* ecb_hex = gost_to_hex(ecb_cipher, ecb_cipher_len);
    printf("ECB mode:\n");
    printf("  Ciphertext (hex): %s\n", ecb_hex);
    printf("  Decrypted : %.*s\n\n", (int)ecb_decrypted_len, (char*)ecb_decrypted);

    // Free ECB outputs
    free(ecb_cipher);
    free(ecb_decrypted);
    free(ecb_hex);

    // 4. CBC encryption + decryption
    uint8_t* cbc_cipher = NULL;
    size_t cbc_cipher_len = 0;
    gost_cbc_encrypt((const uint8_t*)plaintext, pt_len, key, iv, &cbc_cipher, &cbc_cipher_len);

    uint8_t* cbc_decrypted = NULL;
    size_t cbc_decrypted_len = 0;
    gost_cbc_decrypt(cbc_cipher, cbc_cipher_len, key, iv, &cbc_decrypted, &cbc_decrypted_len);

    char* cbc_hex = gost_to_hex(cbc_cipher, cbc_cipher_len);
    printf("CBC mode:\n");
    printf("  Ciphertext (hex): %s\n", cbc_hex);
    printf("  Decrypted : %.*s\n\n", (int)cbc_decrypted_len, (char*)cbc_decrypted);

    // Free CBC outputs
    free(cbc_cipher);
    free(cbc_decrypted);
    free(cbc_hex);

    return 0;
}
