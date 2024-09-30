// test_encryption.c

#include "secure_comm.h"

#include <stdio.h>      // For printf
#include <string.h>     // For strlen, memcmp

int main() {
    // Sample plaintext
    const char* plaintext = "This is a secret message.";
    int plaintext_len = strlen(plaintext);

    // Encryption key (32 bytes for AES-256)
    const unsigned char key[32] = "0123456789abcdef0123456789abcdef";

    // Initialization Vector (16 bytes for AES)
    const unsigned char iv[16] = "abcdef9876543210";

    // Buffer for ciphertext (will be larger than plaintext)
    unsigned char ciphertext[128];
    int ciphertext_len = 0;

    // Buffer for decrypted text
    unsigned char decryptedtext[128];
    int decryptedtext_len = 0;

    // Encrypt the plaintext
    SecureCommError enc_ret = encrypt_data((unsigned char*)plaintext, plaintext_len,
                                           key, iv, ciphertext, &ciphertext_len);
    if (enc_ret != SECURE_COMM_SUCCESS) {
        fprintf(stderr, "Encryption failed with error code: %d\n", enc_ret);
        return 1;
    }

    printf("Encrypted text is:\n");
    for(int i = 0; i < ciphertext_len; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    // Decrypt the ciphertext
    SecureCommError dec_ret = decrypt_data(ciphertext, ciphertext_len,
                                           key, iv, decryptedtext, &decryptedtext_len);
    if (dec_ret != SECURE_COMM_SUCCESS) {
        fprintf(stderr, "Decryption failed with error code: %d\n", dec_ret);
        return 1;
    }

    // Null-terminate the decrypted text
    decryptedtext[decryptedtext_len] = '\0';

    printf("Decrypted text is:\n%s\n", decryptedtext);

    // Verify that decrypted text matches original plaintext
    if (decryptedtext_len != plaintext_len || memcmp(plaintext, decryptedtext, plaintext_len) != 0) {
        fprintf(stderr, "Decryption did not produce the original plaintext.\n");
        return 1;
    }

    printf("Encryption and decryption successful.\n");

    return 0;
}
