#include "secure_comm.h"

#include <stdio.h>      // For fprintf
#include <stdlib.h>     // For malloc, free
#include <string.h>     // For memset
#include <errno.h>      // For errno and strerror

#include <openssl/evp.h> // For EVP encryption functions
#include <openssl/err.h> // For error handling
#include <openssl/rand.h> // For random IV generation

/**
 * @brief Encrypts data using AES-GCM (Authenticated Encryption).
 *
 * This function encrypts the input data using AES-GCM encryption.
 *
 * @param plaintext Pointer to the data to encrypt.
 * @param plaintext_len Length of the plaintext in bytes.
 * @param key Pointer to the encryption key (16, 24, or 32 bytes for AES-128, AES-192, AES-256).
 * @param iv Pointer to the 12-byte Initialization Vector (randomly generated).
 * @param ciphertext Pointer to the buffer where encrypted data will be stored.
 * @param ciphertext_len Pointer to store the length of the ciphertext.
 * @param tag Pointer to store the authentication tag (16 bytes).
 *
 * @return SECURE_COMM_SUCCESS on success, or a negative error code on failure.
 */
SecureCommError encrypt_data(const unsigned char* plaintext, int plaintext_len,
                             const unsigned char* key, unsigned char* iv,
                             unsigned char* ciphertext, int* ciphertext_len,
                             unsigned char* tag) {
    if (plaintext == NULL || key == NULL || iv == NULL || ciphertext == NULL || ciphertext_len == NULL || tag == NULL) {
        fprintf(stderr, "encrypt_data: Invalid arguments\n");
        return SECURE_COMM_ERR_ENCRYPT;
    }

    EVP_CIPHER_CTX* ctx = NULL;
    int len = 0;
    int total_len = 0;
    SecureCommError ret = SECURE_COMM_SUCCESS;

    // Create and initialize the context
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "encrypt_data: EVP_CIPHER_CTX_new failed\n");
        ret = SECURE_COMM_ERR_ENCRYPT;
        goto cleanup;
    }

    // Generate a random IV (12 bytes for AES-GCM)
    if (!RAND_bytes(iv, 12)) {
        fprintf(stderr, "encrypt_data: Failed to generate IV\n");
        ret = SECURE_COMM_ERR_ENCRYPT;
        goto cleanup;
    }

    // Initialize the encryption operation with AES-256-GCM
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv)) {
        fprintf(stderr, "encrypt_data: EVP_EncryptInit_ex failed\n");
        ret = SECURE_COMM_ERR_ENCRYPT;
        goto cleanup;
    }

    // Provide the plaintext to be encrypted, and obtain the ciphertext output
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        fprintf(stderr, "encrypt_data: EVP_EncryptUpdate failed\n");
        ret = SECURE_COMM_ERR_ENCRYPT;
        goto cleanup;
    }
    total_len += len;

    // Finalize the encryption. Further ciphertext bytes may be written.
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + total_len, &len)) {
        fprintf(stderr, "encrypt_data: EVP_EncryptFinal_ex failed\n");
        ret = SECURE_COMM_ERR_ENCRYPT;
        goto cleanup;
    }
    total_len += len;

    *ciphertext_len = total_len;

    // Get the authentication tag
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)) {
        fprintf(stderr, "encrypt_data: Failed to get GCM authentication tag\n");
        ret = SECURE_COMM_ERR_ENCRYPT;
        goto cleanup;
    }

cleanup:
    // Clean up the context
    if (ctx) {
        EVP_CIPHER_CTX_free(ctx);
    }

    return ret;
}

/**
 * @brief Decrypts data using AES-GCM (Authenticated Encryption).
 *
 * This function decrypts the input data using AES-GCM decryption.
 *
 * @param ciphertext Pointer to the data to decrypt.
 * @param ciphertext_len Length of the ciphertext in bytes.
 * @param key Pointer to the decryption key (must be the same as encryption key).
 * @param iv Pointer to the 12-byte Initialization Vector (must be the same as used in encryption).
 * @param plaintext Pointer to the buffer where decrypted data will be stored.
 * @param plaintext_len Pointer to store the length of the plaintext.
 * @param tag Pointer to the authentication tag (16 bytes, same as used during encryption).
 *
 * @return SECURE_COMM_SUCCESS on success, or a negative error code on failure.
 */
SecureCommError decrypt_data(const unsigned char* ciphertext, int ciphertext_len,
                             const unsigned char* key, const unsigned char* iv,
                             unsigned char* plaintext, int* plaintext_len,
                             const unsigned char* tag) {
    if (ciphertext == NULL || key == NULL || iv == NULL || plaintext == NULL || plaintext_len == NULL || tag == NULL) {
        fprintf(stderr, "decrypt_data: Invalid arguments\n");
        return SECURE_COMM_ERR_DECRYPT;
    }

    EVP_CIPHER_CTX* ctx = NULL;
    int len = 0;
    int total_len = 0;
    SecureCommError ret = SECURE_COMM_SUCCESS;

    // Create and initialize the context
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "decrypt_data: EVP_CIPHER_CTX_new failed\n");
        ret = SECURE_COMM_ERR_DECRYPT;
        goto cleanup;
    }

    // Initialize the decryption operation with AES-256-GCM
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv)) {
        fprintf(stderr, "decrypt_data: EVP_DecryptInit_ex failed\n");
        ret = SECURE_COMM_ERR_DECRYPT;
        goto cleanup;
    }

    // Provide the ciphertext to be decrypted
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        fprintf(stderr, "decrypt_data: EVP_DecryptUpdate failed\n");
        ret = SECURE_COMM_ERR_DECRYPT;
        goto cleanup;
    }
    total_len += len;

    // Set expected GCM authentication tag for verification
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag)) {
        fprintf(stderr, "decrypt_data: Failed to set GCM authentication tag\n");
        ret = SECURE_COMM_ERR_DECRYPT;
        goto cleanup;
    }

    // Finalize the decryption. If the tag doesn't match, this will fail.
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + total_len, &len)) {
        fprintf(stderr, "decrypt_data: EVP_DecryptFinal_ex failed. Possibly wrong key, IV, or corrupted data.\n");
        ret = SECURE_COMM_ERR_DECRYPT;
        goto cleanup;
    }
    total_len += len;

    *plaintext_len = total_len;

cleanup:
    // Clean up the context
    if (ctx) {
        EVP_CIPHER_CTX_free(ctx);
    }

    return ret;
}
