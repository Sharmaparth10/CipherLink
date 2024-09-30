// session.c

#include "secure_comm.h"

#include <stdio.h>      // For fprintf, printf
#include <stdlib.h>     // For malloc, free, memset
#include <string.h>     // For strlen, strcmp

#include <openssl/evp.h>      // For high-level cryptographic functions
#include <openssl/rand.h>     // For random number generation
#include <openssl/err.h>      // For error handling
#include <openssl/sha.h>      // For SHA hashing
#include <openssl/dh.h> // Add this line


/**
 * @brief Authenticates a user with the given credentials.
 *
 * This function verifies the provided username and password.
 * In a real-world scenario, this would involve checking against a user database.
 *
 * @param username The username of the user.
 * @param password The password of the user.
 *
 * @return SECURE_COMM_SUCCESS if authentication is successful,
 *         SECURE_COMM_ERR_SESSION otherwise.
 */
SecureCommError authenticate_user(const char* username, const char* password) {
    // TODO: Implement proper authentication (e.g., database lookup, hashing)
    // For demonstration purposes, we'll use hardcoded credentials.
    const char* valid_username = "user";
    const char* valid_password = "pass";

    if (strcmp(username, valid_username) == 0 && strcmp(password, valid_password) == 0) {
        return SECURE_COMM_SUCCESS;
    } else {
        fprintf(stderr, "authenticate_user: Invalid credentials for user '%s'\n", username);
        return SECURE_COMM_ERR_SESSION;
    }
}

/**
 * @brief Generates a Diffie-Hellman key pair using EVP_PKEY.
 *
 * This function initializes Diffie-Hellman parameters and generates a key pair.
 *
 * @param keypair Pointer to store the generated EVP_PKEY key pair.
 *
 * @return SECURE_COMM_SUCCESS on success, or SECURE_COMM_ERR_SESSION on failure.
 */
SecureCommError generate_dh_keypair(EVP_PKEY** keypair) {
    if (keypair == NULL) {
        fprintf(stderr, "generate_dh_keypair: Invalid argument\n");
        return SECURE_COMM_ERR_SESSION;
    }

    // Initialize the OpenSSL algorithms
    // Not strictly necessary with OpenSSL 1.1.0 and above, but kept for compatibility
    OpenSSL_add_all_algorithms();

    // Create a new EVP_PKEY_CTX for DH key generation with 2048-bit MODP Group 14
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);
    if (!pctx) {
        fprintf(stderr, "generate_dh_keypair: EVP_PKEY_CTX_new_id failed\n");
        return SECURE_COMM_ERR_SESSION;
    }

    if (EVP_PKEY_paramgen_init(pctx) <= 0) {
        fprintf(stderr, "generate_dh_keypair: EVP_PKEY_paramgen_init failed\n");
        EVP_PKEY_CTX_free(pctx);
        return SECURE_COMM_ERR_SESSION;
    }

    // Set the DH group to 2048-bit MODP Group 14 (RFC 3526)
    if (EVP_PKEY_CTX_set_dh_paramgen_prime_len(pctx, 2048) <= 0 ||
        EVP_PKEY_CTX_set_dh_paramgen_generator(pctx, 2) <= 0) {
        fprintf(stderr, "generate_dh_keypair: Setting DH parameters failed\n");
        EVP_PKEY_CTX_free(pctx);
        return SECURE_COMM_ERR_SESSION;
    }

    // Generate DH parameters
    EVP_PKEY* params = NULL;
    if (EVP_PKEY_paramgen(pctx, &params) <= 0) {
        fprintf(stderr, "generate_dh_keypair: EVP_PKEY_paramgen failed\n");
        EVP_PKEY_CTX_free(pctx);
        return SECURE_COMM_ERR_SESSION;
    }

    // Create a new context for key generation
    EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new(params, NULL);
    if (!kctx) {
        fprintf(stderr, "generate_dh_keypair: EVP_PKEY_CTX_new failed\n");
        EVP_PKEY_free(params);
        EVP_PKEY_CTX_free(pctx);
        return SECURE_COMM_ERR_SESSION;
    }

    if (EVP_PKEY_keygen_init(kctx) <= 0) {
        fprintf(stderr, "generate_dh_keypair: EVP_PKEY_keygen_init failed\n");
        EVP_PKEY_free(params);
        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_CTX_free(kctx);
        return SECURE_COMM_ERR_SESSION;
    }

    // Generate the DH key pair
    if (EVP_PKEY_keygen(kctx, keypair) <= 0) {
        fprintf(stderr, "generate_dh_keypair: EVP_PKEY_keygen failed\n");
        EVP_PKEY_free(params);
        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_CTX_free(kctx);
        return SECURE_COMM_ERR_SESSION;
    }

    // Cleanup
    EVP_PKEY_free(params);
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_CTX_free(kctx);

    return SECURE_COMM_SUCCESS;
}

/**
 * @brief Derives a shared secret using the peer's public key.
 *
 * This function computes the shared secret using the peer's public key.
 *
 * @param session Pointer to the UserSession.
 *
 * @return SECURE_COMM_SUCCESS on success, or SECURE_COMM_ERR_SESSION on failure.
 */
SecureCommError derive_shared_secret(UserSession* session) {
    if (session == NULL || session->dh_keypair == NULL) {
        fprintf(stderr, "derive_shared_secret: Invalid session or DH keypair\n");
        return SECURE_COMM_ERR_SESSION;
    }

    // In a real-world scenario, the peer's public key would be received from the connected party.
    // For demonstration, we'll generate it locally.
    // TODO: Replace with actual peer public key exchange.

    // For demonstration, duplicate the local keypair as the peer's key (not secure)
    session->peer_dh_public = EVP_PKEY_dup(session->dh_keypair);
    if (session->peer_dh_public == NULL) {
        fprintf(stderr, "derive_shared_secret: EVP_PKEY_dup failed\n");
        return SECURE_COMM_ERR_SESSION;
    }

    // Create a context for key derivation
    EVP_PKEY_CTX* derivation_ctx = EVP_PKEY_CTX_new(session->dh_keypair, NULL);
    if (!derivation_ctx) {
        fprintf(stderr, "derive_shared_secret: EVP_PKEY_CTX_new failed\n");
        return SECURE_COMM_ERR_SESSION;
    }

    if (EVP_PKEY_derive_init(derivation_ctx) <= 0) {
        fprintf(stderr, "derive_shared_secret: EVP_PKEY_derive_init failed\n");
        EVP_PKEY_CTX_free(derivation_ctx);
        return SECURE_COMM_ERR_SESSION;
    }

    if (EVP_PKEY_derive_set_peer(derivation_ctx, session->peer_dh_public) <= 0) {
        fprintf(stderr, "derive_shared_secret: EVP_PKEY_derive_set_peer failed\n");
        EVP_PKEY_CTX_free(derivation_ctx);
        return SECURE_COMM_ERR_SESSION;
    }

    // Determine the size of the shared secret
    size_t secret_len;
    if (EVP_PKEY_derive(derivation_ctx, NULL, &secret_len) <= 0) {
        fprintf(stderr, "derive_shared_secret: EVP_PKEY_derive (size determination) failed\n");
        EVP_PKEY_CTX_free(derivation_ctx);
        return SECURE_COMM_ERR_SESSION;
    }

    // Allocate memory for the shared secret
    unsigned char* secret = (unsigned char*)malloc(secret_len);
    if (secret == NULL) {
        fprintf(stderr, "derive_shared_secret: Failed to allocate memory for shared secret\n");
        EVP_PKEY_CTX_free(derivation_ctx);
        return SECURE_COMM_ERR_MEMORY;
    }

    // Derive the shared secret
    if (EVP_PKEY_derive(derivation_ctx, secret, &secret_len) <= 0) {
        fprintf(stderr, "derive_shared_secret: EVP_PKEY_derive failed\n");
        free(secret);
        EVP_PKEY_CTX_free(derivation_ctx);
        return SECURE_COMM_ERR_SESSION;
    }

    // Cleanup
    EVP_PKEY_CTX_free(derivation_ctx);

    // Hash the shared secret to derive a symmetric session key
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(secret, secret_len, hash);
    free(secret);

    // Allocate and store the session key
    session->session_key_len = SHA256_DIGEST_LENGTH;
    session->session_key = (unsigned char*)malloc(session->session_key_len);
    if (session->session_key == NULL) {
        fprintf(stderr, "derive_shared_secret: Failed to allocate memory for session key\n");
        return SECURE_COMM_ERR_MEMORY;
    }
    memcpy(session->session_key, hash, session->session_key_len);

    return SECURE_COMM_SUCCESS;
}

/**
 * @brief Initializes a new user session by authenticating the user and establishing a shared secret.
 *
 * @param username The username of the user initiating the session.
 * @param password The password of the user.
 * @param session Pointer to store the created UserSession.
 *
 * @return SECURE_COMM_SUCCESS on success, or a negative error code on failure.
 */
SecureCommError initialize_session(const char* username, const char* password, UserSession** session) {
    if (username == NULL || password == NULL || session == NULL) {
        fprintf(stderr, "initialize_session: Invalid arguments\n");
        return SECURE_COMM_ERR_SESSION;
    }

    // Allocate memory for the session
    UserSession* new_session = (UserSession*)malloc(sizeof(UserSession));
    if (new_session == NULL) {
        fprintf(stderr, "initialize_session: Failed to allocate memory for session\n");
        return SECURE_COMM_ERR_MEMORY;
    }
    memset(new_session, 0, sizeof(UserSession));

    // Authenticate the user
    SecureCommError auth_ret = authenticate_user(username, password);
    if (auth_ret != SECURE_COMM_SUCCESS) {
        fprintf(stderr, "initialize_session: User authentication failed for '%s'\n", username);
        free(new_session);
        return auth_ret;
    }

    // Set the username
    new_session->username = strdup(username);
    if (new_session->username == NULL) {
        fprintf(stderr, "initialize_session: Failed to allocate memory for username\n");
        free(new_session);
        return SECURE_COMM_ERR_MEMORY;
    }

    // Generate Diffie-Hellman key pair using EVP_PKEY
    SecureCommError dh_ret = generate_dh_keypair(&new_session->dh_keypair);
    if (dh_ret != SECURE_COMM_SUCCESS) {
        fprintf(stderr, "initialize_session: Failed to generate DH key pair\n");
        free(new_session->username);
        free(new_session);
        return dh_ret;
    }

    // Derive the shared secret and establish the session key
    SecureCommError secret_ret = derive_shared_secret(new_session);
    if (secret_ret != SECURE_COMM_SUCCESS) {
        fprintf(stderr, "initialize_session: Failed to derive shared secret\n");
        EVP_PKEY_free(new_session->dh_keypair);
        free(new_session->username);
        free(new_session);
        return secret_ret;
    }

    // Assign the created session to the output parameter
    *session = new_session;

    printf("initialize_session: Session initialized for user '%s'\n", username);

    return SECURE_COMM_SUCCESS;
}

/**
 * @brief Terminates an existing user session, freeing all associated resources.
 *
 * @param session Pointer to the UserSession to terminate.
 */
void terminate_session(UserSession* session) {
    if (session == NULL) {
        return;
    }

    // Free the session key
    if (session->session_key) {
        // Securely erase the key
        OPENSSL_cleanse(session->session_key, session->session_key_len);
        free(session->session_key);
    }

    // Free the DH key pair
    if (session->dh_keypair) {
        EVP_PKEY_free(session->dh_keypair);
    }

    // Free the peer's public key
    if (session->peer_dh_public) {
        EVP_PKEY_free(session->peer_dh_public);
    }

    // Free the username
    if (session->username) {
        free(session->username);
    }

    // Free the session structure itself
    free(session);

    printf("terminate_session: Session terminated successfully.\n");
}
