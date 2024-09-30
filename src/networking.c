// networking.c

#include "secure_comm.h"

#include <stdio.h>      // For printf, perror
#include <stdlib.h>     // For malloc, free
#include <string.h>     // For memset, memcpy

#include <openssl/ssl.h>  // For SSL functions
#include <openssl/err.h>  // For SSL error functions

#ifdef _WIN32
    // Windows-specific includes and definitions are already handled in the header
#else
    // POSIX-specific includes are already handled in the header
#endif

// Definition of the opaque SecureConnection structure
struct SecureConnection {
    int socket_fd;      // Socket file descriptor
    SSL* ssl;           // SSL connection object
    SSL_CTX* ssl_ctx;   // SSL context
};

/**
 * @brief Initializes the networking module.
 *
 * This function sets up any necessary networking resources, such as
 * initializing networking libraries required by the underlying platform.
 *
 * @return SECURE_COMM_SUCCESS on success, or a negative error code on failure.
 */
SecureCommError init_networking() {
#ifdef _WIN32
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2,2), &wsaData);
    if (result != 0) {
        printf("WSAStartup failed: %d\n", result);
        return SECURE_COMM_ERR_INIT;
    }
#endif
    // Initialize OpenSSL
    SSL_load_error_strings();      // Load human-readable error strings
    OpenSSL_add_ssl_algorithms();  // Register available SSL/TLS ciphers and digests

    return SECURE_COMM_SUCCESS;
}

/**
 * @brief Creates a secure connection to the specified address and port.
 *
 * This function establishes a TCP connection to the given address and port,
 * and initializes the SSL context for secure communication.
 *
 * @param address The IP address or hostname to connect to.
 * @param port The port number to connect on.
 * @param error Pointer to store the error code if connection fails.
 *
 * @return Pointer to a SecureConnection on success, or NULL on failure.
 *         The specific error code is stored in *error.
 */
SecureConnection* create_connection(const char* address, int port, SecureCommError* error) {
    if (address == NULL || error == NULL) {
        fprintf(stderr, "create_connection: Invalid arguments\n");
        if (error) *error = SECURE_COMM_ERR_ADDRESS;
        return NULL;
    }

    SecureConnection* conn = (SecureConnection*)malloc(sizeof(SecureConnection));
    if (!conn) {
        perror("malloc");
        *error = SECURE_COMM_ERR_MEMORY;
        return NULL;
    }

    memset(conn, 0, sizeof(SecureConnection));  // Initialize memory to zero

    // Create a socket
    conn->socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (conn->socket_fd < 0) {
        perror("socket");
        free(conn);
        *error = SECURE_COMM_ERR_SOCKET;
        return NULL;
    }

    // Set up the server address structure
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));  // Zero out the structure
    server_addr.sin_family = AF_INET;              // IPv4
    server_addr.sin_port = htons(port);            // Convert port to network byte order

    // Convert the address from text to binary form
    if (inet_pton(AF_INET, address, &server_addr.sin_addr) <= 0) {
        perror("inet_pton");
        close(conn->socket_fd);
        free(conn);
        *error = SECURE_COMM_ERR_ADDRESS;
        return NULL;
    }

    // Connect to the server
    if (connect(conn->socket_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect");
        close(conn->socket_fd);
        free(conn);
        *error = SECURE_COMM_ERR_CONNECT;
        return NULL;
    }

    // Create a new SSL context using TLS client method
    conn->ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!conn->ssl_ctx) {
        ERR_print_errors_fp(stderr);
        close(conn->socket_fd);
        free(conn);
        *error = SECURE_COMM_ERR_SSL_CTX;
        return NULL;
    }

    // Create a new SSL structure for the connection
    conn->ssl = SSL_new(conn->ssl_ctx);
    if (!conn->ssl) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(conn->ssl_ctx);
        close(conn->socket_fd);
        free(conn);
        *error = SECURE_COMM_ERR_SSL;
        return NULL;
    }

    // Associate the socket file descriptor with the SSL structure
    SSL_set_fd(conn->ssl, conn->socket_fd);

    // Initiate the TLS/SSL handshake with the server
    if (SSL_connect(conn->ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(conn->ssl);
        SSL_CTX_free(conn->ssl_ctx);
        close(conn->socket_fd);
        free(conn);
        *error = SECURE_COMM_ERR_SSL;
        return NULL;
    }

    // Connection and SSL setup successful
    *error = SECURE_COMM_SUCCESS;
    return conn;
}

/**
 * @brief Sends data over the secure connection.
 *
 * This function encrypts and sends the specified data over the connection.
 *
 * @param conn Pointer to an established SecureConnection.
 * @param data Pointer to the data buffer to send.
 * @param len Length of the data in bytes.
 * @param bytes_sent Pointer to store the number of bytes actually sent.
 *
 * @return SECURE_COMM_SUCCESS on success, or a negative error code on failure.
 */
SecureCommError secure_send(SecureConnection* conn, const void* data, size_t len, ssize_t* bytes_sent) {
    if (conn == NULL || data == NULL || bytes_sent == NULL) {
        fprintf(stderr, "secure_send: Invalid arguments\n");
        return SECURE_COMM_ERR_SEND;
    }

    // Send data using SSL_write
    int sent = SSL_write(conn->ssl, data, (int)len);
    if (sent <= 0) {
        int ssl_error = SSL_get_error(conn->ssl, sent);
        fprintf(stderr, "SSL_write failed with error %d\n", ssl_error);
        return SECURE_COMM_ERR_SEND;
    }

    *bytes_sent = sent;
    return SECURE_COMM_SUCCESS;
}

/**
 * @brief Receives data from the secure connection.
 *
 * This function receives and decrypts data from the connection.
 *
 * @param conn Pointer to an established SecureConnection.
 * @param buffer Pointer to the buffer where received data will be stored.
 * @param len Maximum number of bytes to receive.
 * @param bytes_received Pointer to store the number of bytes actually received.
 *
 * @return SECURE_COMM_SUCCESS on success, SECURE_COMM_ERR_RECV if connection is closed,
 *         or a negative error code on failure.
 */
SecureCommError secure_recv(SecureConnection* conn, void* buffer, size_t len, ssize_t* bytes_received) {
    if (conn == NULL || buffer == NULL || bytes_received == NULL) {
        fprintf(stderr, "secure_recv: Invalid arguments\n");
        return SECURE_COMM_ERR_RECV;
    }

    // Receive data using SSL_read
    int received = SSL_read(conn->ssl, buffer, (int)len);
    if (received <= 0) {
        int ssl_error = SSL_get_error(conn->ssl, received);
        if (ssl_error == SSL_ERROR_ZERO_RETURN) {
            // Connection has been closed cleanly
            return SECURE_COMM_ERR_RECV;
        }
        fprintf(stderr, "SSL_read failed with error %d\n", ssl_error);
        return SECURE_COMM_ERR_RECV;
    }

    *bytes_received = received;
    return SECURE_COMM_SUCCESS;
}

/**
 * @brief Closes the secure connection and frees resources.
 *
 * This function gracefully shuts down the SSL connection, closes the socket,
 * and frees any allocated memory associated with the connection.
 *
 * @param conn Pointer to the SecureConnection to close.
 */
void close_connection(SecureConnection* conn) {
    if (conn) {
        // Shutdown the SSL connection
        if (conn->ssl) {
            SSL_shutdown(conn->ssl);
            SSL_free(conn->ssl);
        }

        // Free the SSL context
        if (conn->ssl_ctx) {
            SSL_CTX_free(conn->ssl_ctx);
        }

        // Close the socket
#ifdef _WIN32
        closesocket(conn->socket_fd);
#else
        close(conn->socket_fd);
#endif
        // Free the SecureConnection structure
        free(conn);
    }
}

/**
 * @brief Cleans up networking resources.
 *
 * This function should be called once all networking operations are complete.
 * It performs necessary cleanup tasks, such as freeing global resources.
 */
void cleanup_networking() {
#ifdef _WIN32
    WSACleanup();
#endif
    // Cleanup OpenSSL algorithms
    EVP_cleanup();
    ERR_free_strings();
}
