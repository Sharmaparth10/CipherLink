#ifndef SECURE_COMM_H
#define SECURE_COMM_H

#include <stddef.h>  // for size_t
#include <openssl/evp.h>

// Platform-specific includes and definitions
#ifdef _WIN32
    // Windows-specific headers
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")  // Link with Winsock library

    // ssize_t is not available on Windows by default, so define it here.
    typedef SSIZE_T ssize_t;
#else
    // POSIX-specific headers (Linux, macOS)
    #include <unistd.h>     // for close
    #include <arpa/inet.h>  // for inet_pton
    #include <netdb.h>      // for getaddrinfo
    #include <sys/types.h>
    #include <sys/socket.h>
#endif

// Enum for standardized error codes
typedef enum {
    SECURE_COMM_SUCCESS = 0,        // Operation successful
    SECURE_COMM_ERR_INIT = -1,      // Initialization failed
    SECURE_COMM_ERR_SOCKET = -2,    // Socket creation failed
    SECURE_COMM_ERR_ADDRESS = -3,   // Address resolution failed
    SECURE_COMM_ERR_CONNECT = -4,   // Connection failed
    SECURE_COMM_ERR_SSL_CTX = -5,   // SSL context creation failed
    SECURE_COMM_ERR_SSL = -6,       // SSL operation failed
    SECURE_COMM_ERR_SEND = -7,      // Sending data failed
    SECURE_COMM_ERR_RECV = -8,      // Receiving data failed
    SECURE_COMM_ERR_MEMORY = -9,    // Memory allocation failed
    SECURE_COMM_ERR_ENCRYPT = -10,  // Encryption failed
    SECURE_COMM_ERR_DECRYPT = -11,  // Decryption failed
    SECURE_COMM_ERR_COMPRESS = -12, // Compression failed
    SECURE_COMM_ERR_DECOMPRESS = -13,// Decompression failed
    SECURE_COMM_ERR_SESSION = -14,    // Session management failed
    SECURE_COMM_ERR_CONFIG = -15,    // Configuration parsing failed
    SECURE_COMM_ERR_LOG = -16        //logging failed
} SecureCommError;

// Opaque structure for secure connections
typedef struct SecureConnection SecureConnection;

// Opaque structure for user sessions
typedef struct UserSession {
    char* username;                // Username of the authenticated user
    unsigned char* session_key;    // Symmetric session key for encryption/decryption
    size_t session_key_len;        // Length of the session key
    EVP_PKEY* dh_keypair;          // Diffie-Hellman key pair (EVP_PKEY)
    EVP_PKEY* peer_dh_public;      // Peer public key (EVP_PKEY)
} UserSession;

/**
 * @brief Initializes the networking module.
 *
 * This function sets up any necessary networking resources, such as
 * initializing networking libraries required by the underlying platform.
 *
 * @return SECURE_COMM_SUCCESS on success, or a negative error code on failure.
 */
SecureCommError init_networking();

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
SecureConnection* create_connection(const char* address, int port, SecureCommError* error);

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
SecureCommError secure_send(SecureConnection* conn, const void* data, size_t len, ssize_t* bytes_sent);

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
SecureCommError secure_recv(SecureConnection* conn, void* buffer, size_t len, ssize_t* bytes_received);

/**
 * @brief Closes the secure connection and frees resources.
 *
 * This function gracefully shuts down the SSL connection, closes the socket,
 * and frees any allocated memory associated with the connection.
 *
 * @param conn Pointer to the SecureConnection to close.
 */
void close_connection(SecureConnection* conn);

/**
 * @brief Cleans up networking resources.
 *
 * This function should be called once all networking operations are complete.
 * It performs necessary cleanup tasks, such as freeing global resources.
 */
void cleanup_networking();

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
                             unsigned char* tag);

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
                             const unsigned char* tag);

/**
 * @brief Compresses data using zlib (deflate) with dynamic buffer allocation.
 *
 * This function compresses the input data using the deflate algorithm provided by zlib.
 * It dynamically allocates memory for the compressed data, which must be freed by the caller.
 *
 * @param input Pointer to the data to compress.
 * @param input_len Length of the input data in bytes.
 * @param compressed_ptr Pointer to store the pointer to the compressed data buffer.
 * @param compressed_len Pointer to store the length of the compressed data.
 * @param level Compression level (0-9). 0 = no compression, 9 = maximum compression.
 *
 * @return SECURE_COMM_SUCCESS on success, or a negative error code on failure.
 */
SecureCommError compress_data_dynamic(const unsigned char* input, size_t input_len,
                                      unsigned char** compressed_ptr, size_t* compressed_len,
                                      int level);

/**
 * @brief Decompresses data using zlib (inflate) with dynamic buffer allocation.
 *
 * This function decompresses the input data using the inflate algorithm provided by zlib.
 * It dynamically allocates memory for the decompressed data, which must be freed by the caller.
 *
 * @param compressed Pointer to the data to decompress.
 * @param compressed_len Length of the compressed data in bytes.
 * @param output_ptr Pointer to store the pointer to the decompressed data buffer.
 * @param output_len Pointer to store the length of the decompressed data.
 *
 * @return SECURE_COMM_SUCCESS on success, or a negative error code on failure.
 */
SecureCommError decompress_data_dynamic(const unsigned char* compressed, size_t compressed_len,
                                        unsigned char** output_ptr, size_t* output_len);

/**
 * @brief Initializes a user session.
 *
 * This function initializes a new user session, performing necessary authentication
 * and establishing secure key exchanges.
 *
 * @param username The username of the user initiating the session.
 * @param password The password of the user (for authentication).
 * @param session Pointer to store the created UserSession.
 *
 * @return SECURE_COMM_SUCCESS on success, or a negative error code on failure.
 */
SecureCommError initialize_session(const char* username, const char* password, UserSession** session);

/**
 * @brief Terminates a user session.
 *
 * This function terminates an existing user session, freeing all associated resources.
 *
 * @param session Pointer to the UserSession to terminate.
 */
void terminate_session(UserSession* session);

// -----------------------------------
// Utilities Module Function Declarations
// -----------------------------------

/**
 * @brief Log levels for the logging system.
 */
typedef enum {
    LOG_LEVEL_ERROR = 0,    // Critical errors
    LOG_LEVEL_WARN,         // Warnings
    LOG_LEVEL_INFO,         // Informational messages
    LOG_LEVEL_DEBUG         // Debugging messages
} LogLevel;

/**
 * @brief Initializes the logging system.
 *
 * This function sets up the logging mechanism, including log levels and output destinations.
 * It should be called before any logging is performed.
 *
 * @param level The minimum log level to output.
 * @param log_file_path The file path for logging output. If NULL, logs will be output to the console.
 *
 * @return SECURE_COMM_SUCCESS on success, or a negative error code on failure.
 */
SecureCommError init_logging(LogLevel level, const char* log_file_path);

/**
 * @brief Logs a message with the specified log level.
 *
 * @param level The log level of the message.
 * @param format The format string (printf-style).
 * @param ... Additional arguments for the format string.
 *
 * @return SECURE_COMM_SUCCESS on success, or a negative error code on failure.
 */
SecureCommError log_message(LogLevel level, const char* format, ...);

/**
 * @brief Cleans up the logging system.
 *
 * This function should be called once all logging operations are complete.
 * It performs necessary cleanup tasks, such as closing log files.
 */
void cleanup_logging();

/**
 * @brief Structure to hold configuration parameters.
 *
 * This structure should be expanded to include all necessary configuration options.
 */
typedef struct {
    // Example configuration parameters
    char server_address[256];
    int server_port;
    LogLevel log_level;
    char log_file_path[512];
    // Add additional configuration fields as needed
} Configuration;

/**
 * @brief Loads and parses a JSON configuration file.
 *
 * This function reads a JSON file from the specified path, parses it,
 * and populates the provided Configuration structure.
 * It employs defensive programming to handle malformed or unexpected inputs.
 *
 * @param config_path The file path to the JSON configuration file.
 * @param config Pointer to the Configuration structure to populate.
 *
 * @return SECURE_COMM_SUCCESS on success, or a negative error code on failure.
 */
SecureCommError load_configuration(const char* config_path, Configuration* config);


#endif // SECURE_COMM_H
