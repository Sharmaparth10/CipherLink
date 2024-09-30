// server.c

#include "secure_comm.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>         // For close()
#include <arpa/inet.h>      // For sockaddr_in, inet_ntoa()
#include <pthread.h>        // For threading
#include <errno.h>          // For errno and strerror

#define BUFFER_SIZE 4096
#define IV_SIZE 12          // 12 bytes IV for AES-GCM
#define TAG_SIZE 16         // 16 bytes authentication tag

// Function prototypes
void* handle_client(void* arg);
void* sender_thread_func(void* arg);
void* receiver_thread_func(void* arg);

// Structure to pass data to client handler threads
typedef struct {
    int client_sock;
    struct sockaddr_in client_addr;
    unsigned char session_key[32];
} server_thread_data_t;

// Mutex for console access
pthread_mutex_t console_mutex = PTHREAD_MUTEX_INITIALIZER;

int main(int argc, char* argv[]) {
    printf("Server starting...\n");

    // Load configuration
    Configuration config;
    SecureCommError config_ret = load_configuration("../server_config.json", &config);
    if (config_ret != SECURE_COMM_SUCCESS) {
        fprintf(stderr, "server: Failed to load configuration. Error code: %d\n", config_ret);
        return EXIT_FAILURE;
    }

    // Initialize logging
    SecureCommError log_ret;
    if (strlen(config.log_file_path) > 0) {
        log_ret = init_logging(config.log_level, config.log_file_path);
    } else {
        log_ret = init_logging(config.log_level, NULL); // Log to console
    }

    if (log_ret != SECURE_COMM_SUCCESS) {
        fprintf(stderr, "server: Failed to initialize logging. Error code: %d\n", log_ret);
        return EXIT_FAILURE;
    }

    log_message(LOG_LEVEL_INFO, "Server starting...");

    // Initialize server socket
    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) {
        log_message(LOG_LEVEL_ERROR, "Failed to create socket: %s", strerror(errno));
        cleanup_logging();
        return EXIT_FAILURE;
    }

    // Allow socket reuse
    int opt = 1;
    if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        log_message(LOG_LEVEL_WARN, "setsockopt(SO_REUSEADDR) failed: %s", strerror(errno));
    }

    // Bind socket to the specified address and port
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(config.server_port);
    server_addr.sin_addr.s_addr = inet_addr(config.server_address);

    if (bind(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        log_message(LOG_LEVEL_ERROR, "Failed to bind socket: %s", strerror(errno));
        close(server_sock);
        cleanup_logging();
        return EXIT_FAILURE;
    }

    log_message(LOG_LEVEL_INFO, "Server listening on %s:%d", config.server_address, config.server_port);

    // Listen for incoming connections
    if (listen(server_sock, 5) < 0) {
        log_message(LOG_LEVEL_ERROR, "Failed to listen on socket: %s", strerror(errno));
        close(server_sock);
        cleanup_logging();
        return EXIT_FAILURE;
    }

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_sock = accept(server_sock, (struct sockaddr*)&client_addr, &client_len);
        if (client_sock < 0) {
            log_message(LOG_LEVEL_WARN, "Failed to accept connection: %s", strerror(errno));
            continue;
        }

        log_message(LOG_LEVEL_INFO, "Accepted connection from %s:%d",
                    inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

        // Allocate memory for client info
        server_thread_data_t* thread_data = (server_thread_data_t*)malloc(sizeof(server_thread_data_t));
        if (!thread_data) {
            log_message(LOG_LEVEL_ERROR, "Failed to allocate memory for client info");
            close(client_sock);
            continue;
        }
        thread_data->client_sock = client_sock;
        thread_data->client_addr = client_addr;

        // Predefined session key (must be the same on both client and server)
        unsigned char session_key[32] = {
            0x00, 0x01, 0x02, 0x03,
            0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B,
            0x0C, 0x0D, 0x0E, 0x0F,
            0x10, 0x11, 0x12, 0x13,
            0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1A, 0x1B,
            0x1C, 0x1D, 0x1E, 0x1F
        };
        memcpy(thread_data->session_key, session_key, 32);

        // Create a thread to handle the client
        pthread_t thread_id;
        if (pthread_create(&thread_id, NULL, handle_client, (void*)thread_data) != 0) {
            log_message(LOG_LEVEL_ERROR, "Failed to create thread for client %s:%d",
                        inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
            close(client_sock);
            free(thread_data);
            continue;
        }

        // Detach the thread to reclaim resources upon completion
        pthread_detach(thread_id);
    }

    // Cleanup (unreachable in this example)
    close(server_sock);
    cleanup_logging();
    return EXIT_SUCCESS;
}

/**
 * @brief Handles communication with a connected client.
 */
void* handle_client(void* arg) {
    server_thread_data_t* data = (server_thread_data_t*)arg;
    int client_sock = data->client_sock;
    struct sockaddr_in client_addr = data->client_addr;
    unsigned char* session_key = data->session_key;

    // Create sender and receiver threads
    pthread_t sender_thread, receiver_thread;

    if (pthread_create(&sender_thread, NULL, sender_thread_func, (void*)data) != 0) {
        log_message(LOG_LEVEL_ERROR, "Failed to create sender thread for client %s:%d",
                    inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
        close(client_sock);
        free(data);
        pthread_exit(NULL);
    }

    if (pthread_create(&receiver_thread, NULL, receiver_thread_func, (void*)data) != 0) {
        log_message(LOG_LEVEL_ERROR, "Failed to create receiver thread for client %s:%d",
                    inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
        close(client_sock);
        free(data);
        pthread_exit(NULL);
    }

    // Wait for the sender thread to finish
    pthread_join(sender_thread, NULL);

    // Close the socket to signal the receiver thread to exit
    close(client_sock);

    // Wait for the receiver thread to finish
    pthread_join(receiver_thread, NULL);

    // Cleanup
    free(data);

    pthread_exit(NULL);
}

/**
 * @brief Thread function to handle sending messages to the client.
 */
void* sender_thread_func(void* arg) {
    server_thread_data_t* data = (server_thread_data_t*)arg;
    int client_sock = data->client_sock;
    unsigned char* session_key = data->session_key;

    while (1) {
        // Lock console to print prompt
        pthread_mutex_lock(&console_mutex);

        // Print prompt
        printf("To client %s:%d: ", inet_ntoa(data->client_addr.sin_addr), ntohs(data->client_addr.sin_port));
        fflush(stdout); // Ensure prompt is displayed

        // Unlock console before blocking on fgets
        pthread_mutex_unlock(&console_mutex);

        // Get user input
        char message[BUFFER_SIZE];
        if (fgets(message, sizeof(message), stdin) == NULL) {
            break;
        }

        // Remove newline character
        size_t msg_len = strlen(message);
        if (msg_len > 0 && message[msg_len - 1] == '\n') {
            message[msg_len - 1] = '\0';
            msg_len--;
        }

        // Check for exit command
        if (strcmp(message, "exit") == 0) {
            break;
        }

        unsigned char encrypted_msg[BUFFER_SIZE];
        int encrypted_len = 0;
        unsigned char iv[IV_SIZE];
        unsigned char tag[TAG_SIZE];

        // Encrypt the message
        SecureCommError encrypt_ret = encrypt_data((unsigned char*)message, msg_len,
                                                   session_key, iv,
                                                   encrypted_msg, &encrypted_len, tag);
        if (encrypt_ret != SECURE_COMM_SUCCESS) {
            log_message(LOG_LEVEL_ERROR, "Failed to encrypt message to %s:%d. Error code: %d",
                        inet_ntoa(data->client_addr.sin_addr), ntohs(data->client_addr.sin_port), encrypt_ret);
            continue;
        }

        // Send the IV + tag + encrypted message
        unsigned char final_output[IV_SIZE + TAG_SIZE + encrypted_len];
        memcpy(final_output, iv, IV_SIZE);                             // Copy IV
        memcpy(final_output + IV_SIZE, tag, TAG_SIZE);                 // Copy authentication tag
        memcpy(final_output + IV_SIZE + TAG_SIZE, encrypted_msg, encrypted_len); // Copy encrypted data

        ssize_t bytes_sent = send(client_sock, final_output, IV_SIZE + TAG_SIZE + encrypted_len, 0);
        if (bytes_sent < 0) {
            log_message(LOG_LEVEL_WARN, "Failed to send message to %s:%d: %s",
                        inet_ntoa(data->client_addr.sin_addr), ntohs(data->client_addr.sin_port), strerror(errno));
            break;
        }
    }

    pthread_exit(NULL);
}

/**
 * @brief Thread function to handle receiving messages from the client.
 */
void* receiver_thread_func(void* arg) {
    server_thread_data_t* data = (server_thread_data_t*)arg;
    int client_sock = data->client_sock;
    unsigned char* session_key = data->session_key;

    unsigned char buffer[BUFFER_SIZE];

    while (1) {
        ssize_t bytes_received = recv(client_sock, buffer, sizeof(buffer), 0);
        if (bytes_received <= 0) {
            if (bytes_received == 0) {
                log_message(LOG_LEVEL_INFO, "Client %s:%d disconnected",
                            inet_ntoa(data->client_addr.sin_addr), ntohs(data->client_addr.sin_port));
            } else {
                log_message(LOG_LEVEL_WARN, "Recv failed from %s:%d: %s",
                            inet_ntoa(data->client_addr.sin_addr), ntohs(data->client_addr.sin_port), strerror(errno));
            }
            break; // Exit the loop to close the connection
        }

        // Decrypt the received message
        unsigned char iv[IV_SIZE];
        unsigned char tag[TAG_SIZE];
        unsigned char decrypted_msg[BUFFER_SIZE];
        int decrypted_len = 0;

        if (bytes_received < IV_SIZE + TAG_SIZE) {
            log_message(LOG_LEVEL_ERROR, "Received data is too short to contain IV and tag");
            continue;
        }

        // Extract IV and tag from the received buffer
        memcpy(iv, buffer, IV_SIZE);
        memcpy(tag, buffer + IV_SIZE, TAG_SIZE);
        unsigned char* ciphertext = buffer + IV_SIZE + TAG_SIZE;
        int ciphertext_len = bytes_received - IV_SIZE - TAG_SIZE;

        SecureCommError decrypt_ret = decrypt_data(ciphertext, ciphertext_len,
                                                   session_key, iv,
                                                   decrypted_msg, &decrypted_len, tag);
        if (decrypt_ret != SECURE_COMM_SUCCESS) {
            log_message(LOG_LEVEL_ERROR, "Failed to decrypt message from %s:%d. Error code: %d",
                        inet_ntoa(data->client_addr.sin_addr), ntohs(data->client_addr.sin_port), decrypt_ret);
            continue;
        }

        decrypted_msg[decrypted_len] = '\0'; // Null-terminate the decrypted message

        // Lock console before printing received message
        pthread_mutex_lock(&console_mutex);

        // Move cursor to a new line if the sender prompt is active
        printf("\nClient %s:%d: %s\n",
               inet_ntoa(data->client_addr.sin_addr), ntohs(data->client_addr.sin_port), decrypted_msg);

        // Re-print the sender prompt
        printf("To client %s:%d: ", inet_ntoa(data->client_addr.sin_addr), ntohs(data->client_addr.sin_port));
        fflush(stdout);

        // Unlock console
        pthread_mutex_unlock(&console_mutex);
    }

    pthread_exit(NULL);
}
