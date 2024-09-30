// utils.c

#include "secure_comm.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <pthread.h> // For mutex (POSIX)
#include <errno.h>

#include "cJSON.h" // Include cJSON header

// Mutex for thread-safe logging
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

// Global variables for logging
static LogLevel current_log_level = LOG_LEVEL_INFO;
static FILE* log_file = NULL;

/**
 * @brief Initializes the logging system.
 *
 * @param level The minimum log level to output.
 * @param log_file_path The file path for logging output. If NULL, logs will be output to the console.
 *
 * @return SECURE_COMM_SUCCESS on success, or a negative error code on failure.
 */
SecureCommError init_logging(LogLevel level, const char* log_file_path) {
    pthread_mutex_lock(&log_mutex);

    current_log_level = level;

    if (log_file_path != NULL && strlen(log_file_path) > 0) {
        log_file = fopen(log_file_path, "a");
        if (log_file == NULL) {
            fprintf(stderr, "init_logging: Failed to open log file '%s': %s\n", log_file_path, strerror(errno));
            pthread_mutex_unlock(&log_mutex);
            return SECURE_COMM_ERR_LOG;
        }
    } else {
        log_file = stdout; // Default to console
    }

    pthread_mutex_unlock(&log_mutex);
    return SECURE_COMM_SUCCESS;
}

/**
 * @brief Logs a message with the specified log level.
 *
 * @param level The log level of the message.
 * @param format The format string (printf-style).
 * @param ... Additional arguments for the format string.
 *
 * @return SECURE_COMM_SUCCESS on success, or a negative error code on failure.
 */
SecureCommError log_message(LogLevel level, const char* format, ...) {
    if (level > current_log_level) {
        return SECURE_COMM_SUCCESS; // Do not log messages below the current log level
    }

    pthread_mutex_lock(&log_mutex);

    // Get current time
    time_t rawtime;
    struct tm* timeinfo;
    char time_buffer[20]; // "YYYY-MM-DD HH:MM:SS"

    time(&rawtime);
    timeinfo = localtime(&rawtime);
    if (timeinfo == NULL) {
        fprintf(stderr, "log_message: localtime failed\n");
        pthread_mutex_unlock(&log_mutex);
        return SECURE_COMM_ERR_LOG;
    }

    if (strftime(time_buffer, sizeof(time_buffer), "%Y-%m-%d %H:%M:%S", timeinfo) == 0) {
        fprintf(stderr, "log_message: strftime failed\n");
        pthread_mutex_unlock(&log_mutex);
        return SECURE_COMM_ERR_LOG;
    }

    // Determine log level string
    const char* level_strings[] = {"ERROR", "WARN", "INFO", "DEBUG"};
    const char* level_str = "UNKNOWN";
    if (level >= LOG_LEVEL_ERROR && level <= LOG_LEVEL_DEBUG) {
        level_str = level_strings[level];
    }

    // Prepare the formatted message
    char message[1024];
    va_list args;
    va_start(args, format);
    int msg_len = vsnprintf(message, sizeof(message), format, args);
    va_end(args);

    if (msg_len < 0) {
        fprintf(stderr, "log_message: vsnprintf failed\n");
        pthread_mutex_unlock(&log_mutex);
        return SECURE_COMM_ERR_LOG;
    }

    // Ensure null-termination
    message[sizeof(message) - 1] = '\0';

    // Write to log destination
    fprintf(log_file, "[%s] [%s] %s\n", time_buffer, level_str, message);
    fflush(log_file);

    pthread_mutex_unlock(&log_mutex);
    return SECURE_COMM_SUCCESS;
}

/**
 * @brief Cleans up the logging system.
 *
 * This function should be called once all logging operations are complete.
 * It performs necessary cleanup tasks, such as closing log files.
 */
void cleanup_logging() {
    pthread_mutex_lock(&log_mutex);

    if (log_file != NULL && log_file != stdout) {
        fclose(log_file);
        log_file = NULL;
    }

    pthread_mutex_unlock(&log_mutex);
    pthread_mutex_destroy(&log_mutex);
}

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
SecureCommError load_configuration(const char* config_path, Configuration* config) {
    if (config_path == NULL || config == NULL) {
        fprintf(stderr, "load_configuration: Invalid arguments\n");
        return SECURE_COMM_ERR_CONFIG;
    }

    // Open the configuration file
    FILE* file = fopen(config_path, "r");
    if (file == NULL) {
        fprintf(stderr, "load_configuration: Failed to open config file '%s': %s\n", config_path, strerror(errno));
        return SECURE_COMM_ERR_CONFIG;
    }

    // Determine the file size
    if (fseek(file, 0, SEEK_END) != 0) {
        fprintf(stderr, "load_configuration: fseek failed\n");
        fclose(file);
        return SECURE_COMM_ERR_CONFIG;
    }

    long file_size = ftell(file);
    if (file_size < 0) {
        fprintf(stderr, "load_configuration: ftell failed\n");
        fclose(file);
        return SECURE_COMM_ERR_CONFIG;
    }
    rewind(file);

    // Allocate memory for the file content
    char* buffer = (char*)malloc(file_size + 1); // +1 for null terminator
    if (buffer == NULL) {
        fprintf(stderr, "load_configuration: Failed to allocate memory for config file\n");
        fclose(file);
        return SECURE_COMM_ERR_MEMORY;
    }

    // Read the file into the buffer
    size_t read_size = fread(buffer, 1, file_size, file);
    if (read_size != (size_t)file_size) {
        fprintf(stderr, "load_configuration: fread failed\n");
        free(buffer);
        fclose(file);
        return SECURE_COMM_ERR_CONFIG;
    }
    buffer[file_size] = '\0'; // Null-terminate

    fclose(file);

    // Parse the JSON
    cJSON* json = cJSON_Parse(buffer);
    if (json == NULL) {
        fprintf(stderr, "load_configuration: Failed to parse JSON: %s\n", cJSON_GetErrorPtr());
        free(buffer);
        return SECURE_COMM_ERR_CONFIG;
    }

    // Defensive parsing: Check for expected fields and validate types
    // Example expected fields:
    // - server_address (string)
    // - server_port (number)
    // - log_level (string)
    // - log_file_path (string)

    // server_address
    cJSON* server_address = cJSON_GetObjectItemCaseSensitive(json, "server_address");
    if (!cJSON_IsString(server_address) || (server_address->valuestring == NULL)) {
        fprintf(stderr, "load_configuration: 'server_address' is missing or not a string\n");
        cJSON_Delete(json);
        free(buffer);
        return SECURE_COMM_ERR_CONFIG;
    }
    strncpy(config->server_address, server_address->valuestring, sizeof(config->server_address) - 1);
    config->server_address[sizeof(config->server_address) - 1] = '\0';

    // server_port
    cJSON* server_port = cJSON_GetObjectItemCaseSensitive(json, "server_port");
    if (!cJSON_IsNumber(server_port)) {
        fprintf(stderr, "load_configuration: 'server_port' is missing or not a number\n");
        cJSON_Delete(json);
        free(buffer);
        return SECURE_COMM_ERR_CONFIG;
    }
    config->server_port = server_port->valueint;

    // log_level
    cJSON* log_level = cJSON_GetObjectItemCaseSensitive(json, "log_level");
    if (cJSON_IsString(log_level) && (log_level->valuestring != NULL)) {
        if (strcmp(log_level->valuestring, "ERROR") == 0) {
            config->log_level = LOG_LEVEL_ERROR;
        } else if (strcmp(log_level->valuestring, "WARN") == 0) {
            config->log_level = LOG_LEVEL_WARN;
        } else if (strcmp(log_level->valuestring, "INFO") == 0) {
            config->log_level = LOG_LEVEL_INFO;
        } else if (strcmp(log_level->valuestring, "DEBUG") == 0) {
            config->log_level = LOG_LEVEL_DEBUG;
        } else {
            fprintf(stderr, "load_configuration: Unknown 'log_level' value '%s'\n", log_level->valuestring);
            cJSON_Delete(json);
            free(buffer);
            return SECURE_COMM_ERR_CONFIG;
        }
    } else {
        fprintf(stderr, "load_configuration: 'log_level' is missing or not a string\n");
        cJSON_Delete(json);
        free(buffer);
        return SECURE_COMM_ERR_CONFIG;
    }

    // log_file_path
    cJSON* log_file_path = cJSON_GetObjectItemCaseSensitive(json, "log_file_path");
    if (cJSON_IsString(log_file_path) && (log_file_path->valuestring != NULL)) {
        strncpy(config->log_file_path, log_file_path->valuestring, sizeof(config->log_file_path) - 1);
        config->log_file_path[sizeof(config->log_file_path) - 1] = '\0';
    } else {
        // If log_file_path is not provided, default to NULL (console)
        config->log_file_path[0] = '\0';
    }

    // Add additional configuration fields here with similar defensive checks

    // Cleanup
    cJSON_Delete(json);
    free(buffer);

    return SECURE_COMM_SUCCESS;
}
