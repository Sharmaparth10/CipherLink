// test_utils.c

#include "secure_comm.h"   // Include the main header
#include <stdio.h>         // For printf, fprintf
#include <string.h>        // For strlen

int main() {
    // Load configuration
    Configuration config;
    SecureCommError config_ret = load_configuration("config.json", &config);
    if (config_ret != SECURE_COMM_SUCCESS) {
        fprintf(stderr, "test_utils: Failed to load configuration. Error code: %d\n", config_ret);
        return 1;
    }

    // Initialize logging based on configuration
    SecureCommError log_ret;
    if (strlen(config.log_file_path) > 0) {
        log_ret = init_logging(config.log_level, config.log_file_path);
    } else {
        log_ret = init_logging(config.log_level, NULL); // Log to console
    }

    if (log_ret != SECURE_COMM_SUCCESS) {
        fprintf(stderr, "test_utils: Failed to initialize logging. Error code: %d\n", log_ret);
        return 1;
    }

    // Log messages at different levels
    log_message(LOG_LEVEL_ERROR, "This is an ERROR message.");
    log_message(LOG_LEVEL_WARN, "This is a WARN message.");
    log_message(LOG_LEVEL_INFO, "This is an INFO message.");
    log_message(LOG_LEVEL_DEBUG, "This is a DEBUG message.");

    // Cleanup logging
    cleanup_logging();

    printf("test_utils: Configuration loaded and logging performed successfully.\n");

    return 0;
}
