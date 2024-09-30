// test_session.c

#include "secure_comm.h"

#include <stdio.h>      // For printf, fprintf

int main() {
    // Initialize a user session with valid credentials
    const char* username = "user";
    const char* password = "pass"; // Correct password

    UserSession* session = NULL;
    SecureCommError ret = initialize_session(username, password, &session);
    if (ret != SECURE_COMM_SUCCESS) {
        fprintf(stderr, "test_session: Failed to initialize session. Error code: %d\n", ret);
        return 1;
    }

    printf("test_session: Session initialized successfully.\n");

    // Initialize a session with invalid credentials
    const char* invalid_username = "user";
    const char* invalid_password = "wrongpass";

    UserSession* invalid_session = NULL;
    SecureCommError invalid_ret = initialize_session(invalid_username, invalid_password, &invalid_session);
    if (invalid_ret != SECURE_COMM_SUCCESS) {
        printf("test_session: Correctly failed to initialize session with invalid credentials.\n");
    } else {
        fprintf(stderr, "test_session: Unexpectedly succeeded in initializing session with invalid credentials.\n");
        terminate_session(invalid_session);
        return 1;
    }

    // Terminate the valid session
    terminate_session(session);

    return 0;
}
