// test_compression.c

#include "secure_comm.h"

#include <stdio.h>      // For printf, fprintf
#include <string.h>     // For strlen, memcmp
#include <stdlib.h>     // For malloc, free

int main() {
    // Sample input data (replace with a larger text for more rigorous testing)
    const char* input = "This is a sample text that will be compressed using zlib. "
                        "Compression can significantly reduce the size of data, "
                        "especially when dealing with large volumes of repetitive information. "
                        "Adding more data to increase the size and test the robustness of the compression module. "
                        "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.";
    size_t input_len = strlen(input);

    // -----------------------------
    // Testing compress_data_dynamic
    // -----------------------------
    printf("---- Testing compress_data_dynamic ----\n");

    unsigned char* compressed = NULL;
    size_t compressed_len = 0;

    SecureCommError comp_ret = compress_data_dynamic((unsigned char*)input, input_len,
                                                     &compressed, &compressed_len, 9); // Compression level 6
    if (comp_ret != SECURE_COMM_SUCCESS) {
        fprintf(stderr, "compress_data_dynamic failed with error code: %d\n", comp_ret);
        return 1;
    }

    printf("Original size: %zu bytes\n", input_len);
    printf("Compressed size: %zu bytes\n", compressed_len);

    // -------------------------------
    // Testing decompress_data_dynamic
    // -------------------------------
    printf("\n---- Testing decompress_data_dynamic ----\n");

    unsigned char* decompressed = NULL;
    size_t decompressed_len = 0;

    SecureCommError decomp_ret = decompress_data_dynamic(compressed, compressed_len,
                                                         &decompressed, &decompressed_len);
    if (decomp_ret != SECURE_COMM_SUCCESS) {
        fprintf(stderr, "decompress_data_dynamic failed with error code: %d\n", decomp_ret);
        free(compressed);
        return 1;
    }

    // Null-terminate the decompressed data for safe printing
    char* decompressed_str = (char*)malloc(decompressed_len + 1);
    if (decompressed_str == NULL) {
        fprintf(stderr, "Failed to allocate memory for null-terminated decompressed string.\n");
        free(compressed);
        free(decompressed);
        return 1;
    }
    memcpy(decompressed_str, decompressed, decompressed_len);
    decompressed_str[decompressed_len] = '\0';

    printf("Decompressed size: %zu bytes\n", decompressed_len);
    printf("Decompressed text:\n%s\n", decompressed_str);

    // Verify that decompressed data matches original input
    if (decompressed_len != input_len || memcmp(input, decompressed, input_len) != 0) {
        fprintf(stderr, "Decompressed data does not match original input.\n");
        free(compressed);
        free(decompressed);
        free(decompressed_str);
        return 1;
    }

    printf("Compression and decompression successful.\n");

    // Clean up
    free(compressed);
    free(decompressed);
    free(decompressed_str);

    return 0;
}
