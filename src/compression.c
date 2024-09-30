// compression.c

#include "secure_comm.h"

#include <stdio.h>      // For fprintf
#include <stdlib.h>     // For malloc, free
#include <string.h>     // For memset

#include <zlib.h>       // For compression functions

/**
 * @brief Compresses data using zlib (deflate) with pre-allocated buffer.
 *
 * This function compresses the input data using the deflate algorithm provided by zlib.
 * The caller must provide a buffer that is large enough to hold the compressed data.
 *
 * @param input Pointer to the data to compress.
 * @param input_len Length of the input data in bytes.
 * @param compressed Pointer to the buffer where compressed data will be stored.
 * @param compressed_len Pointer to store the length of the compressed data.
 * @param level Compression level (0-9). 0 = no compression, 9 = maximum compression.
 *
 * @return SECURE_COMM_SUCCESS on success, or a negative error code on failure.
 */
SecureCommError compress_data(const unsigned char* input, size_t input_len,
                              unsigned char* compressed, size_t* compressed_len,
                              int level) {
    if (input == NULL || compressed == NULL || compressed_len == NULL) {
        fprintf(stderr, "compress_data: Invalid arguments\n");
        return SECURE_COMM_ERR_COMPRESS;
    }

    if (level < 0 || level > 9) {
        fprintf(stderr, "compress_data: Invalid compression level %d\n", level);
        return SECURE_COMM_ERR_COMPRESS;
    }

    z_stream strm;
    memset(&strm, 0, sizeof(strm));

    // Initialize the deflate operation
    if (deflateInit(&strm, level) != Z_OK) {
        fprintf(stderr, "compress_data: deflateInit failed\n");
        return SECURE_COMM_ERR_COMPRESS;
    }

    strm.next_in = (Bytef*)input;
    strm.avail_in = (uInt)input_len;
    strm.next_out = compressed;
    strm.avail_out = (uInt)(*compressed_len);

    // Perform the compression
    int ret = deflate(&strm, Z_FINISH);
    if (ret == Z_STREAM_ERROR) {
        fprintf(stderr, "compress_data: deflate failed with Z_STREAM_ERROR\n");
        deflateEnd(&strm);
        return SECURE_COMM_ERR_COMPRESS;
    }

    // Check if the compression was completed
    if (ret != Z_STREAM_END) {
        // Not enough space in the output buffer
        fprintf(stderr, "compress_data: Not enough space in the compressed buffer. ret=%d\n", ret);
        deflateEnd(&strm);
        return SECURE_COMM_ERR_COMPRESS;
    }

    // Set the compressed length
    *compressed_len = strm.total_out;

    // Clean up
    deflateEnd(&strm);

    return SECURE_COMM_SUCCESS;
}

/**
 * @brief Decompresses data using zlib (inflate) with pre-allocated buffer.
 *
 * This function decompresses the input data using the inflate algorithm provided by zlib.
 * The caller must provide a buffer that is large enough to hold the decompressed data.
 *
 * @param compressed Pointer to the data to decompress.
 * @param compressed_len Length of the compressed data in bytes.
 * @param output Pointer to the buffer where decompressed data will be stored.
 * @param output_len Pointer to store the length of the decompressed data.
 *
 * @return SECURE_COMM_SUCCESS on success, or a negative error code on failure.
 */
SecureCommError decompress_data(const unsigned char* compressed, size_t compressed_len,
                                unsigned char* output, size_t* output_len) {
    if (compressed == NULL || output == NULL || output_len == NULL) {
        fprintf(stderr, "decompress_data: Invalid arguments\n");
        return SECURE_COMM_ERR_DECOMPRESS;
    }

    z_stream strm;
    memset(&strm, 0, sizeof(strm));

    // Initialize the inflate operation
    if (inflateInit(&strm) != Z_OK) {
        fprintf(stderr, "decompress_data: inflateInit failed\n");
        return SECURE_COMM_ERR_DECOMPRESS;
    }

    strm.next_in = (Bytef*)compressed;
    strm.avail_in = (uInt)compressed_len;
    strm.next_out = output;
    strm.avail_out = (uInt)(*output_len);

    // Perform the decompression
    int ret = inflate(&strm, Z_FINISH);
    if (ret == Z_STREAM_ERROR) {
        fprintf(stderr, "decompress_data: inflate failed with Z_STREAM_ERROR\n");
        inflateEnd(&strm);
        return SECURE_COMM_ERR_DECOMPRESS;
    }

    // Check if the decompression was completed
    if (ret != Z_STREAM_END) {
        // Not enough space in the output buffer
        fprintf(stderr, "decompress_data: Not enough space in the output buffer. ret=%d\n", ret);
        inflateEnd(&strm);
        return SECURE_COMM_ERR_DECOMPRESS;
    }

    // Set the decompressed length
    *output_len = strm.total_out;

    // Clean up
    inflateEnd(&strm);

    return SECURE_COMM_SUCCESS;
}

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
                                      int level) {
    if (input == NULL || compressed_ptr == NULL || compressed_len == NULL) {
        fprintf(stderr, "compress_data_dynamic: Invalid arguments\n");
        return SECURE_COMM_ERR_COMPRESS;
    }

    if (level < 0 || level > 9) {
        fprintf(stderr, "compress_data_dynamic: Invalid compression level %d\n", level);
        return SECURE_COMM_ERR_COMPRESS;
    }

    // Calculate the maximum compressed size
    size_t max_compressed_size = compressBound(input_len);

    // Allocate memory for compressed data
    unsigned char* compressed = (unsigned char*)malloc(max_compressed_size);
    if (compressed == NULL) {
        fprintf(stderr, "compress_data_dynamic: Failed to allocate memory for compressed data.\n");
        return SECURE_COMM_ERR_MEMORY;
    }

    z_stream strm;
    memset(&strm, 0, sizeof(strm));

    // Initialize the deflate operation
    if (deflateInit(&strm, level) != Z_OK) {
        fprintf(stderr, "compress_data_dynamic: deflateInit failed\n");
        free(compressed);
        return SECURE_COMM_ERR_COMPRESS;
    }

    strm.next_in = (Bytef*)input;
    strm.avail_in = (uInt)input_len;
    strm.next_out = compressed;
    strm.avail_out = (uInt)max_compressed_size;

    // Perform the compression
    int ret = deflate(&strm, Z_FINISH);
    if (ret == Z_STREAM_ERROR) {
        fprintf(stderr, "compress_data_dynamic: deflate failed with Z_STREAM_ERROR\n");
        deflateEnd(&strm);
        free(compressed);
        return SECURE_COMM_ERR_COMPRESS;
    }

    // Check if the compression was completed
    if (ret != Z_STREAM_END) {
        // Not enough space in the output buffer (shouldn't happen with compressBound)
        fprintf(stderr, "compress_data_dynamic: Compression incomplete. ret=%d\n", ret);
        deflateEnd(&strm);
        free(compressed);
        return SECURE_COMM_ERR_COMPRESS;
    }

    // Set the compressed length
    *compressed_len = strm.total_out;

    // Clean up
    deflateEnd(&strm);

    // Assign the compressed data pointer to the output parameter
    *compressed_ptr = compressed;

    return SECURE_COMM_SUCCESS;
}

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
                                        unsigned char** output_ptr, size_t* output_len) {
    if (compressed == NULL || output_ptr == NULL || output_len == NULL) {
        fprintf(stderr, "decompress_data_dynamic: Invalid arguments\n");
        return SECURE_COMM_ERR_DECOMPRESS;
    }

    // Estimate the decompressed size. This is application-specific.
    // Here, we assume that the decompressed data won't exceed 10 times the compressed size.
    size_t estimated_decompressed_size = compressed_len * 10;

    // Allocate memory for decompressed data
    unsigned char* decompressed = (unsigned char*)malloc(estimated_decompressed_size);
    if (decompressed == NULL) {
        fprintf(stderr, "decompress_data_dynamic: Failed to allocate memory for decompressed data.\n");
        return SECURE_COMM_ERR_MEMORY;
    }

    z_stream strm;
    memset(&strm, 0, sizeof(strm));

    // Initialize the inflate operation
    if (inflateInit(&strm) != Z_OK) {
        fprintf(stderr, "decompress_data_dynamic: inflateInit failed\n");
        free(decompressed);
        return SECURE_COMM_ERR_DECOMPRESS;
    }

    strm.next_in = (Bytef*)compressed;
    strm.avail_in = (uInt)compressed_len;
    strm.next_out = decompressed;
    strm.avail_out = (uInt)estimated_decompressed_size;

    // Perform the decompression
    int ret = inflate(&strm, Z_FINISH);
    if (ret == Z_STREAM_ERROR) {
        fprintf(stderr, "decompress_data_dynamic: inflate failed with Z_STREAM_ERROR\n");
        inflateEnd(&strm);
        free(decompressed);
        return SECURE_COMM_ERR_DECOMPRESS;
    }

    // Check if the decompression was completed
    if (ret != Z_STREAM_END) {
        // Not enough space in the output buffer
        fprintf(stderr, "decompress_data_dynamic: Decompression incomplete. ret=%d\n", ret);
        inflateEnd(&strm);
        free(decompressed);
        return SECURE_COMM_ERR_DECOMPRESS;
    }

    // Set the decompressed length
    *output_len = strm.total_out;

    // Clean up
    inflateEnd(&strm);

    // Assign the decompressed data pointer to the output parameter
    *output_ptr = decompressed;

    return SECURE_COMM_SUCCESS;
}
