# CMakeLists.txt

cmake_minimum_required(VERSION 3.10)
project(SecureCommLibrary C)

# Set C standard
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED True)

# Find OpenSSL
find_package(OpenSSL REQUIRED)
if (OPENSSL_FOUND)
    include_directories(${OPENSSL_INCLUDE_DIR})
else()
    message(FATAL_ERROR "OpenSSL not found")
endif()

# Find zlib
find_package(ZLIB REQUIRED)
if (ZLIB_FOUND)
    include_directories(${ZLIB_INCLUDE_DIRS})
else()
    message(FATAL_ERROR "zlib not found")
endif()

# Add cJSON source files
set(CJSON_SOURCES
    libs/cJSON/cJSON.c
)

# Add library source files
set(LIB_SOURCES
    src/compression.c
    src/encryption.c
    src/session.c
    src/utils.c
    ${CJSON_SOURCES}
    # Add other module source files here as they are implemented
)

# Create the static library
add_library(secure_comm STATIC ${LIB_SOURCES})

# Link libraries
target_link_libraries(secure_comm PUBLIC OpenSSL::SSL OpenSSL::Crypto ZLIB::ZLIB pthread)

# Add include directories
target_include_directories(secure_comm PUBLIC 
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/libs/cJSON
)

# Add test programs
add_executable(test_compression tests/test_compression.c)
target_link_libraries(test_compression PRIVATE secure_comm)

add_executable(test_session tests/test1_session.c)
target_link_libraries(test_session PRIVATE secure_comm)

add_executable(test_utils tests/test_utils.c)
target_link_libraries(test_utils PRIVATE secure_comm)

# -------------------------------------------------------
# Extend CMake to include client and server build targets
# -------------------------------------------------------

# Add executable for client
add_executable(client client.c)
target_link_libraries(client PRIVATE secure_comm)

# Add executable for server
add_executable(server server.c)
target_link_libraries(server PRIVATE secure_comm)

# -------------------------------------------------------
# Optional: Add some output configuration messages
# -------------------------------------------------------
message(STATUS "Building the Secure Communication Library")
message(STATUS "OpenSSL Include Directory: ${OPENSSL_INCLUDE_DIR}")
message(STATUS "Zlib Include Directory: ${ZLIB_INCLUDE_DIRS}")

