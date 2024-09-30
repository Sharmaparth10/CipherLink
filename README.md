
# CipherLink Project

## Overview

This project implements a secure client-server communication system using AES-GCM encryption. It allows for bidirectional, encrypted messaging between a client and a server. The communication is designed to be secure, reliable, and efficient, using multithreading and proper synchronization techniques.

## Features

- Secure Communication: Messages are encrypted using AES-256-GCM, providing both confidentiality and integrity.
- Bidirectional Messaging: Both client and server can send and receive messages interactively during a continuous connection.
- Multithreaded Server: The server can handle multiple clients simultaneously using threads.
- Thread Synchronization: Proper synchronization ensures that messages are displayed immediately upon receipt, without blocking other operations.
- Logging: Configurable logging levels and outputs help in monitoring and debugging.
- Configurable Settings: Uses JSON configuration files for easy adjustment of server and client settings.

```

## Prerequisites

- **C Compiler**: GCC or Clang.
- **OpenSSL**: For encryption functions.
- **pthread Library**: For threading.
- **JSON-C Library**: For parsing JSON configuration files.

## Setup and Installation

### Install Dependencies

- **Ubuntu/Debian**:

  ```bash
  sudo apt-get install build-essential libssl-dev libpthread-stubs0-dev libjson-c-dev doxygen graphviz
  ```

- **macOS (using Homebrew)**:

  ```bash
  brew install openssl json-c doxygen graphviz
  ```

### Building the Project

Use the provided `Makefile` to build the project.

```bash
# In the project root directory
make all
```

This will compile the client and server applications and place the executables in the `bin/` directory.

### Running the Server

```bash
./bin/server
```

### Running the Client

```bash
./bin/client
```

## Configuration

The client and server use JSON configuration files located in the `config/` directory.

- **server_config.json**:

  ```json
  {
    "server_address": "127.0.0.1",
    "server_port": 8080,
    "log_level": "info",
    "log_file_path": "logs/server.log"
  }
  ```

- **client_config.json**:

  ```json
  {
    "server_address": "127.0.0.1",
    "server_port": 8080,
    "log_level": "info",
    "log_file_path": "logs/client.log"
  }
  ```

## Logging

- Logging Levels: `debug`, `info`, `warn`, `error`.
- Log Output: Logs can be written to a file or displayed on the console, based on the `log_file_path` in the configuration.

## Documentation

Documentation is generated using **Doxygen**.

### Generating Documentation

```bash
cd docs
doxygen Doxyfile
```

### Viewing Documentation

Open `docs/html/index.html` in your web browser.
