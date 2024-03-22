# One-Time Pad Encryption System

This [One-Time Pad (OTP) encryption system](https://en.wikipedia.org/wiki/One-time_pad) provides a secure method of encrypting and decrypting messages using the unbreakable OTP encryption technique. The project consists of two main components: an encryption server (`enc_server`) and a decryption server (`dec_server`), along with corresponding clients (`enc_client` and `dec_client`) that communicate with these servers to perform encryption and decryption operations.

## Features

- **Secure Communication:** Leverages the OTP method for encryption, ensuring the confidentiality of the message as long as the key is kept secret and used only once.
- **Server-Client Architecture:** Implements a server-client model, allowing encryption and decryption operations to be performed over the network.
- **Concurrent Handling:** Both servers can handle multiple client connections concurrently, thanks to multi-threading.
- **Handshake Protocol:** Includes an application-level handshake protocol to prevent incorrect client-server connections.

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

### Prerequisites

- Rust programming language (latest stable version recommended)
- Cargo (Rust's package manager and build system)

### Installation

1. **Clone the Repository:**

```bash
git clone git@github.com:slucasmyer/otp-rust.git
cd otp-rust
```

2. **Build the Project:**

```bash
cargo build --release
```

3. **Run it:**

```bash
cargo run --bin enc_server <enc_port> &

cargo run --bin dec_server <dec_port> &

cargo run --bin keygen <key_length (must be at least as long as file to be encrypted)> > key

cargo run --bin enc_client plaintext* key <enc_port> > ciphertext*

cargo run --bin dec_client ciphertext key <dec_port> > decrypted*
```

Alternatively, you can use the provided `testing_script.sh` script to run the servers, generate keys, and invoke the clients to encrypt and decrypt the provided plaintext files.

```bash
./testing_script.sh
```