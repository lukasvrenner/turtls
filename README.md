# turtls 🐢

## A work-in-progress TLS 1.3 dynamic library
Note: Although turtls is written in Rust, it only provides a C API.

WARNING: This code has not been audited. Use it at your own risk.
================================================================

## Features
1. Simple API:
- `turtls_generate_config`: Generate the default configuration struct.
- `turtls_alloc`: Allocate the connection state buffer.
- `turtls_free`: Free the connection state buffer.
- `turtls_client_handshake`: Perform the TLS handshake as the client.
- `turtls_server_handshake`: Perform the TLS handshake as the server (not yet implemented).
- `turtls_send`: send data to the peer (not yet implemented).
- `turtls_read`: read data from the peer (not yet implemented).
- `turtls_close`: close the connection.
2. Configuration struct: all configuration is done via a single config struct
3. AEADs:
- [AES-* GCM](https://en.wikipedia.org/wiki/Galois/Counter_Mode)
- [ChaCha20Poly1305](https://en.wikipedia.org/wiki/ChaCha20-Poly1305)
4. ECC:
- [ECDSA](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm)
- [ECDH](https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman)
- Curves: secp256r1 (NIST-P 256)
5. Hash:
- [SHA-256](https://en.wikipedia.org/wiki/SHA-2)
- [SHA-512](https://en.wikipedia.org/wiki/SHA-2)
- [HMAC](https://en.wikipedia.org/wiki/HMAC)
- [HKDF](https://en.wikipedia.org/wiki/HKDF)


## Cryptography
turtls uses in-house cryptography, meaning it uses its own crypto library, called crylib.
crylib can also be used independently of turtls.

## Building
Make sure you have a recent version of Rust installed. This project uses on new language features as they release,
so make sure your version is recent enough.

To build in debug mode:
```bash
cargo build
```

To build in release mode:
```bash
cargo build --release
```

Move `libturtls.so` from `./target/debug/` -- debug -- or `./target/release/` -- release to the desired directory.

## License
Copyright 2024 Lukas Renner

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

See LICENSE for details
