# TurTLS Roadmap and Feature Description

## Project Overview
A work-in-progress implementation of the TLS 1.3 protocol (RFC 8446) in Rust, providing a C ABI for broad compatibility. The project emphasizes memory safety, standards compliance, and secure cryptographic operations.

## Meeting Structure
- Set up regular weekly 1-hour meetings
- Establish agenda format:
    - Previous week's goals review
    - Progress updates
    - Technical questions
    - Next week's goals
- [x] Create informal communication channel for ad-hoc questions
  <details>
  <summary>How it was completed</summary>
  <!-- Add your description here -->
  We are using HackMD for collaborative project notes.
  </details>

## Implementation Goals and Features

### Cryptography (crylib)
- AEADs
    - [x] AES-* GCM
    - [x] ChaCha20-Poly1305
- ECC
    - [x] ECDSA
    - [x] ECDH
    - Curves:
        - [x] Sepc256r1
- Big Integer
    - [x] Unsigned big integers
    - [x] Signed big integers
    - [x] Big integer modular arithmetic
- Hash
    - [x] SHA-256
    - [x] SHA-512
    - [ ] SHA-384
- [ ] RSA

### 1. Client implementation
- [x] ClientHello
- [x] ServerHello
- [ ] Handle HelloRetryRequest
- [x] Derive client_handshake_traffic
- [x] Derive server_handshake_traffic
    - [ ] Derive client_application_traffic
    - [ ] Derive server_application_traffic
- [ ] EncryptedExtensions
- [ ] CertificateRequest support (optional)
- [ ] Certificate handling
    - [ ] Define certificate format
    - [ ] Implement certificate user input mechanism
- [ ] CertificateVerify
- [ ] Finished message
- [ ] Derive client_application_traffic
- [ ] Derive server_application_traffic

### 2. Server Implementation
- [ ] ClientHello
- [ ] ServerHello
- [ ] Handle HelloRetryRequest
- [ ] Derive client_handshake_traffic
- [ ] Derive server_handshake_traffic
    - [ ] Derive client_application_traffic
    - [ ] Derive server_application_traffic
- [ ] EncryptedExtensions
- [ ] CertificateRequest support (optional)
- [ ] Certificate handling
    - [ ] Define certificate format
    - [ ] Implement certificate user input mechanism
- [ ] CertificateVerify
- [ ] Finished message
- [ ] Derive client_application_traffic
- [ ] Derive server_application_traffic

### Supported Extensions
- [x] server_name
- [x] supported_groups
- [x] signature_algorithms
- [x] application_layer_protocol_negotiation
- [x] supported_versions
- [ ] cookie
- [x] key_share

### 3. TLS 1.3 Specification Compliance Requirements
- [ ] Mandatory signature algorithms
    - [x] ecdsa_secp256r1
    - [ ] rsa_pkcs1_sha256 (for certificates)
    - [ ] rsa_pss_rsae_sha256 (for CertificateVerify and certificates)
- [x] Mandatory key-exchange methods
    - [x] Secp256r1
- [x] Mandatory Cipher Suites
    - [x] AES_128_GCM_SHA_256
- [x] Record Layer Protocol
    - [x] Unprotected read
    - [x] Unprotected write
    - [x] Protected read
    - [x] Protected write
- [ ] Handshake Protocol
- [x] Alert Protocol

### 4. Testing and Verification
- [ ] Integration Tests
  - [ ] Handshake flows
  - [ ] Error scenarios
  - [ ] Extension handling
- [ ] Cryptographic Algorithm Tests
    - [x] AES-GCM
    - [x] ChaCha20-Poly1305
    - [x] SHA-256
    - [x] SHA-512
    - [x] HMAC
    - [ ] HKDF
    - [x] ECDSA
- [ ] Fuzzing Infrastructure
    - [ ] Protocol message fuzzing
    - [ ] Cryptographic input fuzzing
- [ ] Interoperability Testing
    - [ ] OpenSSL
    - [ ] BoringSSL
    - [ ] Other major implementations

### 5. Optional Enhancements
- [ ] Additional Features
    - [ ] AES_256_GCM_SHA_384
    - [ ] Additional curve support
    - [ ] Pre-shared key (PSK)
    - [ ] 0-RTT data (with PSK)
    - [ ] Send ChangeCipherSpec
    - [ ] Record padding
- [ ] Performance Optimizations
    - [ ] Multi-threaded AEAD
    - [ ] Benchmark AES-GCM and ChaCha20-Poly1305 and prefer faster implementation

### 6. Documentation
- [ ] Code Documentation
  - [ ] Inline API documentation
  - [ ] Architecture overview
- [ ] README
  - [ ] Project goals
  - [x] Feature documentation
  - [x] Setup instructions
  - [x] Reference links
- [ ] Build and Integration Guide
  - [ ] Library usage
  - [ ] C ABI documentation
  - [ ] Build configuration

### 7. HTTPS Client Implementation
- [ ] Core Functionality
    - [x] DNS lookup
    - [x] TCP connection handling
    - [x] TLS handshake integration
    - [ ] HTTP protocol implementation
- [ ] Features
    - [ ] Content retrieval
    - [ ] File writing
    - [x] Error handling
    - [ ] User interface

## Technical Requirements

### System Compatibility
- TurTLS: All systems supported by [getrandom](https://docs.rs/getrandom)
- Pull (HTTPS client): POSIX-compliant systems
- Build system integration
- Dynamic linking configuration

### Security Requirements
- [x] Secure random number generation
- [ ] Protection against timing attacks
- [x] Memory zeroization
- [ ] Side-channel resistance
- [ ] Safe buffer handling
- [x] Resource cleanup
- [x] Clear ownership model

### Performance Goals
- [ ] Define throughput targets
- [ ] Set latency requirements
- [ ] Establish resource usage limits

## Documentation and Resources
- Repository Links:
  - TurTLS: https://github.com/lukasvrenner/turtls
  - Pull (HTTPS client): https://github.com/lukasvrenner/pull
- Specification Links:
  - TLS 1.3: https://datatracker.ietf.org/doc/html/rfc8446
  - Compliance Requirements: https://datatracker.ietf.org/doc/html/rfc8446#section-9

## Project Timeline
### Short Term (1-2 months)
- [ ] Complete test suite
- [ ] Basic client functionality
- [ ] Core documentation

### Medium Term (3-6 months)
- [ ] Server implementation
- [ ] Enhanced features
- [ ] Performance optimization
- [ ] Integration testing

### Long Term (6+ months)
- [ ] Security audit
- [ ] Production readiness
- [ ] API stabilization
- [ ] Complete documentation
