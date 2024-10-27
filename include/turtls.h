#ifndef TURTLS_H
#define TURTLS_H

/* This file is autogenerated by cbindgen. Don't modify this manually. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define turtls_CipherSuites_AES_128_GCM_SHA256 1

#define turtls_SignatureAlgorithms_ECDSA_SECP256R1 1

#define turtls_SupportedGroups_SECP256R1 1

#define turtls_SupportedVersions_TLS_ONE_THREE 1

struct turtls_State;

enum turtls_ShakeResult_Tag {
    Ok,
    RngError,
    IoError,
};

struct turtls_ShakeResult {
    enum turtls_ShakeResult_Tag tag;
    union {
        struct {
            struct turtls_State *ok;
        };
    };
};

struct turtls_Io {
    ptrdiff_t (*write_fn)(const void *buf, size_t amt, const void *ctx);
    ptrdiff_t (*read_fn)(void *buf, size_t amt, const void *ctx);
    bool (*is_ready_fn)(const void *ctx);
    void (*close_fn)(const void *ctx);
    const void *ctx;
};

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * Performs a TLS handshake as the client, returning the connection state
 */
struct turtls_ShakeResult shake_hands_client(struct turtls_Io io);

/**
 * Listens for and performs a TLS handshake as the server, returning the connection state
 */
struct turtls_ShakeResult shake_hands_server(struct turtls_Io io);

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus

#endif  /* TURTLS_H */
