#ifndef TURTLS_H
#define TURTLS_H

/* This file is autogenerated by cbindgen. Don't modify this manually. */

#include <stddef.h>
#include <stdint.h>


enum turtls_Alert
#ifdef __cplusplus
  : uint8_t
#endif // __cplusplus
 {
    TURTLS_ALERT_CLOSE_NOTIFY = 0,
    TURTLS_ALERT_UNEXPECTED_MESSAGE = 10,
    TURTLS_ALERT_BAD_RECORD_MAC = 20,
    TURTLS_ALERT_RECORD_OVERFLOW = 22,
    TURTLS_ALERT_HANDSHAKE_FAILURE = 40,
    TURTLS_ALERT_BAD_CERT = 42,
    TURTLS_ALERT_UNSUPPORTED_CERT = 43,
    TURTLS_ALERT_CERT_REVOKED = 44,
    TURTLS_ALERT_CERT_EXPIRED = 45,
    TURTLS_ALERT_CERT_UNKNOWN = 46,
    TURTLS_ALERT_ILLEGAL_PARAM = 47,
    TURTLS_ALERT_UNKNOWN_CA = 48,
    TURTLS_ALERT_ACCESS_DENIED = 49,
    TURTLS_ALERT_DECODE_ERROR = 50,
    TURTLS_ALERT_DECRYPT_ERORR = 51,
    TURTLS_ALERT_PROTOCOL_VERSION = 70,
    TURTLS_ALERT_INSUFFICIENT_SECURITY = 71,
    TURTLS_ALERT_INTERNAL_ERROR = 80,
    TURTLS_ALERT_INAPPROPRIATE_FALLBACK = 86,
    TURTLS_ALERT_USER_CANCELLED = 90,
    TURTLS_ALERT_MISSING_EXTENSION = 109,
    TURTLS_ALERT_UNSUPPORTED_EXTENSION = 110,
    TURTLS_ALERT_UNRECOGNIZED_NAME = 112,
    TURTLS_ALERT_BAD_CERT_STATUS_RESPONSE = 113,
    TURTLS_ALERT_UNKNOWN_PSK_IDENTITY = 115,
    TURTLS_ALERT_CERT_REQUIRED = 116,
    TURTLS_ALERT_NO_APP_PROTOCOL = 120,
};
#ifndef __cplusplus
typedef uint8_t turtls_Alert;
#endif // __cplusplus

/**
 * The maximum length of a record.
 *
 * This is useful in constrained environments.
 */
enum turtls_MaxFragLen
#ifdef __cplusplus
  : uint8_t
#endif // __cplusplus
 {
    /**
     * Use the default record length of 0x4000 bytes.
     */
    TURTLS_MAX_FRAG_LEN_DEFAULT = 0,
    /**
     * 0x200 bytes.
     */
    TURTLS_MAX_FRAG_LEN_HEX200 = 1,
    /**
     * 0x400 bytes.
     */
    TURTLS_MAX_FRAG_LEN_HEX400 = 2,
    /**
     * 0x500 bytes.
     */
    TURTLS_MAX_FRAG_LEN_HEX500 = 3,
    /**
     * 0x600 bytes.
     */
    TURTLS_MAX_FRAG_LEN_HEX600 = 4,
};
#ifndef __cplusplus
typedef uint8_t turtls_MaxFragLen;
#endif // __cplusplus

struct turtls_State;

enum turtls_ShakeResult_Tag {
    TURTLS_SHAKE_RESULT_OK,
    TURTLS_SHAKE_RESULT_RECIEVED_ALERT,
    TURTLS_SHAKE_RESULT_RNG_ERROR,
    TURTLS_SHAKE_RESULT_IO_ERROR,
    TURTLS_SHAKE_RESULT_NULL_PTR,
    TURTLS_SHAKE_RESULT_TIMEOUT,
    TURTLS_SHAKE_RESULT_HANDSHAKE_FAILED,
};

struct turtls_ShakeResult {
    enum turtls_ShakeResult_Tag tag;
    union {
        struct {
            struct turtls_State *ok;
        };
        struct {
            turtls_Alert recieved_alert;
        };
    };
};

struct turtls_Io {
    /**
     * Any io write function.
     *
     * `buf`: the buffer to write.
     * `amt`: the number of bytes to write.
     * `ctx`: any contextual data (e.g. where to write to).
     */
    ptrdiff_t (*write_fn)(const void *buf, size_t amt, const void *ctx);
    /**
     * Any *non-blocking* io read function.
     *
     * `buf`: the buffer to read to.
     * `amt`: the maximum number of bytes to read.
     * `ctx`: any contextual data (e.g. where to read to).
     *
     * This function must return a negative value on error, and `0` when no bytes are read.
     */
    ptrdiff_t (*read_fn)(void *buf, size_t amt, const void *ctx);
    /**
     * Any function to close io.
     *
     * `ctx`: any contextual data (e.g. what socket to close).
     */
    void (*close_fn)(const void *ctx);
    /**
     * Any contextual data.
     *
     * Lifetime: this pointer must be valid for the duration of the connection.
     */
    const void *ctx;
};

/**
 * The server name to send to the server or expect from the client.
 *
 * If no server name is to be sent or expected, set `name` to `NULL` and `len` to `0`.
 * By default, no name will be sent or expected.
 */
struct turtls_ServerName {
    /**
     * The name of the server.
     *
     * The string need not be null-terminated.
     *
     * Lifetime: this pointer must be valid for the duration of the handshake.
     */
    const char *name;
    /**
     * The length of the server name in bytes.
     */
    size_t len;
};

/**
 * A list of algorithms to use for signatures.
 *
 * Use bit-OR to turn an option on and bit-NAND to turn an option off.
 */
typedef uint16_t turtls_SigAlgs;
/**
 * The Elliptic Curve Digital Signature Algorithm with curve Secp256r1 (NIST-P 256).
 */
#define turtls_SigAlgs_ECDSA_SECP256R1 1

/**
 * A list of curves to use for key exchange.
 *
 * Use bit-OR to turn an option on and bit-NAND to turn an option off.
 */
typedef uint16_t turtls_SupGroups;

typedef uint8_t turtls_SupVersions;
#define turtls_SupVersions_TLS_ONE_THREE 1

/**
 * The extensions to use in the handshake.
 *
 * Refer to each extension's individual documentation for specific usage information.
 */
struct turtls_Extensions {
    /**
     * The server name to send to the server or to expect from the client.
     *
     * Refer to its specific documentation for more information.
     */
    struct turtls_ServerName server_name;
    /**
     * A list of signature algorithms to support.
     *
     * Refer to its specific documentation for more information.
     */
    turtls_SigAlgs sig_algs;
    /**
     * A list of curves to use for key exchange.
     *
     * Refer to its specific documentation for more information.
     */
    turtls_SupGroups sup_groups;
    /**
     * A list of TLS versions to support.
     *
     * For now, this must be set to `TLS_ONE_THREE`.
     *
     * Refer to its specific documentation for more information.
     */
    turtls_SupVersions sup_versions;
    /**
     * The maximum length of a record.
     *
     * Refer to its specific documentation for more information.
     */
    turtls_MaxFragLen max_frag_len;
};

/**
 * The supported ciphersuites.
 */
typedef uint8_t turtls_CipherList;
#define turtls_CipherList_AES_128_GCM_SHA256 1
#define turtls_CipherList_CHA_CHA_POLY1305_SHA256 2

struct turtls_Config {
    uint64_t timeout_millis;
    struct turtls_Extensions extensions;
    turtls_CipherList cipher_suites;
};

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * Performs a TLS handshake as the client, returning the connection state or an error.
 */
struct turtls_ShakeResult turtls_client_handshake(struct turtls_Io io,
                                                  const struct turtls_Config *config);

/**
 * Generates a default configuration struct.
 */
struct turtls_Config turtls_generate_config(void);

/**
 * Performs a TLS handshake as the server, returning the connection state or an error.
 */
struct turtls_ShakeResult turtls_server_handshake(struct turtls_Io io,
                                                  const struct turtls_Config *config);

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus

#endif  /* TURTLS_H */
