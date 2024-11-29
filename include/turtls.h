#ifndef TURTLS_H
#define TURTLS_H

/* This file is autogenerated by cbindgen. Don't modify this manually. */

#include <stddef.h>
#include <stdint.h>


/**
 * The ECDSA signature algoritm over the secp256r1 (NIST-P 256) curve.
 */
#define turtls_ECDSA_SECP256R1 1

/**
 * Key exchange via ECDH on the secp256r1 (NIST-P 256) curve.
 */
#define turtls_SECP256R1 1

/**
 * TLS error reporting.
 */
enum turtls_Alert
#ifdef __cplusplus
  : uint8_t
#endif // __cplusplus
 {
    /**
     * The connection is being closed
     */
    TURTLS_ALERT_CLOSE_NOTIFY = 0,
    /**
     * An unexpected message was received.
     */
    TURTLS_ALERT_UNEXPECTED_MESSAGE = 10,
    /**
     * Record authentication failed.
     */
    TURTLS_ALERT_BAD_RECORD_MAC = 20,
    /**
     * The record was longer than the maximum record size.
     */
    TURTLS_ALERT_RECORD_OVERFLOW = 22,
    /**
     * The handshake failed for an unspecified reason.
     */
    TURTLS_ALERT_HANDSHAKE_FAILURE = 40,
    /**
     * The provided certificate was invalid.
     */
    TURTLS_ALERT_BAD_CERT = 42,
    /**
     * The provided certificated is unsupported.
     */
    TURTLS_ALERT_UNSUPPORTED_CERT = 43,
    /**
     * The provided certificate has been revoked.
     */
    TURTLS_ALERT_CERT_REVOKED = 44,
    /**
     * The provided certificate has expired.
     */
    TURTLS_ALERT_CERT_EXPIRED = 45,
    /**
     * There was an unspecified error processing the certificate.
     */
    TURTLS_ALERT_CERT_UNKNOWN = 46,
    /**
     * A parameter was invalid (e.g. an elliptic curve point wasn't on the curve).
     */
    TURTLS_ALERT_ILLEGAL_PARAM = 47,
    /**
     * The provided certificate authority is unrecognized.
     */
    TURTLS_ALERT_UNKNOWN_CA = 48,
    /**
     * The sender decided not to proceed with the handshake.
     */
    TURTLS_ALERT_ACCESS_DENIED = 49,
    /**
     * There was an error decoding a message.
     */
    TURTLS_ALERT_DECODE_ERROR = 50,
    /**
     * There was an error decrypting a message.
     */
    TURTLS_ALERT_DECRYPT_ERORR = 51,
    /**
     * The attempted protocol version is unsupported.
     */
    TURTLS_ALERT_PROTOCOL_VERSION = 70,
    /**
     * The server requires more-secure parameters than those provided by the client.
     */
    TURTLS_ALERT_INSUFFICIENT_SECURITY = 71,
    /**
     * An unrelated internal error has occured.
     */
    TURTLS_ALERT_INTERNAL_ERROR = 80,
    TURTLS_ALERT_INAPPROPRIATE_FALLBACK = 86,
    /**
     * The user interupted the handshake.
     */
    TURTLS_ALERT_USER_CANCELLED = 90,
    /**
     * A required extension is missing.
     */
    TURTLS_ALERT_MISSING_EXTENSION = 109,
    /**
     * An extension was sent that isn't supported.
     */
    TURTLS_ALERT_UNSUPPORTED_EXTENSION = 110,
    /**
     * The provided server name is unrecognized.
     */
    TURTLS_ALERT_UNRECOGNIZED_NAME = 112,
    TURTLS_ALERT_BAD_CERT_STATUS_RESPONSE = 113,
    TURTLS_ALERT_UNKNOWN_PSK_IDENTITY = 115,
    /**
     * A certificate is required.
     */
    TURTLS_ALERT_CERT_REQUIRED = 116,
    /**
     * No application protocol was provided.
     */
    TURTLS_ALERT_NO_APP_PROTOCOL = 120,
};
#ifndef __cplusplus
typedef uint8_t turtls_Alert;
#endif // __cplusplus

/**
 * The error that is returned when there is an error in the config.
 */
enum turtls_ConfigError {
    /**
     * No cipher suites were provided.
     */
    TURTLS_CONFIG_ERROR_MISSING_CIPHER_SUITES,
    /**
     * One or more extensions is missing.
     */
    TURTLS_CONFIG_ERROR_MISSING_EXTENSIONS,
};

/**
 * A TLS connection buffer.
 *
 * This connection buffer may be reused between multiple consecutive connections.
 */
struct turtls_Connection;

/**
 * The result of the handshake.
 *
 * If a value other than `Ok` is returned, the connection is closed.
 */
enum turtls_ShakeResult_Tag {
    /**
     * Indicates a successful handshake.
     */
    TURTLS_SHAKE_RESULT_OK,
    /**
     * Indicates that the peer sent an alert.
     */
    TURTLS_SHAKE_RESULT_RECEIVED_ALERT,
    /**
     * Indicates that an alert was sent to the peer.
     */
    TURTLS_SHAKE_RESULT_SENT_ALERT,
    /**
     * Indicates that there was an error generating a random number.
     */
    TURTLS_SHAKE_RESULT_RNG_ERROR,
    /**
     * Indicates that there was an error performing an IO operation.
     */
    TURTLS_SHAKE_RESULT_IO_ERROR,
    /**
     * Indicates that the record read took too long.
     */
    TURTLS_SHAKE_RESULT_TIMEOUT,
    /**
     * Indicates that the randomly-generated private key was zero.
     */
    TURTLS_SHAKE_RESULT_PRIV_KEY_IS_ZERO,
    /**
     * Indicates there was an error in the config struct.
     */
    TURTLS_SHAKE_RESULT_CONFIG_ERROR,
};

struct turtls_ShakeResult {
    enum turtls_ShakeResult_Tag tag;
    union {
        struct {
            turtls_Alert received_alert;
        };
        struct {
            turtls_Alert sent_alert;
        };
        struct {
            enum turtls_ConfigError config_error;
        };
    };
};

/**
 * The functions to use to perform IO.
 *
 * This includes reading, writing, and closing the connection.
 */
struct turtls_Io {
    /**
     * A *non-blocking* write function.
     *
     * `write_fn` must return a negative value when a fatal error occurs and zero when a non-fatal
     * error occurs. If no error occurs, it must return the number of bytes written.
     *
     * `buf`: the buffer to write.
     * `amt`: the number of bytes to write.
     * `ctx`: contextual data (e.g. a file descriptor).
     */
    ptrdiff_t (*write_fn)(const void *buf, size_t amt, const void *ctx);
    /**
     * A *non-blocking* read function.
     *
     * `read_fn` must return a negative value when a fatal error occurs and zero when a non-fatal
     * error occurs. If no error occurs, it must return the number of bytes written.
     *
     * `buf`: the buffer to read to.
     * `amt`: the maximum number of bytes to read.
     * `ctx`: contextual data (e.g. a file descriptor).
     *
     * This function must return a negative value on error, and `0` when no bytes are read.
     */
    ptrdiff_t (*read_fn)(void *buf, size_t amt, const void *ctx);
    /**
     * A function to close the connection.
     *
     * `ctx`: any contextual data (e.g. what socket to close).
     */
    void (*close_fn)(const void *ctx);
    /**
     * Contextual data (e.g. a file descriptor).
     *
     * Lifetime: this pointer must be valid for the duration of the connection.
     */
    void *ctx;
};

/**
 * The extensions to use in the handshake.
 *
 * Refer to each extension's individual documentation for specific usage information.
 */
struct turtls_ExtList {
    /**
     * The server name to send to the server or to expect from the client.
     *
     * If `server_name` is `null`, the extension won't be sent.
     *
     * `server_name` need not be null-terminated.
     */
    const char *server_name;
    /**
     * The length of the `server_name` string in bytes.
     *
     * If `server_name_len` is `0`, the extension won't be sent.
     */
    size_t server_name_len;
    /**
     * The signature algorithms to support.
     */
    uint16_t sig_algs;
    /**
     * The methods to use for key exchange.
     */
    uint16_t sup_groups;
};

/**
 * The supported ciphersuites.
 */
typedef uint8_t turtls_CipherList;
/**
 * AES-128 GCM with SHA-256.
 *
 * Use this unless *UTMOST* security is needed.
 */
#define turtls_CipherList_AES_128_GCM_SHA256 1
/**
 * ChaCha20 Poly1305 with SHA-256.
 *
 * This is a good option. You should probably leave it enabled.
 */
#define turtls_CipherList_CHA_CHA_POLY1305_SHA256 2

/**
 * The configurations to use for a specific TLS connection.
 *
 * This can be automatically generated by `turtls_generate_config`.
 */
struct turtls_Config {
    /**
     * The timeout in milliseconds to use for record layer reads during the handshake.
     *
     * Default value: `10000`
     */
    uint64_t timeout_millis;
    /**
     * The extensions to use.
     */
    struct turtls_ExtList extensions;
    /**
     * The cipher suites to use.
     */
    turtls_CipherList cipher_suites;
};

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * Allocates a connection buffer.
 *
 * This buffer must be freed by `turtls_free` to avoid memory leakage.
 */
struct turtls_Connection *turtls_alloc(void);

/**
 * Alerts the peer and closes the connection.
 *
 * # Safety:
 * `connection` may be `NULL` but must be valid.
 */
void turtls_close(struct turtls_Connection *connection);

/**
 * Performs a TLS handshake with a server, returning the connection status.
 *
 * If any error is returned, the connection is automatically closed.
 *
 * # Safety:
 * `connection` must be valid.
 * `config` must be valid.
 *
 * Lifetime: `io.ctx` must be valid until the connction is closed.
 */
struct turtls_ShakeResult turtls_connect(struct turtls_Io io,
                                         struct turtls_Connection *connection,
                                         const struct turtls_Config *config);

/**
 * Frees a connection buffer.
 *
 * This buffer must have been allocated by `turtls_alloc`.
 *
 * # Safety:
 * `connection` must be allocated by `turtls_alloc`.
 */
void turtls_free(struct turtls_Connection *connection);

/**
 * Generates a default configuration struct.
 */
struct turtls_Config turtls_generate_config(void);

/**
 * Returns a string representation of the alert.
 *
 * Lifetime: the returned string has a static lifetime and as such can be used for the duration of
 * the program.
 */
const int8_t *turtls_stringify_alert(turtls_Alert alert);

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus

#endif  /* TURTLS_H */
