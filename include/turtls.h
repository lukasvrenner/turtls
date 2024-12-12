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
    /**
     * An inappropriate downgrade was attempted.
     */
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
    /**
     * An invalid or unacceptable OCSP was provided.
     */
    TURTLS_ALERT_BAD_CERT_STATUS_RESPONSE = 113,
    /**
     * PSK is desired but no acceptable PSK identity is sent by the client.
     */
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
    TURTLS_SHAKE_RESULT_MISSING_EXTENSIONS,
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
    };
};

/**
 * The functions to use to perform IO.
 *
 * This includes reading, writing, and closing the connection.
 */
struct turtls_Io {
    /**
     * A write function.
     *
     * `write_fn` must return the number of bytes written. To indicate an error, it must return a
     * value less than `1`.
     *
     * `buf`: the buffer to write.
     * `amt`: the number of bytes to write.
     * `ctx`: contextual data.
     */
    ptrdiff_t (*write_fn)(const void *buf, size_t amt, const void *ctx);
    /**
     * A read function.
     *
     * `read_fn` must return the number of bytes read. To indicate an error, it must return a
     * value less than `1`.
     *
     * `buf`: the buffer to read to.
     * `amt`: the maximum number of bytes to read.
     * `ctx`: contextual data.
     */
    ptrdiff_t (*read_fn)(void *buf, size_t amt, const void *ctx);
    /**
     * A function to close the connection.
     *
     * `ctx`: contextual data.
     */
    void (*close_fn)(const void *ctx);
    /**
     * Contextual data.
     *
     * This can simply be a file descriptor, or it can be something more complex. For example, it
     * could store both a read and a write file descriptor, error values, and even mutable state.
     *
     * Lifetime: this pointer must be valid for the duration of the connection.
     */
    void *ctx;
};

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * Returns a pointer to name of the negotiated application protocol.
 *
 * The string is nul-terminated.
 *
 * # Safety
 * `connection` must be valid. If `connection` is null, a null pointer will be returned.
 * If `connection` isn't null, a null pointer will never be returned.
 *
 * Lifetime: the returned pointer is valid for the entire lifetime of `connection`. If a new
 * connection is created with the same allocation, pointer is still valid and will point to the
 * new application protocol.
 */
const char *turtls_app_proto(const struct turtls_Connection *connection);

/**
 * Alerts the peer and closes the connection.
 *
 * # Safety:
 * `connection` must be valid.
 */
void turtls_close(struct turtls_Connection *connection);

/**
 * Performs a TLS handshake with a server, returning the connection status.
 *
 * If any error is returned, the connection is automatically closed.
 *
 * # Safety:
 * `connection` must be valid.
 */
struct turtls_ShakeResult turtls_connect(struct turtls_Connection *connection);

/**
 * Frees a connection buffer.
 *
 * After this function is called, `connection` is no longer a valid pointer. Do NOT use it again.
 *
 * # Safety:
 * `connection` must be allocated by `turtls_new`.
 */
void turtls_free(struct turtls_Connection *connection);

/**
 * Creates a new connection object.
 *
 * The object must be freed by `turtls_free` to avoid memory leakage.
 *
 * Lifetime: All pointers contained in `io` must be valid for the lifespan of the connection
 * object.
 */
struct turtls_Connection *turtls_new(struct turtls_Io io);

void turtls_set_app_protos(struct turtls_Connection *connection, const char *ap, size_t ap_len);

void turtls_set_server_name(struct turtls_Connection *connection, const char *sn);

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
