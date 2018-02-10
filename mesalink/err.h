/*
 *   __  __                 _     _       _
 *  |  \/  | ___  ___  __ _| |   (_)_ __ | | __
 *  | |\/| |/ _ \/ __|/ _` | |   | | '_ \| |/ /
 *  | |  | |  __/\__ \ (_| | |___| | | | |   <
 *  |_|  |_|\___||___/\__,_|_____|_|_| |_|_|\_\
 *
 * Copyright (c) 2017, The MesaLink Authors. 
 * All rights reserved.
 *
 * This work is licensed under the terms of the BSD 3-Clause License.
 * For a copy, see the LICENSE file.
 *
 */

#ifndef MESALINK_ERR_H
#define MESALINK_ERR_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <mesalink/options.h>
#include <mesalink/version.h>
#include <mesalink/visibility.h>

enum /* ssl constants */
{
    MESALINK_ERROR_NONE = 0,
    MESALINK_FAILURE = 0,
    MESALINK_ERROR = -1,
    MESALINK_SUCCESS = 1,
    MESALINK_SHUTDOWN_NOT_DONE = 2,

    MESALINK_FILETYPE_PEM = 1,
    MESALINK_FILETYPE_ASN1 = 2,
    MESALINK_FILETYPE_DEFAULT = 2,
    MESALINK_FILETYPE_RAW = 3,
};

typedef enum ErrorCode {
    // OpenSSL error codes
    SSL_ERR_NONE = 0,
    SSL_ERROR_ZERO_RETURN = 6,
    SSL_ERROR_WANT_READ = 2,
    SSL_ERROR_WANT_WRITE = 3,
    SSL_ERROR_WANT_CONNECT = 7,
    SSL_ERROR_WANT_ACCEPT = 8,
    SSL_ERROR_SYSCALL = 5,
    SSL_ERROR_SSL = 85,
    // MesaLink built-in error codes
    NULL_POINTER_EXCEPTION = 0x2001,
    MALFORMED_OBJECT,
    BAD_FILE_NAME,
    BAD_KEY,
    CERT_KEY_MISMATCH,
    // std::io error codes
    NOT_FOUND = 0x3001,
    PERMISSION_DENIED,
    CONNECTION_REFUSED,
    CONNECTION_RESET,
    CONNECTION_ABORTED,
    NOT_CONNECTED,
    ADDR_IN_USE,
    ADDR_NOT_AVAILABLE,
    BROKEN_PIPE,
    ALREADY_EXISTS,
    WOULD_BLOCK,
    INVALID_INPUT,
    INVALID_DATA,
    TIMED_OUT,
    WRITE_ZERO,
    INTERRUPTED,
    OTHER,
    UNEXPECTED_EOF,
    // Rustls error codes
    INAPPROPRIATE_MESSAGE = 0x4001,
    INAPPROPRIATE_HANDSHAKE_MESSAGE,
    CORRUPT_MESSAGE,
    CORRUPT_MESSAGE_PAYLOAD,
    NO_CERTIFICATES_PRESENTED,
    DECRYPT_ERROR,
    PEER_INCOMPATIBLE_ERROR,
    PEER_MISBEHAVED_ERROR,
    ALERT_RECEIVED,
    WEB_PKI_ERROR,
    INVALID_SCT,
    GENERAL,
    FAILED_TO_GET_CURRENT_TIME,
    INVALID_DNS_NAME,
    HANDSHAKE_NOT_COMPLETE,
    PEER_SENT_OVERSIZED_RECORD,
} ErrorCode;

MESALINK_API const char *mesalink_ERR_error_string_n(unsigned long e, char *buf, size_t len);
MESALINK_API const char *mesalink_ERR_reason_error_string(unsigned long e);

MESALINK_API unsigned long mesalink_ERR_get_error(void);
MESALINK_API unsigned long mesalink_ERR_peek_last_error(void);
MESALINK_API void mesalink_ERR_clear_error(void);

MESALINK_API void mesalink_ERR_print_errors_fp(const FILE *);

#ifdef __cplusplus
} /* extern C */
#endif

#endif /* MESALINK_ERR_H */
