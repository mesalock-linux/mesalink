/*
 *   __  __                 _     _       _
 *  |  \/  | ___  ___  __ _| |   (_)_ __ | | __
 *  | |\/| |/ _ \/ __|/ _` | |   | | '_ \| |/ /
 *  | |  | |  __/\__ \ (_| | |___| | | | |   <
 *  |_|  |_|\___||___/\__,_|_____|_|_| |_|_|\_\
 *
 * Copyright (c) 2017-2018, The MesaLink Authors.
 * All rights reserved.
 *
 * This work is licensed under the terms of the BSD 3-Clause License.
 * For a copy, see the LICENSE file.
 *
 */

#ifndef MESALINK_OPENSSL_ERR_H
#define MESALINK_OPENSSL_ERR_H

#include <mesalink/ssl.h>
#include <mesalink/err.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SSL_ERROR_WANT_READ MESALINK_ERROR_WANT_READ
#define SSL_ERROR_WANT_WRITE MESALINK_ERROR_WANT_WRITE
#define SSL_ERROR_WANT_CONNECT MESALINK_ERROR_WANT_CONNECT
#define SSL_ERROR_WANT_ACCEPT MESALINK_ERROR_WANT_ACCEPT
#define SSL_ERROR_ZERO_RETURN MESALINK_ERROR_ZERO_RETURN
#define SSL_ERROR_SYSCALL MESALINK_ERROR_SYSCALL
#define SSL_ERROR_SSL MESALINK_ERROR_SSL

#define ERR_load_crypto_strings mesalink_ERR_load_error_strings
#define ERR_free_strings mesalink_ERR_free_error_strings

#define ERR_error_string_n mesalink_ERR_error_string_n
#define ERR_reason_error_string mesalink_ERR_reason_error_string

#define ERR_get_error mesalink_ERR_get_error
#define ERR_peek_last_error mesalink_ERR_peek_last_error
#define ERR_clear_error mesalink_ERR_clear_error

#define ERR_print_errors_fp mesalink_ERR_print_errors_fp

#ifdef __cplusplus
} /* extern C */
#endif

#endif /* MESALINK_OPENSSL_ERR_H */
