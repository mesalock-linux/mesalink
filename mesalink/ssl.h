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

#ifndef MESALINK_SSL_H
#define MESALINK_SSL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <mesalink/options.h>
#include <mesalink/version.h>
#include <mesalink/visibility.h>
#include <mesalink/x509.h>
#include <mesalink/evp.h>

typedef struct MESALINK_METHOD MESALINK_METHOD;
typedef struct MESALINK_CTX MESALINK_CTX;
typedef struct MESALINK_CIPHER MESALINK_CIPHER;
typedef struct MESALINK_SSL MESALINK_SSL;

typedef enum mesalink_verify_mode_t
{
  MESALINK_SSL_VERIFY_NONE = 0,
  MESALINK_SSL_VERIFY_PEER = 1,
  MESALINK_SSL_VERIFY_FAIL_IF_NO_PEER_CERT = 2,
} mesalink_verify_mode_t;

typedef enum mesalink_constant_t
{
  MESALINK_FAILURE = 0,
  MESALINK_ERROR = -1,
  MESALINK_SUCCESS = 1,

  MESALINK_FILETYPE_PEM = 1,
  MESALINK_FILETYPE_ASN1 = 2,
  MESALINK_FILETYPE_DEFAULT = 2,
  MESALINK_FILETYPE_RAW = 3,

  MESALINK_SSL_SESS_CACHE_OFF = 0x0,
  MESALINK_SSL_SESS_CACHE_CLIENT = 0x1,
  MESALINK_SSL_SESS_CACHE_SERVER = 0x2,
  MESALINK_SSL_SESS_CACHE_BOTH = 0x3,

  MESALINK_SSL_EARLY_DATA_NOT_SENT = 0,
  MESALINK_SSL_EARLY_DATA_REJECTED = 1,
  MESALINK_SSL_EARLY_DATA_ACCEPTED = 2,
} mesalink_constant_t;

MESALINK_API int mesalink_library_init(void);
MESALINK_API int mesalink_add_ssl_algorithms(void);
MESALINK_API void mesalink_SSL_load_error_strings(void);
MESALINK_API void mesalink_ERR_load_error_strings(void);
MESALINK_API void mesalink_ERR_free_error_strings(void);

typedef MESALINK_METHOD *(*mesalink_method_func)(void);
MESALINK_API MESALINK_METHOD *mesalink_TLS_method(void);
#ifdef HAVE_CLIENT
// Version-flexible methods
MESALINK_API MESALINK_METHOD *mesalink_TLS_client_method(void);
MESALINK_API MESALINK_METHOD *mesalink_SSLv23_client_method(void);

// Not supported
MESALINK_API MESALINK_METHOD *mesalink_SSLv3_client_method(void);
MESALINK_API MESALINK_METHOD *mesalink_TLSv1_client_method(void);
MESALINK_API MESALINK_METHOD *mesalink_TLSv1_1_client_method(void);

// Version-specific methods
MESALINK_API MESALINK_METHOD *mesalink_TLSv1_2_client_method(void);
#ifdef HAVE_TLS13
MESALINK_API MESALINK_METHOD *mesalink_TLSv1_3_client_method(void);
#endif
MESALINK_API MESALINK_METHOD *mesalink_TLS_client_method(void);
#endif

#ifdef HAVE_SERVER
// Version-flexible methods
MESALINK_API MESALINK_METHOD *mesalink_SSLv23_server_method(void);
MESALINK_API MESALINK_METHOD *mesalink_TLSv_server_method(void);

// Not supported
MESALINK_API MESALINK_METHOD *mesalink_SSLv3_server_method(void);
MESALINK_API MESALINK_METHOD *mesalink_TLSv1_server_method(void);
MESALINK_API MESALINK_METHOD *mesalink_TLSv1_1_server_method(void);

// Version-specific methods
MESALINK_API MESALINK_METHOD *mesalink_TLSv1_2_server_method(void);
#ifdef HAVE_TLS13
MESALINK_API MESALINK_METHOD *mesalink_TLSv1_3_server_method(void);
#endif
#endif

MESALINK_API MESALINK_CTX *mesalink_SSL_CTX_new(MESALINK_METHOD *);
MESALINK_API int mesalink_SSL_CTX_load_verify_locations(MESALINK_CTX *,
                                                        const char *,
                                                        const char *);

MESALINK_API int mesalink_SSL_CTX_use_certificate(MESALINK_CTX *,
                                                  MESALINK_X509 *);
MESALINK_API int mesalink_SSL_CTX_add_extra_chain_cert(MESALINK_CTX *,
                                                       MESALINK_X509 *);
MESALINK_API int mesalink_SSL_CTX_use_certificate_chain_file(MESALINK_CTX *,
                                                             const char *,
                                                             int);
MESALINK_API int mesalink_SSL_CTX_use_certificate_ASN1(MESALINK_CTX *, int,
                                                       const unsigned char *);
MESALINK_API int mesalink_SSL_use_certificate_ASN1(MESALINK_SSL *,
                                                   const unsigned char *, int);
MESALINK_API int mesalink_SSL_CTX_use_PrivateKey_file(MESALINK_CTX *,
                                                      const char *, int);
MESALINK_API int mesalink_SSL_CTX_use_PrivateKey(MESALINK_CTX *,
                                                 MESALINK_EVP_PKEY *);
MESALINK_API int mesalink_SSL_CTX_check_private_key(const MESALINK_CTX *);
MESALINK_API int mesalink_SSL_CTX_use_PrivateKey_ASN1(int, MESALINK_CTX *,
                                                      const unsigned char *,
                                                      long);
MESALINK_API int mesalink_SSL_use_PrivateKey_ASN1(int, MESALINK_SSL *,
                                                  const unsigned char *, long);
MESALINK_API int mesalink_SSL_CTX_check_private_key(const MESALINK_CTX *);
MESALINK_API int mesalink_SSL_check_private_key(const MESALINK_SSL *ctx);

MESALINK_API int mesalink_SSL_CTX_set_verify(MESALINK_CTX *, int,
                                             int (*cb)(int, MESALINK_CTX *));
MESALINK_API long mesalink_SSL_CTX_set_session_cache_mode(MESALINK_CTX *,
                                                          long);
MESALINK_API long mesalink_SSL_CTX_get_session_cache_mode(MESALINK_CTX *);
MESALINK_API long mesalink_SSL_CTX_sess_set_cache_size(MESALINK_CTX *, long);
MESALINK_API long mesalink_SSL_CTX_sess_get_cache_size(MESALINK_CTX *);
MESALINK_API void mesalink_SSL_CTX_free(MESALINK_CTX *);

MESALINK_API MESALINK_SSL *mesalink_SSL_new(MESALINK_CTX *);
MESALINK_API MESALINK_CIPHER *mesalink_SSL_get_current_cipher(MESALINK_SSL *);
MESALINK_API const char *mesalink_SSL_CIPHER_get_name(const MESALINK_CIPHER *);
MESALINK_API int mesalink_SSL_CIPHER_get_bits(const MESALINK_CIPHER *, int *);
MESALINK_API const char *mesalink_SSL_CIPHER_get_version(
  const MESALINK_CIPHER *);
MESALINK_API const char *mesalink_SSL_get_cipher_name(MESALINK_SSL *);
MESALINK_API int mesalink_SSL_get_cipher_bits(MESALINK_SSL *, int *);
MESALINK_API const char *mesalink_SSL_get_cipher_version(const MESALINK_SSL *);
MESALINK_API MESALINK_X509 *mesalink_SSL_get_peer_certificate(
  const MESALINK_SSL *);
MESALINK_API int mesalink_SSL_set_tlsext_host_name(MESALINK_SSL *,
                                                   const char *);
MESALINK_API int mesalink_SSL_set_fd(MESALINK_SSL *, int);
MESALINK_API int mesalink_SSL_get_fd(const MESALINK_SSL *);
MESALINK_API int mesalink_SSL_do_handshake(MESALINK_SSL *);

#ifdef HAVE_CLIENT
MESALINK_API int mesalink_SSL_connect(MESALINK_SSL *);
MESALINK_API int mesalink_SSL_connect0(MESALINK_SSL *);
#endif

#ifdef HAVE_SERVER
MESALINK_API int mesalink_SSL_accept(MESALINK_SSL *);
#endif

MESALINK_API int mesalink_SSL_write(MESALINK_SSL *, const void *, int);
MESALINK_API int mesalink_SSL_read(MESALINK_SSL *, void *, int);
MESALINK_API int mesalink_SSL_flush(MESALINK_SSL *);
#ifdef HAVE_TLS13
MESALINK_API int mesalink_SSL_write_early_data(MESALINK_SSL *, const void *,
                                               int, size_t *);
MESALINK_API int mesalink_SSL_get_early_data_status(const MESALINK_SSL *);
#endif
MESALINK_API int mesalink_SSL_shutdown(MESALINK_SSL *);
MESALINK_API MESALINK_CTX *mesalink_SSL_get_SSL_CTX(const MESALINK_SSL *);
MESALINK_API MESALINK_CTX *mesalink_SSL_set_SSL_CTX(MESALINK_SSL *,
                                                    MESALINK_CTX *);
MESALINK_API const char *mesalink_SSL_get_version(const MESALINK_SSL *);
MESALINK_API void mesalink_SSL_free(MESALINK_SSL *);

MESALINK_API int mesalink_SSL_get_error(const MESALINK_SSL *, int);

#ifdef __cplusplus
} /* extern C */
#endif

#endif /* MESALINK_SSL_H */
