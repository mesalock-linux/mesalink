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

#ifndef MESALINK_SSL_H
#define MESALINK_SSL_H

#ifdef __cplusplus
extern "C" {
#endif

//#include <mesalink/settings.h>
//#include <mesalink/version.h>
#include <mesalink/visibility.h>

typedef struct MESALINK_METHOD MESALINK_METHOD;
typedef struct MEASLINK_CTX MESALINK_CTX;
typedef struct MESALINK_CIPHER MESALINK_CIPHER;
typedef struct MESALINK_SSL MESALINK_SSL;

MESALINK_API int mesalink_library_init();
MESALINK_API int mesalink_add_ssl_algorithms();
MESALINK_API void mesalink_SSL_load_error_strings();
MESALINK_API void mesalink_ERR_load_error_strings();
MESALINK_API void mesalink_ERR_free_error_strings();

MESALINK_API const char *mesalink_ERR_reason_error_string(unsigned long);

typedef MESALINK_METHOD *(*mesalink_method_func)();
MESALINK_API MESALINK_METHOD *mesalink_SSLv3_client_method();
MESALINK_API MESALINK_METHOD *mesalink_SSLv23_client_method();
MESALINK_API MESALINK_METHOD *mesalink_TLSv1_client_method();
MESALINK_API MESALINK_METHOD *mesalink_TLSv1_1_client_method();
MESALINK_API MESALINK_METHOD *mesalink_TLSv1_2_client_method();
MESALINK_API MESALINK_METHOD *mesalink_TLSv1_3_client_method();

MESALINK_API MESALINK_METHOD *mesalink_SSLv3_server_method();
MESALINK_API MESALINK_METHOD *mesalink_SSLv23_server_method();
MESALINK_API MESALINK_METHOD *mesalink_TLSv1_server_method();
MESALINK_API MESALINK_METHOD *mesalink_TLSv1_1_server_method();
MESALINK_API MESALINK_METHOD *mesalink_TLSv1_2_server_method();
MESALINK_API MESALINK_METHOD *mesalink_TLSv1_3_server_method();

MESALINK_API MESALINK_CTX *mesalink_CTX_new(const MESALINK_METHOD *);
MESALINK_API int mesalink_SSL_CTX_use_certificate_chain_file(MESALINK_CTX *, const char *, int);
MESALINK_API int mesalink_SSL_CTX_use_PrivateKey_file(MESALINK_CTX *, const char *, int);
MESALINK_API int mesalink_SSL_CTX_check_private_key(const MESALINK_CTX *);
MESALINK_API void mesalink_CTX_free(MESALINK_CTX *);

MESALINK_API MESALINK_SSL *mesalink_SSL_new(MESALINK_CTX *);
MESALINK_API MESALINK_CIPHER *mesalink_SSL_get_current_cipher(MESALINK_SSL *);
MESALINK_API const char *mesalink_SSL_CIPHER_get_name(const MESALINK_CIPHER *);
MESALINK_API int mesalink_SSL_CIPHER_get_bits(const MESALINK_CIPHER *);
MESALINK_API const char *mesalink_SSL_CIPHER_get_version(const MESALINK_CIPHER *);
MESALINK_API const char *mesalink_SSL_get_cipher_name(MESALINK_SSL *);
MESALINK_API int mesalink_SSL_get_cipher_bits(MESALINK_SSL *);
MESALINK_API const char *mesalink_SSL_get_cipher_version(const MESALINK_SSL *);
MESALINK_API int mesalink_SSL_set_tlsext_host_name(MESALINK_SSL *, const char *);
MESALINK_API const char *mesalink_SSL_get_servername(const MESALINK_SSL *, const int);
MESALINK_API int mesalink_SSL_set_fd(MESALINK_SSL *, int);
MESALINK_API int mesalink_SSL_get_fd(const MESALINK_SSL *);
MESALINK_API int mesalink_SSL_connect(MESALINK_SSL *);
MESALINK_API int mesalink_SSL_accept(MESALINK_SSL *);
MESALINK_API int mesalink_SSL_write(MESALINK_SSL *, const void *, int);
MESALINK_API int mesalink_SSL_read(MESALINK_SSL *, void *, int);
MESALINK_API int mesalink_SSL_shutdown(MESALINK_SSL *);
MESALINK_API MESALINK_CTX *mesalink_SSL_get_SSL_CTX(const MESALINK_SSL *);
MESALINK_API MESALINK_CTX *mesalink_SSL_set_SSL_CTX(MESALINK_SSL *, MESALINK_CTX *);
MESALINK_API void mesalink_SSL_free(MESALINK_SSL *);

#ifdef __cplusplus
} /* extern C */
#endif

#endif /* MESALINK_SSL_H */