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

/* ssl.h defines the compatibility layer for OpenSSL */

#ifndef MESALINK_OPENSSL_H
#define MESALINK_OPENSSL_H

#include <mesalink/ssl.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef MESALINK_METHOD SSL_METHOD;
typedef MESALINK_CTX SSL_CTX;
typedef MESALINK_CIPHER CIPHER;
typedef MESALINK_SSL SSL;

#define SSL_library_init mesalink_library_init
#define OpenSSL_add_ssl_algorithms mesalink_add_ssl_algorithms
#define SSL_load_error_strings mesalink_SSL_load_error_strings

#define SSLv3_client_method mesalink_SSLv3_client_method
#define SSLv23_client_method mesalink_SSLv3_client_method
#define TLSv1_client_method mesalink_TLSv1_client_method
#define TLSv1_1_client_method mesalink_TLSv1_1_client_method
#define TLSv1_2_client_method mesalink_TLSv1_2_client_method
#define TLSv1_3_client_method mesalink_TLSv1_3_client_method

#define SSLv3_server_method mesalink_SSLv3_server_method
#define SSLv23_server_method mesalink_SSLv3_server_method
#define TLSv1_server_method mesalink_TLSv1_server_method
#define TLSv1_1_server_method mesalink_TLSv1_1_server_method
#define TLSv1_2_server_method mesalink_TLSv1_2_server_method
#define TLSv1_3_server_method mesalink_TLSv1_3_server_method

#define SSL_CTX_new mesalink_CTX_new
#define SSL_CTX_use_certificate_chain_file mesalink_SSL_CTX_use_certificate_chain_file
#define SSL_CTX_use_PrivateKey_file mesalink_SSL_CTX_use_PrivateKey_file
#define SSL_CTX_check_private_key mesalink_SSL_CTX_check_private_key
#define SSL_CTX_free mesalink_CTX_free

#define SSL_new mesalink_SSL_new
#define SSL_set_tlsext_host_name mesalink_SSL_set_tlsext_host_name
#define SSL_get_servername mesalink_SSL_get_servername
#define SSL_get_SSL_CTX mesalink_SSL_get_SSL_CTX
#define SSL_set_SSL_CTX mesalink_SSL_set_SSL_CTX
#define SSL_set_fd mesalink_SSL_set_fd
#define SSL_get_fd mesalink_SSL_get_fd
#define SSL_connect mesalink_SSL_connect
#define SSL_accept mesalink_SSL_accept
#define SSL_write mesalink_SSL_write
#define SSL_read mesalink_SSL_read
#define SSL_shutdown mesalink_SSL_shutdown
#define SSL_free mesalink_SSL_free

enum
{ /* ssl constants */
  ERROR_NONE = 0,
  FAILURE = 0,
  SUCCESS = 1,
  SHUTDOWN_NOT_DONE = 2,

  SSL_FILETYPE_PEM = 1,
  SSL_FILETYPE_ASN1 = 2,
  SSL_FILETYPE_DEFAULT = 2,
  SSL_FILETYPE_RAW = 3,
};

#ifdef __cplusplus
} /* extern C */
#endif
#endif /* MESALINK_OPENSSL_H */