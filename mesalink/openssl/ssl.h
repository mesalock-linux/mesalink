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

/* ssl.h defines the compatibility layer for OpenSSL */

#ifndef MESALINK_OPENSSL_SSL_H
#define MESALINK_OPENSSL_SSL_H

#include <mesalink/ssl.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef MESALINK_METHOD SSL_METHOD;
typedef MESALINK_CTX SSL_CTX;
typedef MESALINK_CIPHER CIPHER;
typedef MESALINK_SSL SSL;

#define SSL_ERROR_NONE MESALINK_ERROR_NONE
#define SSL_FAILURE MESALINK_FAILURE
#define SSL_FATAL_ERROR MESALINK_FATAL_ERROR
#define SSL_SUCCESS MESALINK_SUCCESS

#define SSL_FILETYPE_PEM MESALINK_FILETYPE_PEM
#define SSL_FILETYPE_ASN1 MESALINK_FILETYPE_ASN1
#define SSL_FILETYPE_DEFAULT MESALINK_FILETYPE_DEFAULT
#define SSL_FILETYPE_RAW MESALINK_FILETYPE_RAW

#define SSL_SESS_CACHE_OFF MESALINK_SSL_SESS_CACHE_OFF
#define SSL_SESS_CACHE_CLIENT MESALINK_SSL_SESS_CACHE_CLIENT
#define SSL_SESS_CACHE_SERVER MESALINK_SSL_SESS_CACHE_SERVER
#define SSL_SESS_CACHE_BOTH MESALINK_SSL_SESS_CACHE_BOTH

#define SSL_library_init mesalink_library_init
#define OpenSSL_add_ssl_algorithms mesalink_add_ssl_algorithms
#define SSL_load_error_strings mesalink_SSL_load_error_strings

#ifdef HAVE_CLIENT
#define SSLv3_client_method mesalink_SSLv3_client_method
#define SSLv23_client_method mesalink_SSLv3_client_method
#define TLSv1_client_method mesalink_TLSv1_client_method
#define TLSv1_1_client_method mesalink_TLSv1_1_client_method
#define TLSv1_2_client_method mesalink_TLSv1_2_client_method
#ifdef HAVE_TLS13
#define TLSv1_3_client_method mesalink_TLSv1_3_client_method
#endif
#define TLS_client_method mesalink_TLS_client_method
#endif

#ifdef HAVE_SERVER
#define SSLv3_server_method mesalink_SSLv3_server_method
#define SSLv23_server_method mesalink_SSLv3_server_method
#define TLSv1_server_method mesalink_TLSv1_server_method
#define TLSv1_1_server_method mesalink_TLSv1_1_server_method
#define TLSv1_2_server_method mesalink_TLSv1_2_server_method
#ifdef HAVE_TLS13
#define TLSv1_3_server_method mesalink_TLSv1_3_server_method
#endif
#define TLS_server_method mesalink_TLS_server_method
#endif

#define SSL_CTX_new mesalink_SSL_CTX_new
#ifdef HAVE_SERVER
#define SSL_CTX_use_certificate_chain_file                                    \
  mesalink_SSL_CTX_use_certificate_chain_file
#define SSL_CTX_use_PrivateKey_file mesalink_SSL_CTX_use_PrivateKey_file
#define SSL_CTX_check_private_key mesalink_SSL_CTX_check_private_key
#endif
#define SSL_CTX_set_verify mesalink_SSL_CTX_set_verify
#define SSL_CTX_set_session_cache_mode mesalink_SSL_CTX_set_session_cache_mode
#define SSL_CTX_get_session_cache_mode mesalink_SSL_CTX_get_session_cache_mode
#define SSL_CTX_free mesalink_SSL_CTX_free

#define SSL_new mesalink_SSL_new
#define SSL_get_current_cipher mesalink_SSL_get_current_cipher
#define SSL_CIPHER_get_name mesalink_SSL_CIPHER_get_name
#define SSL_CIPHER_get_bits mesalink_SSL_CIPHER_get_bits
#define SSL_CIPHER_get_version mesalink_SSL_CIPHER_get_version
#define SSL_get_cipher_name mesalink_SSL_get_cipher_name
#define SSL_get_cipher_bits mesalink_SSL_get_cipher_bits
#define SSL_get_cipher_version mesalink_SSL_get_cipher_version
#define SSL_get_peer_certificate mesalink_SSL_get_peer_certificate
#define SSL_set_tlsext_host_name mesalink_SSL_set_tlsext_host_name
#define SSL_get_SSL_CTX mesalink_SSL_get_SSL_CTX
#define SSL_set_SSL_CTX mesalink_SSL_set_SSL_CTX
#define SSL_set_fd mesalink_SSL_set_fd
#define SSL_get_fd mesalink_SSL_get_fd
#define SSL_do_handshake mesalink_SSL_do_handshake

#ifdef HAVE_CLIENT
#define SSL_connect mesalink_SSL_connect
#define SSL_connect0 mesalink_SSL_connect0
#endif
#ifdef HAVE_SERVER
#define SSL_accept mesalink_SSL_accept
#endif

#define SSL_write mesalink_SSL_write
#define SSL_read mesalink_SSL_read
#define SSL_shutdown mesalink_SSL_shutdown
#define SSL_get_version mesalink_SSL_get_version
#define SSL_free mesalink_SSL_free

#define SSL_get_error mesalink_SSL_get_error

#ifdef __cplusplus
} /* extern C */
#endif

#endif /* MESALINK_OPENSSL_SSL_H */
