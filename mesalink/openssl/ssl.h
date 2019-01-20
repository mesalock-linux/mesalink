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

#define SSL_CTX MESALINK_CTX
#define SSL MESALINK_SSL
#define SSL_METHOD MESALINK_METHOD
#define CIPHER MESALINK_CIPHER

#define SSL_VERIFY_NONE MESALINK_SSL_VERIFY_NONE
#define SSL_VERIFY_PEER MESALINK_SSL_VERIFY_PEER
#define SSL_VERIFY_FAIL_IF_NO_PEER_CERT                                       \
  MESALINK_SSL_VERIFY_FAIL_IF_NO_PEER_CERT

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

#define SSL_EARLY_DATA_NOT_SENT MESALINK_SSL_EARLY_DATA_NOT_SENT
#define SSL_EARLY_DATA_REJECTED MESALINK_SSL_EARLY_DATA_REJECTED
#define SSL_EARLY_DATA_ACCEPTED MESALINK_SSL_EARLY_DATA_ACCEPTED

#define SSL_library_init mesalink_library_init
#define OpenSSL_add_ssl_algorithms mesalink_add_ssl_algorithms
#define SSL_load_error_strings mesalink_SSL_load_error_strings

#define TLS_method mesalink_TLS_method
#ifdef HAVE_CLIENT
// Version-flexible methods
#define TLS_client_method mesalink_TLS_client_method
#define SSLv23_client_method mesalink_SSLv23_client_method

// Not supported
#define SSLv3_client_method mesalink_SSLv3_client_method
#define TLSv1_client_method mesalink_TLSv1_client_method
#define TLSv1_1_client_method mesalink_TLSv1_1_client_method

// Version-specific methods
#define TLSv1_2_client_method mesalink_TLSv1_2_client_method
#ifdef HAVE_TLS13
#define TLSv1_3_client_method mesalink_TLSv1_3_client_method
#endif
#endif

#ifdef HAVE_SERVER
// Version-flexible methods
#define TLS_server_method mesalink_TLS_server_method
#define SSLv23_server_method mesalink_SSLv23_server_method

// Not supported
#define SSLv3_server_method mesalink_SSLv3_server_method
#define TLSv1_server_method mesalink_TLSv1_server_method
#define TLSv1_1_server_method mesalink_TLSv1_1_server_method

// Version-specific methods
#define TLSv1_2_server_method mesalink_TLSv1_2_server_method
#ifdef HAVE_TLS13
#define TLSv1_3_server_method mesalink_TLSv1_3_server_method
#endif

#endif

#define SSL_CTX_new mesalink_SSL_CTX_new
#define SSL_CTX_load_verify_locations mesalink_SSL_CTX_load_verify_locations
#define SSL_CTX_use_certificate mesalink_SSL_CTX_use_certificate
#define SSL_CTX_add_extra_chain_cert mesalink_SSL_CTX_add_extra_chain_cert
#define SSL_CTX_use_certificate_chain_file                                    \
  mesalink_SSL_CTX_use_certificate_chain_file
#define SSL_CTX_use_PrivateKey mesalink_SSL_CTX_use_PrivateKey
#define SSL_CTX_use_certificate_ASN1 mesalink_SSL_CTX_use_certificate_ASN1
#define SSL_use_certificate_ASN1 mesalink_SSL_use_certificate_ASN1
#define SSL_CTX_use_PrivateKey_file mesalink_SSL_CTX_use_PrivateKey_file
#define SSL_CTX_use_PrivateKey_ASN1 mesalink_SSL_CTX_use_PrivateKey_ASN1
#define SSL_use_PrivateKey_ASN1 mesalink_SSL_use_PrivateKey_ASN1
#define SSL_CTX_check_private_key mesalink_SSL_CTX_check_private_key
#define SSL_check_private_key mesalink_SSL_check_private_key
#define SSL_CTX_set_verify mesalink_SSL_CTX_set_verify
#define SSL_CTX_set_session_cache_mode mesalink_SSL_CTX_set_session_cache_mode
#define SSL_CTX_get_session_cache_mode mesalink_SSL_CTX_get_session_cache_mode
#define SSL_CTX_sess_set_cache_size mesalink_SSL_CTX_sess_set_cache_size
#define SSL_CTX_sess_get_cache_size mesalink_SSL_CTX_sess_get_cache_size
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
#ifdef HAVE_TLS13
#define SSL_write_early_data mesalink_SSL_write_early_data
#define SSL_get_early_data_status mesalink_SSL_get_early_data_status
#endif
#define SSL_flush mesalink_SSL_flush
#define SSL_shutdown mesalink_SSL_shutdown
#define SSL_get_version mesalink_SSL_get_version
#define SSL_free mesalink_SSL_free

#define SSL_get_error mesalink_SSL_get_error

#ifdef __cplusplus
} /* extern C */
#endif

#endif /* MESALINK_OPENSSL_SSL_H */
