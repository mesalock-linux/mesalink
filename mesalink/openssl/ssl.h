/* openssl/ssh.h
 *                            _ _       _    
 *                           | (_)     | |   
 *  _ __ ___   ___  ___  __ _| |_ _ __ | | __
 * | '_ ` _ \ / _ \/ __|/ _` | | | '_ \| |/ /
 * | | | | | |  __/\__ \ (_| | | | | | |   < 
 * |_| |_| |_|\___||___/\__,_|_|_|_| |_|_|\_\
 *
 * Copyright (C) 2017 Baidu USA.
 *
 * This file is part of Mesalink.
 */

 /* ssl.h defines the compatibility layer for OpenSSL */

#ifndef MESALINK_OPENSSL_H
#define MESALINK_OPENSSL_H

#include <mesalink/ssl.h>

#ifdef __cplusplus
    extern "C" {
#endif 

typedef MESALINK_SSL    SSL;
typedef MESALINK_METHOD SSL_METHOD;
typedef MESALINK_CTX    SSL_CTX;

//#define SSLv3_client_method     mesalink_SSLv3_client_method
//#define TLSv1_client_method     mesalink_TLSv1_client_method
//#define TLSv1_1_client_method   mesalink_TLSv1_1_client_method
#define TLSv1_2_client_method   mesalink_TLSv1_2_client_method
//#define TLSv1_3_client_method   mesalink_TLSv1_3_client_method

#define SSL_CTX_new             mesalink_CTX_new
#define SSL_new                 mesalink_SSL_new
#define SSL_set_fd              mesalink_SSL_set_fd
#define SSL_connect             mesalink_SSL_connect
#define SSL_write               mesalink_SSL_write
#define SSL_read                mesalink_SSL_read

#define SSL_CTX_free            mesalink_CTX_free
#define SSL_free                mesalink_SSL_free

#ifdef __cplusplus
    } /* extern C */
#endif
#endif /* MESALINK_OPENSSL_H */