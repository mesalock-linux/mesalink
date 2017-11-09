/* ssl.h
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

#ifndef MESALINK_H
#define MESALINK_H

#ifdef __cplusplus
    extern "C" {
#endif 

//#include <mesalink/settings.h>
//#include <mesalink/version.h>
#include <mesalink/visibility.h>

typedef struct MESALINK_SSL         MESALINK_SSL;
typedef struct MESALINK_METHOD      MESALINK_METHOD;
typedef struct MEASLINK_CTX         MESALINK_CTX;

enum {
    SSL_FAILURE = 0,
    SSL_SUCCESS = 1
};

typedef MESALINK_METHOD* (*mesalink_method_func)();
MESALINK_API MESALINK_METHOD *mesalink_SSLv3_client_method();
MESALINK_API MESALINK_METHOD *mesalink_TLSv1_client_method();
MESALINK_API MESALINK_METHOD *mesalink_TLSv1_1_client_method();
MESALINK_API MESALINK_METHOD *mesalink_TLSv1_2_client_method();
MESALINK_API MESALINK_METHOD *mesalink_TLSv1_3_client_method();

MESALINK_API MESALINK_CTX*  mesalink_CTX_new(MESALINK_METHOD*);
MESALINK_API MESALINK_SSL*  mesalink_SSL_new(MESALINK_CTX*);
MESALINK_API int            mesalink_SSL_set_tlsext_host_name(MESALINK_SSL*, const char*);
MESALINK_API int            mesalink_SSL_set_fd(MESALINK_SSL*, int);
MESALINK_API int            mesalink_SSL_connect(MESALINK_SSL*);
MESALINK_API int            mesalink_SSL_write(MESALINK_SSL*, const void*, int);
MESALINK_API int            mesalink_SSL_read(MESALINK_SSL*, void*, int);

MESALINK_API void           mesalink_CTX_free(MESALINK_CTX*);
MESALINK_API void           mesalink_SSL_free(MESALINK_SSL*);

#ifdef __cplusplus
    } /* extern C */
#endif

#endif /* MESALINK_H */