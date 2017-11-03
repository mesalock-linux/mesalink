/* ssh.h
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

#ifndef MESALINK_SSL_H
#define MESALINK_SSL_H

#ifdef __cplusplus
    extern "C" {
#endif 

//#include <mesalink/settings.h>
//#include <mesalink/version.h>
#include <mesalink/visibility.h>

typedef struct MESALINK             MESALINK;
typedef struct MESALINK_METHOD      MESALINK_METHOD;
typedef struct MEASLINK_CTX         MESALINK_CTX;

typedef MESALINK_METHOD* (*mesalink_method_func)();
//MESALINK_API MESALINK_METHOD *mesalink_SSLv3_client_method();
//MESALINK_API MESALINK_METHOD *mesalink_TLSv1_client_method();
//MESALINK_API MESALINK_METHOD *mesalink_TLSv1_1_client_method();
MESALINK_API MESALINK_METHOD *mesalink_TLSv1_2_client_method();
//MESALINK_API MESALINK_METHOD *mesalink_TLSv1_3_client_method();

MESALINK_API MESALINK_CTX*  mesalink_CTX_new(MESALINK_METHOD*);
MESALINK_API MESALINK*      mesalink_new(MESALINK_CTX*);
MESALINK_API int            mesalink_set_fd(MESALINK*, int);
MESALINK_API int            mesalink_connect(MESALINK*);
MESALINK_API int            mesalink_write(MESALINK*, const void*, int);
MESALINK_API int            mesalink_read(MESALINK*, void*, int);

MESALINK_API void           mesalink_CTX_free(MESALINK_CTX*);
MESALINK_API void           mesalink_free(MESALINK*);

#ifdef __cplusplus
    } /* extern C */
#endif

#endif /* MESALINK_SSL_H */