/*
 *   __  __                 _     _       _
 *  |  \/  | ___  ___  __ _| |   (_)_ __ | | __
 *  | |\/| |/ _ \/ __|/ _` | |   | | '_ \| |/ /
 *  | |  | |  __/\__ \ (_| | |___| | | | |   <
 *  |_|  |_|\___||___/\__,_|_____|_|_| |_|_|\_\
 *
 * Copyright (c) 2017-2019, The MesaLink Authors.
 * All rights reserved.
 *
 * This work is licensed under the terms of the BSD 3-Clause License.
 * For a copy, see the LICENSE file.
 *
 */

#ifndef MESALINK_BIO_H
#define MESALINK_BIO_H

#ifdef __cplusplus
extern "C" {
#endif

#include <mesalink/options.h>
#include <mesalink/version.h>
#include <mesalink/visibility.h>
#include <stdio.h>

typedef struct MESALINK_BIO_METHOD MESALINK_BIO_METHOD;
typedef struct MESALINK_BIO MESALINK_BIO;
typedef struct MESALINK_BUF_MEM MESALINK_BUF_MEM;

MESALINK_API MESALINK_BIO *mesalink_BIO_new(const MESALINK_BIO_METHOD *);
MESALINK_API void mesalink_BIO_free(MESALINK_BIO *);

MESALINK_API int mesalink_BIO_read(MESALINK_BIO *, void *, int);
MESALINK_API int mesalink_BIO_gets(MESALINK_BIO *, void *, int);
MESALINK_API int mesalink_BIO_wrire(MESALINK_BIO *, char *, int);
MESALINK_API int mesalink_BIO_puts(MESALINK_BIO *, const char *);
MESALINK_API int mesalink_BIO_ctrl(MESALINK_BIO *, int, long, void *);

MESALINK_API MESALINK_BIO_METHOD *mesalink_BIO_s_file(void);
MESALINK_API MESALINK_BIO *mesalink_BIO_new_file(const char *, const char *);
MESALINK_API MESALINK_BIO *mesalink_BIO_new_fp(FILE *, int);
MESALINK_API void mesalink_BIO_set_fp(MESALINK_BIO *, FILE *, int);
MESALINK_API void mesalink_BIO_get_fp(MESALINK_BIO *, FILE **);
MESALINK_API int mesalink_BIO_read_filename(MESALINK_BIO *, char *);
MESALINK_API int mesalink_BIO_write_filename(MESALINK_BIO *, char *);

MESALINK_API MESALINK_BIO_METHOD *mesalink_BIO_s_mem(void);
MESALINK_API MESALINK_BIO *mesalink_BIO_new_mem_buf(const void *, int);
MESALINK_API long mesalink_BIO_get_mem_data(MESALINK_BIO *, char **);
MESALINK_API void mesalink_BIO_set_mem_buf(MESALINK_BIO *, MESALINK_BUF_MEM *,
                                           int);
MESALINK_API void mesalink_BIO_get_mem_ptr(MESALINK_BIO *,
                                           MESALINK_BUF_MEM **);

MESALINK_API MESALINK_BUF_MEM *mesalink_BUF_MEM_new(void);
MESALINK_API void mesalink_BUF_MEM_free(MESALINK_BUF_MEM *);
MESALINK_API int mesalink_BUF_MEM_grow(MESALINK_BUF_MEM *, int);
MESALINK_API size_t mesalink_BUF_MEM_grow_clean(MESALINK_BUF_MEM *, size_t);

MESALINK_API MESALINK_BIO_METHOD *mesalink_BIO_s_socket(void);
MESALINK_API MESALINK_BIO *mesalink_BIO_new_socket(int, int);
MESALINK_API long mesalink_BIO_set_fd(MESALINK_BIO *, int, long);
MESALINK_API long mesalink_BIO_get_fd(MESALINK_BIO *, int);

#ifdef __cplusplus
} /* extern C */
#endif

#endif /* MESALINK_BIO_H */
