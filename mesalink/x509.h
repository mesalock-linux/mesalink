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

#ifndef MESALINK_X509_H
#define MESALINK_X509_H

#ifdef __cplusplus
extern "C" {
#endif

#include <mesalink/options.h>
#include <mesalink/version.h>
#include <mesalink/visibility.h>

typedef struct MESALINK_X509 MESALINK_X509;
typedef struct MESALINK_X509_NAME MESALINK_X509_NAME;

#define MESALINK_STACK_OF(NAME) MESALINK_STACK_##NAME

typedef struct MESALINK_STACK_OF(MESALINK_X509)
  MESALINK_STACK_OF(MESALINK_X509);

typedef struct MESALINK_STACK_OF(MESALINK_X509_NAME)
  MESALINK_STACK_OF(MESALINK_X509_NAME);

MESALINK_API MESALINK_STACK_OF(MESALINK_X509_NAME) *
  mesalink_sk_X509_NAME_new_null(void);
MESALINK_API void mesalink_X509_free(const MESALINK_X509 *);
MESALINK_API void mesalink_X509_NAME_free(const MESALINK_X509_NAME *);

MESALINK_API MESALINK_X509_NAME *
  mesalink_X509_get_subject_name(const MESALINK_X509 *);
MESALINK_API MESALINK_STACK_OF(MESALINK_X509_NAME) *
  mesalink_X509_get_alt_subject_names(const MESALINK_X509 *);
MESALINK_API char *mesalink_X509_NAME_oneline(const MESALINK_X509_NAME *,
                                              char *buf, int size);

MESALINK_API int mesalink_sk_X509_num(const MESALINK_STACK_MESALINK_X509 *);
MESALINK_API MESALINK_X509_NAME *mesalink_sk_X509_value(
  const MESALINK_STACK_MESALINK_X509 *, int);
MESALINK_API void mesalink_sk_X509_free(const MESALINK_STACK_MESALINK_X509 *);

MESALINK_API int mesalink_sk_X509_NAME_num(
  const MESALINK_STACK_MESALINK_X509_NAME *);
MESALINK_API MESALINK_X509_NAME *mesalink_sk_X509_NAME_value(
  const MESALINK_STACK_MESALINK_X509_NAME *, int);
MESALINK_API void mesalink_sk_X509_NAME_free(
  const MESALINK_STACK_MESALINK_X509_NAME *);

#ifdef __cplusplus
} /* extern C */
#endif

#endif /* MESALINK_X509_H */
