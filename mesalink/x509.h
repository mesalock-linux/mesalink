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

MESALINK_API MESALINK_X509_NAME *
mesalink_X509_get_subject_name(const MESALINK_X509 *);
MESALINK_API MESALINK_X509_NAME *
mesalink_X509_get_issuer_name(const MESALINK_X509 *);

#ifdef __cplusplus
} /* extern C */
#endif

#endif /* MESALINK_X509_H */
