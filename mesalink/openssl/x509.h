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

/* x509.h defines the compatibility layer for OpenSSL */

#ifndef MESALINK_OPENSSL_X509_H
#define MESALINK_OPENSSL_X509_H

#include <mesalink/x509.h>

#ifdef __cplusplus
extern "C" {
#endif

#define X509 MESALINK_X509
#define X509_NAME MESALINK_X509_NAME

#define STACK_OF(NAME) MESALINK_STACK_OF(MESALINK_##NAME)

#define X509_get_alt_subject_names mesalink_X509_get_alt_subject_names
#define X509_NAME_oneline mesalink_X509_NAME_oneline

#define sk_X509_NAME_num mesalink_sk_X509_NAME_num
#define sk_X509_NAME_value mesalink_sk_X509_NAME_value
#define sk_X509_NAME_free mesalink_sk_X509_NAME_free

#ifdef __cplusplus
} /* extern C */
#endif

#endif /* MESALINK_OPENSSL_X509_H */
