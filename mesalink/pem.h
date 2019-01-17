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

#ifndef MESALINK_PEM_H
#define MESALINK_PEM_H

#ifdef __cplusplus
extern "C" {
#endif

#include <mesalink/options.h>
#include <mesalink/version.h>
#include <mesalink/visibility.h>
#include <mesalink/bio.h>
#include <mesalink/evp.h>
#include <mesalink/x509.h>
#include <stdio.h>

typedef pem_password_cb pem_password_cb;

MESALINK_API MESALINK_EVP_PKEY *mesalink_PEM_read_bio_PrivateKey(
  MESALINK_BIO *, MESALINK_EVP_PKEY **, pem_password_cb *cb, void *u);
MESALINK_API MESALINK_EVP_PKEY *mesalink_PEM_read_PrivateKey(
  FILE *fp, MESALINK_EVP_PKEY **x, pem_password_cb *cb, void *u);
MESALINK_API MESALINK_X509 *mesalink_PEM_read_bio_X509(MESALINK_BIO *,
                                                       MESALINK_X509 **,
                                                       pem_password_cb *cb,
                                                       void *u);
MESALINK_API MESALINK_X509 *mesalink_PEM_read_X509(FILE *fp, MESALINK_X509 **x,
                                                   pem_password_cb *cb,
                                                   void *u);
#ifdef __cplusplus
} /* extern C */
#endif

#endif /* MESALINK_PEM_H */