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

#ifndef MESALINK_OPENSSL_PEM_H
#define MESALINK_OPENSSL_PEM_H

#include <mesalink/evp.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PEM_read_bio_PrivateKey mesalink_PEM_read_bio_PrivateKey
#define PEM_read_PrivateKey mesalink_PEM_read_PrivateKey
#define PEM_read_bio_X509 mesalink_PEM_read_bio_X509
#define PEM_read_X509 mesalink_PEM_read_X509

#ifdef __cplusplus
} /* extern C */
#endif

#endif /* MESALINK_OPENSSL_PEM_H */