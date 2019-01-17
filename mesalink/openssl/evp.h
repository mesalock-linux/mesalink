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

#ifndef MESALINK_OPENSSL_EVP_H
#define MESALINK_OPENSSL_EVP_H

#include <mesalink/evp.h>

#ifdef __cplusplus
extern "C" {
#endif

#define EVP_PKEY MESALINK_EVP_PKEY

#define EVP_PKEY_free mesalink_EVP_PKEY_free

#ifdef __cplusplus
} /* extern C */
#endif

#endif /* MESALINK_OPENSSL_EVP_H */
