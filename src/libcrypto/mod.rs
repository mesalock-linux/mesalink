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

/// Implementations of OpenSSL BIO APIs.
/// Please also refer to the header file at mesalink/openssl/bio.h
pub mod bio;

/// Implementations of OpenSSL EVP APIs.
/// Please also refer to the header file at mesalink/openssl/evp.h
pub mod evp;

/// Implementations of OpenSSL PEM APIs.
/// Please also refer to the header file at mesalink/openssl/evp.h
pub mod pem;

use libc::c_int;
pub(self) const CRYPTO_FAILURE: c_int = 0;
pub(self) const CRYPTO_SUCCESS: c_int = 1;
