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

use ring::rand;
use ring::rand::SecureRandom;

pub const MAGIC_SIZE: usize = 4;
lazy_static! {
    pub static ref MAGIC: [u8; MAGIC_SIZE] = {
        let mut number = [0u8; MAGIC_SIZE];
        if rand::SystemRandom::new().fill(&mut number).is_ok() {
            let number = number;
            number
        } else {
            panic!("Getrandom error");
        }
    };
}

pub trait MesalinkOpaquePointerType {
    fn check_magic(&self) -> bool;
}

/// Implementations of OpenSSL ERR APIs.
/// Please also refer to the header file at mesalink/openssl/err.h
#[macro_use] pub mod err;

/// Implementations of OpenSSL SSL APIs.
/// Please also refer to the header file at mesalink/openssl/ssl.h
pub mod ssl;

/// Implementations of OpenSSL X509 APIs.
/// Please also refer to the header file at mesalink/openssl/x509.h
pub mod x509;