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
use rustls;
use webpki;

use ssl::{MesalinkOpaquePointerType, MAGIC, MAGIC_SIZE};

/// An OpenSSL X509 object
#[allow(non_camel_case_types)]
pub struct MESALINK_X509 {
    magic: [u8; MAGIC_SIZE],
    cert: rustls::Certificate,
}

impl MesalinkOpaquePointerType for MESALINK_X509 {
    fn check_magic(&self) -> bool {
        self.magic == *MAGIC
    }
}

impl MESALINK_X509 {
    fn new(cert: rustls::Certificate) -> MESALINK_X509 {
        MESALINK_X509 {
            magic:  *MAGIC,
            cert: cert,
        }
    }
}
