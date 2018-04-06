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

//use libc::{c_uchar, c_ulong};
use rustls;
use ssl::err::{ErrorCode, ErrorQueue, MesalinkInnerResult};
use ssl::error_san::*;
use ssl::{MesalinkOpaquePointerType, MAGIC, MAGIC_SIZE};
use std::ptr;
use untrusted;
use webpki;

/// An OpenSSL X509 object
#[allow(non_camel_case_types)]
pub struct MESALINK_X509 {
    magic: [u8; MAGIC_SIZE],
    cert_data: rustls::Certificate,
}

impl MesalinkOpaquePointerType for MESALINK_X509 {
    fn check_magic(&self) -> bool {
        self.magic == *MAGIC
    }
}

impl MESALINK_X509 {
    // TODO: handle TrustAnchor certificates
    pub fn new(cert: rustls::Certificate) -> MESALINK_X509 {
        MESALINK_X509 {
            magic: *MAGIC,
            cert_data: cert,
        }
    }
}

/// An OpenSSL X509_NAME object
#[allow(non_camel_case_types)]
pub struct MESALINK_X509_NAME {
    magic: [u8; MAGIC_SIZE],
    name: String,
}

#[no_mangle]
pub extern "C" fn mesalink_X509_get_subject_name(
    x509_ptr: *mut MESALINK_X509,
) -> *mut MESALINK_X509_NAME {
    check_inner_result!(
        inner_mesalink_X509_get_subject_name(x509_ptr),
        ptr::null_mut()
    )
}

fn inner_mesalink_X509_get_subject_name(
    x509_ptr: *mut MESALINK_X509,
) -> MesalinkInnerResult<*mut MESALINK_X509_NAME> {
    let cert = sanitize_ptr_for_ref(x509_ptr)?;
    let cert_der = untrusted::Input::from(&cert.cert_data.0);
    let x509 = webpki::EndEntityCert::from(cert_der).ok();
    
}
