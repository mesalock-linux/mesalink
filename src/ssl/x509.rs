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

use libc::{c_char, c_int};
use rustls;
use ssl::err::{ErrorCode, MesalinkInnerResult};
use ssl::error_san::*;
use ssl::{MesalinkOpaquePointerType, MAGIC, MAGIC_SIZE};
use std::{ptr, slice};
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

impl MesalinkOpaquePointerType for MESALINK_X509_NAME {
    fn check_magic(&self) -> bool {
        self.magic == *MAGIC
    }
}

impl MESALINK_X509_NAME {
    pub fn new(name: String) -> MESALINK_X509_NAME {
        MESALINK_X509_NAME {
            magic: *MAGIC,
            name: name,
        }
    }
}

#[no_mangle]
pub extern "C" fn mesalink_X509_get_subject_name(
    x509_ptr: *mut MESALINK_X509,
) -> *mut MESALINK_X509_NAME {
    check_inner_result!(
        inner_mesalink_x509_get_subject_name(x509_ptr),
        ptr::null_mut()
    )
}

fn inner_mesalink_x509_get_subject_name(
    x509_ptr: *mut MESALINK_X509,
) -> MesalinkInnerResult<*mut MESALINK_X509_NAME> {
    let cert = sanitize_ptr_for_ref(x509_ptr)?;
    let cert_der = untrusted::Input::from(&cert.cert_data.0);
    let x509 =
        webpki::EndEntityCert::from(cert_der).map_err(|_| error!(ErrorCode::TLSErrorWebpkiBadDER))?;
    let subject_name = x509.inner.subject.as_slice_less_safe().to_vec();
    let subject_name =
        String::from_utf8(subject_name).map_err(|_| error!(ErrorCode::TLSErrorWebpkiBadDER))?;
    let x509_name = MESALINK_X509_NAME::new(subject_name);
    Ok(Box::into_raw(Box::new(x509_name)) as *mut MESALINK_X509_NAME)
}

#[no_mangle]
pub extern "C" fn mesalink_X509_get_issuer_name(
    x509_ptr: *mut MESALINK_X509,
) -> *mut MESALINK_X509_NAME {
    check_inner_result!(
        inner_mesalink_x509_get_issuer_name(x509_ptr),
        ptr::null_mut()
    )
}

fn inner_mesalink_x509_get_issuer_name(
    x509_ptr: *mut MESALINK_X509,
) -> MesalinkInnerResult<*mut MESALINK_X509_NAME> {
    let cert = sanitize_ptr_for_ref(x509_ptr)?;
    let cert_der = untrusted::Input::from(&cert.cert_data.0);
    let x509 =
        webpki::EndEntityCert::from(cert_der).map_err(|_| error!(ErrorCode::TLSErrorWebpkiBadDER))?;
    let subject_name = x509.inner.issuer.as_slice_less_safe().to_vec();
    let subject_name =
        String::from_utf8(subject_name).map_err(|_| error!(ErrorCode::TLSErrorWebpkiBadDER))?;
    let x509_name = MESALINK_X509_NAME::new(subject_name);
    Ok(Box::into_raw(Box::new(x509_name)) as *mut MESALINK_X509_NAME)
}

#[no_mangle]
pub extern "C" fn mesalink_X509_NAME_oneline(
    x509_name_ptr: *mut MESALINK_X509_NAME,
    buf_ptr: *mut c_char,
    size: c_int,
) -> *mut c_char {
    check_inner_result!(
        inner_mesalink_x509_name_oneline(x509_name_ptr, buf_ptr, size),
        ptr::null_mut()
    )
}

fn inner_mesalink_x509_name_oneline(
    x509_name_ptr: *mut MESALINK_X509_NAME,
    buf_ptr: *mut c_char,
    buf_len: c_int,
) -> MesalinkInnerResult<*mut c_char> {
    use std::mem;
    let x509_name = sanitize_ptr_for_ref(x509_name_ptr)?;
    let buf_len: usize = buf_len as usize;
    unsafe {
        let name: &[c_char] = mem::transmute::<&[u8], &[c_char]>(x509_name.name.as_bytes());
        let name_len: usize = name.len();
        if buf_ptr.is_null() {
            return Err(error!(ErrorCode::MesalinkErrorNullPointer));
        }
        let buf = slice::from_raw_parts_mut(buf_ptr, buf_len);
        if name.len() > buf_len {
            buf.copy_from_slice(&name[0..buf_len]);
            buf[buf_len - 1] = 0;
        } else {
            buf[0..name_len].copy_from_slice(name);
        }
        Ok(buf_ptr)
    }
}
