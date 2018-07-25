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
use ring::der;
use rustls;
use ssl::err::{ErrorCode, MesalinkInnerResult};
use ssl::error_san::*;
use ssl::safestack::MESALINK_STACK_MESALINK_X509_NAME;
use ssl::{MesalinkOpaquePointerType, MAGIC, MAGIC_SIZE};
use ssl::{SSL_FAILURE, SSL_SUCCESS};
use std::{ptr, slice, str};
use untrusted;
use webpki;

/// An OpenSSL X509 object
#[allow(non_camel_case_types)]
#[derive(Clone)]
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

#[no_mangle]
pub extern "C" fn mesalink_X509_free(x509_ptr: *mut MESALINK_X509) {
    let _ = check_inner_result!(inner_mesalink_x509_free(x509_ptr), SSL_FAILURE);
}

fn inner_mesalink_x509_free(x509_ptr: *mut MESALINK_X509) -> MesalinkInnerResult<c_int> {
    let _ = sanitize_ptr_for_mut_ref(x509_ptr)?;
    let _ = unsafe { Box::from_raw(x509_ptr) };
    Ok(SSL_SUCCESS)
}

/// An OpenSSL X509_NAME object
#[allow(non_camel_case_types)]
#[derive(Clone)]
pub struct MESALINK_X509_NAME {
    magic: [u8; MAGIC_SIZE],
    name: String,
}

impl<'a> MesalinkOpaquePointerType for MESALINK_X509_NAME {
    fn check_magic(&self) -> bool {
        self.magic == *MAGIC
    }
}

impl<'a> MESALINK_X509_NAME {
    pub fn new(name: String) -> MESALINK_X509_NAME {
        MESALINK_X509_NAME {
            magic: *MAGIC,
            name: name,
        }
    }
}

#[no_mangle]
pub extern "C" fn mesalink_X509_NAME_free(x509_name_ptr: *mut MESALINK_X509_NAME) {
    let _ = check_inner_result!(inner_mesalink_x509_name_free(x509_name_ptr), SSL_FAILURE);
}

fn inner_mesalink_x509_name_free(
    x509_name_ptr: *mut MESALINK_X509_NAME,
) -> MesalinkInnerResult<c_int> {
    let _ = sanitize_ptr_for_mut_ref(x509_name_ptr)?;
    let _ = unsafe { Box::from_raw(x509_name_ptr) };
    Ok(SSL_SUCCESS)
}

#[no_mangle]
pub extern "C" fn mesalink_X509_get_alt_subject_names(
    x509_ptr: *mut MESALINK_X509,
) -> *mut MESALINK_STACK_MESALINK_X509_NAME {
    check_inner_result!(
        inner_mesalink_x509_get_alt_subject_names(x509_ptr),
        ptr::null_mut()
    )
}

fn inner_mesalink_x509_get_alt_subject_names(
    x509_ptr: *mut MESALINK_X509,
) -> MesalinkInnerResult<*mut MESALINK_STACK_MESALINK_X509_NAME> {
    let cert = sanitize_ptr_for_ref(x509_ptr)?;
    let cert_der = untrusted::Input::from(&cert.cert_data.0);
    let x509 =
        webpki::EndEntityCert::from(cert_der).map_err(|_| error!(ErrorCode::TLSErrorWebpkiBadDER))?;
    let subject_alt_name = x509
        .inner
        .subject_alt_name
        .ok_or(error!(ErrorCode::TLSErrorWebpkiExtensionValueInvalid))?;
    let mut reader = untrusted::Reader::new(subject_alt_name);
    let mut stack = MESALINK_STACK_MESALINK_X509_NAME::new(Vec::new());
    while !reader.at_end() {
        let (tag, value) = der::read_tag_and_get_value(&mut reader)
            .map_err(|_| error!(ErrorCode::TLSErrorWebpkiBadDER))?;
        if tag == 0x82 {
            let dns_name_str = str::from_utf8(value.as_slice_less_safe()).unwrap();
            let x509_name = MESALINK_X509_NAME::new(String::from(dns_name_str));
            stack.stack.push(x509_name);
        }
    }
    Ok(Box::into_raw(Box::new(stack)) as *mut MESALINK_STACK_MESALINK_X509_NAME)
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

    let mut subject_name = String::new();

    let _ = x509
        .inner
        .subject
        .read_all(error!(ErrorCode::TLSErrorWebpkiBadDER), |subject| {
            while !subject.at_end() {
                let (maybe_asn_set_tag, sequence) = der::read_tag_and_get_value(subject)
                    .map_err(|_| error!(ErrorCode::TLSErrorWebpkiBadDER))?;
                if (maybe_asn_set_tag as usize) != 0x31 {
                    // Subject should be an ASN.1 SET
                    return Err(error!(ErrorCode::TLSErrorWebpkiBadDER));
                }
                let _ = sequence.read_all(error!(ErrorCode::TLSErrorWebpkiBadDER), |seq| {
                    let oid_and_data = der::expect_tag_and_get_value(seq, der::Tag::Sequence)
                        .map_err(|_| error!(ErrorCode::TLSErrorWebpkiBadDER))?;
                    oid_and_data.read_all(error!(ErrorCode::TLSErrorWebpkiBadDER), |oid_and_data| {
                        let oid = der::expect_tag_and_get_value(oid_and_data, der::Tag::OID)
                            .map_err(|_| error!(ErrorCode::TLSErrorWebpkiBadDER))?;
                        let (_, value) = der::read_tag_and_get_value(oid_and_data)
                            .map_err(|_| error!(ErrorCode::TLSErrorWebpkiBadDER))?;

                        let keyword = match oid.as_slice_less_safe().last().unwrap() {
                            // RFC 1779, X.500 attrinutes, oid 2.5.4
                            3 => "CN",  // CommonName
                            7 => "L",   // LocalityName
                            8 => "ST",  // StateOrProvinceName
                            10 => "O",  // OrganizationName
                            11 => "OU", // OrganizationalUnitName
                            6 => "C",   // CountryName
                            _ => "",
                        };

                        if keyword.len() > 0 {
                            if let Ok(s) = str::from_utf8(value.as_slice_less_safe()) {
                                subject_name.push_str("/");
                                subject_name.push_str(keyword);
                                subject_name.push_str("=");
                                subject_name.push_str(s);
                            }
                        }
                        Ok(())
                    })
                });
            }
            Ok(())
        })
        .map_err(|_| error!(ErrorCode::TLSErrorWebpkiBadDER));

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
        if name_len + 1 > buf_len {
            buf.copy_from_slice(&name[0..buf_len]);
            buf[buf_len - 1] = 0;
        } else {
            buf[0..name_len].copy_from_slice(name);
            buf[name_len] = 0;
        }
        Ok(buf_ptr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::internal::pemfile;
    use ssl::safestack::*;
    use std::fs::File;
    use std::io::BufReader;
    use std::str;

    #[test]
    fn x509_get_subject_alt_names() {
        let mut certs_io = BufReader::new(File::open("tests/test.certs").unwrap());
        let certs = pemfile::certs(&mut certs_io).unwrap();
        assert_eq!(true, certs.len() > 0);
        let x509 = MESALINK_X509::new(certs[0].clone());
        let x509_ptr = Box::into_raw(Box::new(x509)) as *mut MESALINK_X509;
        let name_stack_ptr = mesalink_X509_get_alt_subject_names(x509_ptr);

        let name_count = mesalink_sk_X509_NAME_num(name_stack_ptr) as usize;
        assert_eq!(true, name_count > 0);
        for index in 0..name_count {
            let mut name_ptr = mesalink_sk_X509_NAME_value(name_stack_ptr, index as c_int);
            assert_ne!(name_ptr, ptr::null_mut());
            let buf = [0u8; 253];
            let _ = mesalink_X509_NAME_oneline(
                name_ptr as *mut MESALINK_X509_NAME,
                buf.as_ptr() as *mut c_char,
                253,
            );
            println!("DNSName: {}", str::from_utf8(&buf).unwrap());
        }
        mesalink_sk_X509_NAME_free(name_stack_ptr);
        mesalink_X509_free(x509_ptr);
    }

    #[test]
    fn x509_name_free_null_pointer() {
        mesalink_X509_free(ptr::null_mut());
        mesalink_X509_NAME_free(ptr::null_mut());
    }
}
