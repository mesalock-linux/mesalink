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
use libssl::err::{MesalinkBuiltinError, MesalinkInnerResult};
use libssl::error_san::*;
use libssl::safestack::MESALINK_STACK_MESALINK_X509_NAME;
use libssl::{MesalinkOpaquePointerType, MAGIC, MAGIC_SIZE};
use libssl::{SSL_FAILURE, SSL_SUCCESS};
use ring::der;
use rustls;
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
    pub(crate) fn new(cert: rustls::Certificate) -> MESALINK_X509 {
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
    name: Vec<u8>,
}

impl<'a> MesalinkOpaquePointerType for MESALINK_X509_NAME {
    fn check_magic(&self) -> bool {
        self.magic == *MAGIC
    }
}

impl<'a> MESALINK_X509_NAME {
    pub(crate) fn new(name: &[u8]) -> MESALINK_X509_NAME {
        MESALINK_X509_NAME {
            magic: *MAGIC,
            name: name.to_vec(),
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
    let x509 = webpki::EndEntityCert::from(cert_der)
        .map_err(|e| error!(rustls::TLSError::WebPKIError(e).into()))?;
    let subject_alt_name = x509
        .inner
        .subject_alt_name
        .ok_or(error!(MesalinkBuiltinError::BadFuncArg.into()))?;
    let mut reader = untrusted::Reader::new(subject_alt_name);
    let mut stack = MESALINK_STACK_MESALINK_X509_NAME::new(Vec::new());
    while !reader.at_end() {
        let (tag, value) = der::read_tag_and_get_value(&mut reader)
            .map_err(|_| error!(MesalinkBuiltinError::BadFuncArg.into()))?;
        if tag == 0x82 {
            let x509_name = MESALINK_X509_NAME::new(value.as_slice_less_safe());
            stack.stack.push(x509_name);
        }
    }
    Ok(Box::into_raw(Box::new(stack)) as *mut MESALINK_STACK_MESALINK_X509_NAME)
}

#[no_mangle]
pub extern "C" fn mesalink_X509_get_subject(
    x509_ptr: *mut MESALINK_X509,
) -> *mut MESALINK_X509_NAME {
    check_inner_result!(inner_mesalink_x509_get_subject(x509_ptr), ptr::null_mut())
}

fn inner_mesalink_x509_get_subject(
    x509_ptr: *mut MESALINK_X509,
) -> MesalinkInnerResult<*mut MESALINK_X509_NAME> {
    let cert = sanitize_ptr_for_ref(x509_ptr)?;
    let cert_der = untrusted::Input::from(&cert.cert_data.0);
    let x509 = webpki::EndEntityCert::from(cert_der)
        .map_err(|e| error!(rustls::TLSError::WebPKIError(e).into()))?;
    let subject = x509.inner.subject.as_slice_less_safe();
    let subject_len = subject.len();
    let mut value = Vec::new();
    if subject_len <= 127 {
        value.extend_from_slice(&[0x30, subject.len() as u8]);
    } else {
        let mut size_of_length: usize = 0;
        let mut subject_len_tmp = subject_len;
        while subject_len_tmp != 0 {
            size_of_length += 1;
            subject_len_tmp /= 256;
        }
        let mut subject_len_tmp = subject_len;
        value.extend_from_slice(&[0x30, 128 + size_of_length as u8]);
        let mut length_bytes = vec![0; size_of_length];
        for i in 0..size_of_length {
            length_bytes[size_of_length - i - 1] = (subject_len_tmp & 0xff) as u8;
            subject_len_tmp >>= 8;
        }
        value.extend_from_slice(length_bytes.as_slice());
    }
    value.extend_from_slice(subject);
    value.shrink_to_fit();
    let x509_name = MESALINK_X509_NAME::new(&value);
    Ok(Box::into_raw(Box::new(x509_name)) as *mut MESALINK_X509_NAME)
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
    let x509 = webpki::EndEntityCert::from(cert_der)
        .map_err(|e| error!(rustls::TLSError::WebPKIError(e).into()))?;

    let mut subject_name = String::new();

    let _ = x509
        .inner
        .subject
        .read_all(error!(MesalinkBuiltinError::BadFuncArg.into()), |subject| {
            while !subject.at_end() {
                let (maybe_asn_set_tag, sequence) = der::read_tag_and_get_value(subject)
                    .map_err(|_| error!(MesalinkBuiltinError::BadFuncArg.into()))?;
                if (maybe_asn_set_tag as usize) != 0x31 {
                    // Subject should be an ASN.1 SET
                    return Err(error!(MesalinkBuiltinError::BadFuncArg.into()));
                }
                let _ = sequence.read_all(error!(MesalinkBuiltinError::BadFuncArg.into()), |seq| {
                    let oid_and_data = der::expect_tag_and_get_value(seq, der::Tag::Sequence)
                        .map_err(|_| error!(MesalinkBuiltinError::BadFuncArg.into()))?;
                    oid_and_data.read_all(
                        error!(MesalinkBuiltinError::BadFuncArg.into()),
                        |oid_and_data| {
                            let oid = der::expect_tag_and_get_value(oid_and_data, der::Tag::OID)
                                .map_err(|_| error!(MesalinkBuiltinError::BadFuncArg.into()))?;
                            let (_, value) = der::read_tag_and_get_value(oid_and_data)
                                .map_err(|_| error!(MesalinkBuiltinError::BadFuncArg.into()))?;

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

                            if keyword.is_empty() {
                                if let Ok(s) = str::from_utf8(value.as_slice_less_safe()) {
                                    subject_name.push_str("/");
                                    subject_name.push_str(keyword);
                                    subject_name.push_str("=");
                                    subject_name.push_str(s);
                                }
                            }
                            Ok(())
                        },
                    )
                });
            }
            Ok(())
        })
        .map_err(|_| error!(MesalinkBuiltinError::BadFuncArg.into()));

    let x509_name = MESALINK_X509_NAME::new(subject_name.as_bytes());
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
    let x509_name = sanitize_ptr_for_ref(x509_name_ptr)?;
    let buf_len: usize = buf_len as usize;
    unsafe {
        let name: &[c_char] = &*(x509_name.name.as_slice() as *const [u8] as *const [c_char]);
        let name_len: usize = name.len();
        if buf_ptr.is_null() {
            return Err(error!(MesalinkBuiltinError::NullPointer.into()));
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
    use libssl::safestack::*;
    use rustls::internal::pemfile;
    use std::fs::File;
    use std::io::BufReader;

    #[test]
    fn x509_get_subject_name_and_alt_names() {
        let mut certs_io = BufReader::new(File::open("tests/test.certs").unwrap());
        let certs = pemfile::certs(&mut certs_io).unwrap();
        assert_eq!(true, certs.len() > 0);
        let x509 = MESALINK_X509::new(certs[0].clone());
        let x509_ptr = Box::into_raw(Box::new(x509)) as *mut MESALINK_X509;

        let buf = [0u8; 255];
        let subject_der_ptr = mesalink_X509_get_subject(x509_ptr);
        assert_ne!(subject_der_ptr, ptr::null_mut());
        let _ = mesalink_X509_NAME_oneline(
            subject_der_ptr as *mut MESALINK_X509_NAME,
            buf.as_ptr() as *mut c_char,
            255,
        );
        mesalink_X509_NAME_free(subject_der_ptr);

        let subject_name_ptr = mesalink_X509_get_subject_name(x509_ptr);
        assert_ne!(subject_name_ptr, ptr::null_mut());

        let buf = [0u8; 255];
        let _ = mesalink_X509_NAME_oneline(
            subject_name_ptr as *mut MESALINK_X509_NAME,
            buf.as_ptr() as *mut c_char,
            255,
        );
        mesalink_X509_NAME_free(subject_name_ptr);

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
