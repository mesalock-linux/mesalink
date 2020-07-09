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

use super::err::{MesalinkBuiltinError, MesalinkInnerResult};
use super::safestack::MESALINK_STACK_MESALINK_X509_NAME;
use super::{SSL_FAILURE, SSL_SUCCESS};
use crate::error_san::*;
use crate::{MesalinkOpaquePointerType, MAGIC, MAGIC_SIZE};
use libc::{c_char, c_int};
use ring::io::der;
use std::{ptr, slice, str};

/// An OpenSSL X509 object
#[allow(non_camel_case_types)]
#[derive(Clone)]
pub struct MESALINK_X509 {
    magic: [u8; MAGIC_SIZE],
    pub inner: rustls::Certificate,
}

impl MesalinkOpaquePointerType for MESALINK_X509 {
    fn check_magic(&self) -> bool {
        self.magic == *MAGIC
    }
}

#[allow(unused)]
enum EndEntityOrCA<'a> {
    CA(&'a Cert<'a>),
}

#[allow(unused)]
struct SignedData<'a> {
    data: untrusted::Input<'a>,
    algorithm: untrusted::Input<'a>,
    signature: untrusted::Input<'a>,
}

#[allow(unused)]
struct Cert<'a> {
    pub ee_or_ca: EndEntityOrCA<'a>,
    pub signed_data: SignedData<'a>,
    pub issuer: untrusted::Input<'a>,
    pub validity: untrusted::Input<'a>,
    pub subject: untrusted::Input<'a>,
    pub spki: untrusted::Input<'a>,
    pub basic_constraints: Option<untrusted::Input<'a>>,
    pub eku: Option<untrusted::Input<'a>>,
    pub name_constraints: Option<untrusted::Input<'a>>,
    pub subject_alt_name: Option<untrusted::Input<'a>>,
}

#[doc(hidden)]
impl MESALINK_X509 {
    pub(crate) fn new(cert: rustls::Certificate) -> MESALINK_X509 {
        MESALINK_X509 {
            magic: *MAGIC,
            inner: cert,
        }
    }
}

/// `X509_free` - free up a X509 structure. If a is NULL nothing is done.
///
/// ```c
/// #include <mesalink/openssl/x509.h>
///
/// void X509_free(X509 *a);
/// ```
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

/// `X509_NAME_free` - free up a X509_NAME structure. If a is NULL nothing is
/// done.
///
/// ```c
/// #include <mesalink/openssl/x509.h>
///
/// void X509_free(X509 *a);
/// ```
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

/// `X509_get_alt_subject_names` - returns the alternative subject names of
/// certificate x. The returned value is a STACK pointer which MUST be freed by
/// `sk_X509_NAME_free`.
///
/// ```c
/// #include <mesalink/openssl/x509.h>
///
/// STACK_OF(X509_NAME) *X509_get_alt_subject_names(const X509 *x);;
/// ```
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
    let x509 = webpki::EndEntityCert::from(&cert.inner.0)
        .map_err(|e| error!(rustls::TLSError::WebPKIError(e).into()))?;
    let cert: Cert = unsafe { std::mem::transmute(x509) };
    let subject_alt_name = cert
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

/// `X509_get_subject` - returns the DER bytes of the subject of x as a
/// `X509_NAME`. The returned value is a X509_NAME pointer which MUST be freed
/// by `X509_NAME_free`.
///
/// ```c
/// #include <mesalink/openssl/x509.h>
///
/// X509_NAME *X509_get_subject(const X509 *x);;
/// ```
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
    let x509 = webpki::EndEntityCert::from(&cert.inner.0)
        .map_err(|e| error!(rustls::TLSError::WebPKIError(e).into()))?;
    let cert: Cert = unsafe { std::mem::transmute(x509) };
    let subject = cert.subject.as_slice_less_safe();
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

/// `X509_get_subject_name` - returns the subject of x as a human readable
/// `X509_NAME`. The returned value is a X509_NAME pointer which MUST be freed
/// by `X509_NAME_free`.
///
/// ```c
/// #include <mesalink/openssl/x509.h>
///
/// X509_NAME *X509_get_subject_name(const X509 *x);;
/// ```
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
    let x509 = webpki::EndEntityCert::from(&cert.inner.0)
        .map_err(|e| error!(rustls::TLSError::WebPKIError(e).into()))?;
    let mut subject_name = String::new();
    let cert: Cert = unsafe { std::mem::transmute(x509) };
    let _ = cert
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

                            if !keyword.is_empty() {
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

/// `X509_NAME_oneline` - prints an ASCII version of a to buf. If buf is NULL
/// then a buffer is dynamically allocated and returned, and size is ignored.
/// Otherwise, at most size bytes will be written, including the ending '\0',
/// and buf is returned.
///
/// ```c
/// #include <mesalink/openssl/x509.h>
///
/// char * X509_NAME_oneline(X509_NAME *a,char *buf,int size);
/// ```
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
    use crate::libssl::safestack::*;
    use rustls::internal::pemfile;
    use std::fs::File;
    use std::io::BufReader;

    #[test]
    fn x509_get_subject_name_and_alt_names() {
        let mut certs_io = BufReader::new(File::open("tests/end.fullchain").unwrap());
        let certs = pemfile::certs(&mut certs_io).unwrap();
        assert_eq!(true, certs.len() > 0);
        let x509 = MESALINK_X509::new(certs[0].clone());
        let x509_ptr = Box::into_raw(Box::new(x509)) as *mut MESALINK_X509;

        let buf_1 = [0u8; 255];
        let subject_der_ptr = mesalink_X509_get_subject(x509_ptr);
        assert_ne!(subject_der_ptr, ptr::null_mut());
        let _ = mesalink_X509_NAME_oneline(
            subject_der_ptr as *mut MESALINK_X509_NAME,
            buf_1.as_ptr() as *mut c_char,
            255,
        );
        let buf_2 = [0u8; 2];
        let _ = mesalink_X509_NAME_oneline(
            subject_der_ptr as *mut MESALINK_X509_NAME,
            buf_2.as_ptr() as *mut c_char,
            2,
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
            let name_ptr = mesalink_sk_X509_NAME_value(name_stack_ptr, index as c_int);
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
    fn x509_null_pointer() {
        mesalink_X509_free(ptr::null_mut());
        mesalink_X509_NAME_free(ptr::null_mut());
        assert_eq!(
            ptr::null(),
            mesalink_X509_NAME_oneline(ptr::null_mut(), ptr::null_mut(), 10)
        );
    }
}
