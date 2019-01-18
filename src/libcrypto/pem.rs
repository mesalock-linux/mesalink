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

use super::bio;
use super::bio::MESALINK_BIO;
use super::evp::MESALINK_EVP_PKEY;
use error_san::*;
use libc::c_void;
use libssl::x509::MESALINK_X509;
//use libcrypto::{CRYPTO_FAILURE, CRYPTO_SUCCESS};
use libssl::err::{MesalinkBuiltinError, MesalinkInnerResult};
use std::io::{Read, Seek};
use std::{io, ptr};

/// `PEM_read_bio_PrivateKey` reads a private key from *bio*. If there are
/// multiple keys in the bio, only the first one is read.
///
/// ```c
/// #include <mesalink/openssl/pem.h>
///
/// EVP_PKEY *PEM_read_bio_PrivateKey(BIO *bio, EVP_PKEY **x,
///                                        pem_password_cb *cb, void *u);
/// ```
///
#[no_mangle]
pub extern "C" fn mesalink_PEM_read_bio_PrivateKey(
    bio_ptr: *mut MESALINK_BIO,
    pkey_pp: *mut *mut MESALINK_EVP_PKEY,
    _cb: *mut c_void,
    _u: *mut c_void,
) -> *mut MESALINK_EVP_PKEY {
    check_inner_result!(
        inner_mesalink_pem_read_bio_privatekey(bio_ptr, pkey_pp),
        ptr::null_mut()
    )
}

fn inner_mesalink_pem_read_bio_privatekey(
    bio_ptr: *mut MESALINK_BIO,
    pkey_pp: *mut *mut MESALINK_EVP_PKEY,
) -> MesalinkInnerResult<*mut MESALINK_EVP_PKEY> {
    let bio = sanitize_ptr_for_mut_ref(bio_ptr)?;
    let mut buf_reader = io::BufReader::new(bio);
    let key = get_either_rsa_or_ecdsa_private_key(&mut buf_reader)
        .map_err(|_| error!(MesalinkBuiltinError::BadFuncArg.into()))?;
    let pkey = MESALINK_EVP_PKEY::new(key);
    let pkey_ptr = Box::into_raw(Box::new(pkey)) as *mut MESALINK_EVP_PKEY;

    if !pkey_pp.is_null() {
        unsafe {
            let p = &mut *pkey_pp;
            *p = pkey_ptr;
        }
    }
    Ok(pkey_ptr)
}

/// `PEM_read_PrivateKey` reads a private key from *file*. If there are multiple
/// keys in the file, only the first one is read.
///
/// ```c
/// #include <mesalink/openssl/pem.h>
///
/// EVP_PKEY *PEM_read_PrivateKey(FILE *fp, EVP_PKEY **x,
///                                     pem_password_cb *cb, void *u);
/// ```
#[no_mangle]
pub extern "C" fn mesalink_PEM_read_PrivateKey(
    file_ptr: *mut libc::FILE,
    pkey_pp: *mut *mut MESALINK_EVP_PKEY,
    _cb: *mut c_void,
    _u: *mut c_void,
) -> *mut MESALINK_EVP_PKEY {
    let bio_ptr = bio::mesalink_BIO_new_fp(file_ptr, 0x0); // BIO_NOCLOSE
    let ret = check_inner_result!(
        inner_mesalink_pem_read_bio_privatekey(bio_ptr, pkey_pp),
        ptr::null_mut()
    );
    bio::mesalink_BIO_free(bio_ptr);
    ret
}

/// `PEM_read_bio_X509` reads a X509 certificate from *bio*. If there are
/// multiple certificates in the bio, only the first one is read.
///
/// ```c
/// #include <mesalink/openssl/pem.h>
///
/// X509 *PEM_read_bio_X509(BIO *bio, X509 **x, pem_password_cb *cb, void *u);
/// ```
#[no_mangle]
pub extern "C" fn mesalink_PEM_read_bio_X509(
    bio_ptr: *mut MESALINK_BIO,
    x509_pp: *mut *mut MESALINK_X509,
    _cb: *mut c_void,
    _u: *mut c_void,
) -> *mut MESALINK_X509 {
    check_inner_result!(
        inner_mesalink_pem_read_bio_x509(bio_ptr, x509_pp),
        ptr::null_mut()
    )
}

fn inner_mesalink_pem_read_bio_x509(
    bio_ptr: *mut MESALINK_BIO,
    x509_pp: *mut *mut MESALINK_X509,
) -> MesalinkInnerResult<*mut MESALINK_X509> {
    let bio = sanitize_ptr_for_mut_ref(bio_ptr)?;
    let mut buf_reader = io::BufReader::new(bio);
    let cert = get_certificate(&mut buf_reader)
        .map_err(|_| error!(MesalinkBuiltinError::BadFuncArg.into()))?;
    let x509 = MESALINK_X509::new(cert);
    let x509_ptr = Box::into_raw(Box::new(x509)) as *mut MESALINK_X509;
    if !x509_pp.is_null() {
        unsafe {
            let p = &mut *x509_pp;
            *p = x509_ptr;
        }
    }
    Ok(x509_ptr)
}

/// `PEM_read_X509` reads a X509 certificate from *file*.
///
/// ```c
/// #include <mesalink/openssl/pem.h>
///
/// X509 *PEM_read_X509(FILE *fp, X509 **x, pem_password_cb *cb, void *u);
/// ```
#[no_mangle]
pub extern "C" fn mesalink_PEM_read_X509(
    file_ptr: *mut libc::FILE,
    x509_pp: *mut *mut MESALINK_X509,
    _cb: *mut c_void,
    _u: *mut c_void,
) -> *mut MESALINK_X509 {
    let bio_ptr = bio::mesalink_BIO_new_fp(file_ptr, 0x0); // BIO_NOCLOSE
    let ret = check_inner_result!(
        inner_mesalink_pem_read_bio_x509(bio_ptr, x509_pp),
        ptr::null_mut()
    );
    bio::mesalink_BIO_free(bio_ptr);
    ret
}

pub(crate) fn get_either_rsa_or_ecdsa_private_key<T: Read + Seek>(
    buf_reader: &mut io::BufReader<T>,
) -> Result<rustls::PrivateKey, ()> {
    let maybe_rsa_key = get_rsa_private_key(buf_reader);
    let _ = buf_reader.seek(io::SeekFrom::Start(0));
    let maybe_ecdsa_key = get_ecdsa_private_key(buf_reader);
    match (maybe_rsa_key, maybe_ecdsa_key) {
        (Ok(k), Err(_)) => Ok(k),
        (Err(_), Ok(k)) => Ok(k),
        _ => Err(()),
    }
}

pub(crate) fn get_certificate_chain(rd: &mut io::BufRead) -> Vec<rustls::Certificate> {
    let mut certs = Vec::new();
    while let Ok(cert) = get_certificate(rd) {
        certs.push(cert);
    }
    certs
}

pub(crate) fn get_certificate(rd: &mut io::BufRead) -> Result<rustls::Certificate, ()> {
    extract_one(
        rd,
        "-----BEGIN CERTIFICATE-----",
        "-----END CERTIFICATE-----",
        &|v| rustls::Certificate(v),
    )
}

pub(crate) fn get_rsa_private_key(rd: &mut io::BufRead) -> Result<rustls::PrivateKey, ()> {
    extract_one(
        rd,
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----END RSA PRIVATE KEY-----",
        &|v| rustls::PrivateKey(v),
    )
}

pub(crate) fn get_ecdsa_private_key(rd: &mut io::BufRead) -> Result<rustls::PrivateKey, ()> {
    extract_one(
        rd,
        "-----BEGIN PRIVATE KEY-----",
        "-----END PRIVATE KEY-----",
        &|v| rustls::PrivateKey(v),
    )
}

fn extract_one<A>(
    rd: &mut io::BufRead,
    start_mark: &str,
    end_mark: &str,
    f: &Fn(Vec<u8>) -> A,
) -> Result<A, ()> {
    let mut b64buf = String::new();
    let mut take_base64 = false;
    let mut raw_line = Vec::<u8>::new();
    loop {
        raw_line.clear();
        let len = rd.read_until(b'\n', &mut raw_line).map_err(|_| ())?;
        if len == 0 {
            return Err(());
        }
        let line = String::from_utf8_lossy(&raw_line);
        if line.starts_with(start_mark) {
            take_base64 = true;
            continue;
        }
        if line.starts_with(end_mark) {
            let der = base64::decode(&b64buf).map_err(|_| ())?;
            return Ok(f(der));
        }
        if take_base64 {
            b64buf.push_str(line.trim());
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use libc::c_char;
    use libcrypto::{bio, evp};
    use libssl::x509;
    use std::fs;
    use std::os::unix::io::AsRawFd;

    #[test]
    fn pem_read_bio_private_key() {
        let bio_ptr = bio::mesalink_BIO_read_filename(b"tests/end.key\0".as_ptr() as *const c_char);
        assert_ne!(bio_ptr, ptr::null_mut());
        let pkey_ptr = mesalink_PEM_read_bio_PrivateKey(
            bio_ptr,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
        );
        assert_ne!(pkey_ptr, ptr::null_mut());
        evp::mesalink_EVP_PKEY_free(pkey_ptr);
        bio::mesalink_BIO_free(bio_ptr);
    }

    #[test]
    fn pem_read_private_key() {
        let file = fs::File::open("tests/end.key").unwrap(); // Read-only, "r"
        let fd = file.as_raw_fd();
        let fp = unsafe { libc::fdopen(fd, b"r\0".as_ptr() as *const c_char) };
        assert_ne!(fp, ptr::null_mut());
        let pkey_ptr =
            mesalink_PEM_read_PrivateKey(fp, ptr::null_mut(), ptr::null_mut(), ptr::null_mut());
        assert_ne!(pkey_ptr, ptr::null_mut());
        evp::mesalink_EVP_PKEY_free(pkey_ptr);
    }

    #[test]
    fn pem_read_bio_x509() {
        let bio_ptr =
            bio::mesalink_BIO_read_filename(b"tests/end.fullchain\0".as_ptr() as *const c_char);
        assert_ne!(bio_ptr, ptr::null_mut());
        let x509_ptr =
            mesalink_PEM_read_bio_X509(bio_ptr, ptr::null_mut(), ptr::null_mut(), ptr::null_mut());
        assert_ne!(x509_ptr, ptr::null_mut());
        x509::mesalink_X509_free(x509_ptr);
        bio::mesalink_BIO_free(bio_ptr);
    }

    #[test]
    fn pem_read_x509() {
        let file = fs::File::open("tests/end.fullchain").unwrap(); // Read-only, "r"
        let fd = file.as_raw_fd();
        let fp = unsafe { libc::fdopen(fd, b"r\0".as_ptr() as *const c_char) };
        assert_ne!(fp, ptr::null_mut());
        let x509_ptr =
            mesalink_PEM_read_X509(fp, ptr::null_mut(), ptr::null_mut(), ptr::null_mut());
        assert_ne!(x509_ptr, ptr::null_mut());
        x509::mesalink_X509_free(x509_ptr);
    }

}
