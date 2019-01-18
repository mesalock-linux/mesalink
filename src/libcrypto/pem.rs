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
    let parsed_keys = load_private_key(&mut buf_reader)
        .map_err(|_| error!(MesalinkBuiltinError::BadFuncArg.into()))?;
    let pkey = MESALINK_EVP_PKEY::new(parsed_keys[0].clone());
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
    let certs = load_certificate(&mut buf_reader)
        .map_err(|_| error!(MesalinkBuiltinError::BadFuncArg.into()))?;
    let x509 = MESALINK_X509::new(certs[0].clone());
    let x509_ptr = Box::into_raw(Box::new(x509)) as *mut MESALINK_X509;
    if !x509_pp.is_null() {
        unsafe {
            let p = &mut *x509_pp;
            *p = x509_ptr;
        }
    }
    Ok(x509_ptr)
}

/// `PEM_read_X509` reads a X509 certificate from *file*. If there are
/// multiple certificates in the file, only the first one is read.
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

pub(crate) fn load_private_key<T: Read + Seek>(
    buf_reader: &mut io::BufReader<T>,
) -> Result<Vec<rustls::PrivateKey>, ()> {
    let mut parsed_keys: Result<Vec<rustls::PrivateKey>, ()> = Err(());
    let rsa_keys = rustls::internal::pemfile::rsa_private_keys(buf_reader);
    parsed_keys = rsa_keys
        .and_then(|keys| if keys.is_empty() { Err(()) } else { Ok(keys) })
        .or_else(|_| parsed_keys);
    let _ = buf_reader.seek(io::SeekFrom::Start(0));
    let pk8_keys = rustls::internal::pemfile::pkcs8_private_keys(buf_reader);
    parsed_keys = pk8_keys
        .and_then(|keys| if keys.is_empty() { Err(()) } else { Ok(keys) })
        .or_else(|_| parsed_keys);
    parsed_keys
}

pub(crate) fn load_certificate<T: Read>(
    buf_reader: &mut io::BufReader<T>,
) -> Result<Vec<rustls::Certificate>, ()> {
    rustls::internal::pemfile::certs(buf_reader).and_then(|certs| {
        if certs.is_empty() {
            Err(())
        } else {
            Ok(certs)
        }
    })
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
