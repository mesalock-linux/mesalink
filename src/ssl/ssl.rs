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

//! # Synopsis
//! This sub-module implements the necessary APIs to establish a TLS session.
//! All the APIs are compatible to their OpenSSL counterparts.
//!
//! # Usage
//! The first step is to create a `SSL_CTX` object with `SSL_CTX_new`.
//!
//! Then `SSL_CTX_use_certificate_chain_file` and `SSL_CTX_use_PrivateKey_file`
//! must be called to set up the certificate and private key if the context is
//! to be used in a TLS server.
//!
//! When a TCP socket has been created, an `SSL` object can be created with
//! `SSL_new`. Afterwards, the socket can be assigned to the `SSL` object with
//! `SSL_set_fd`.
//!
//! Then the TLS handshake is performed using `SSL_connect` or `SSL_accept` for
//! a client or a server respectively. `SSL_read` and `SSL_write` are used to
//! read and write data on the TLS connection. Finally, `SSL_shutdown` can be
//! used to shut down the connection.

use std;
use std::sync::Arc;
use std::net::TcpStream;
use std::io;
use std::io::{Read, Write};
use std::os::unix::io::{AsRawFd, FromRawFd};
use libc::{c_char, c_int, c_uchar};
use rustls::{self, Session};
use ring;
use ring::rand::SecureRandom;
use webpki;
use webpki_roots::TLS_SERVER_ROOTS;
use ssl::err::{mesalink_push_error, ErrorCode};

const MAGIC_SIZE: usize = 4;
lazy_static! {
    static ref MAGIC: [u8; MAGIC_SIZE] = {
        let mut number = [0u8; MAGIC_SIZE];
        let rng = ring::rand::SystemRandom::new();
        if rng.fill(&mut number).is_ok() {
            number
        } else {
            [0xc0, 0xd4, 0xc5, 0x09]
        }
    };
}

const CONST_NONE_STR: &'static [u8] = b"NONE\0";
const CONST_TLS12_STR: &'static [u8] = b"TLS1.2\0";
const CONST_TLS13_STR: &'static [u8] = b"TLS1.3\0";

#[cfg(not(feature = "error_strings"))]
const CONST_NOTBUILTIN_STR: &'static [u8] = b"(Ciphersuite string not built-in)\0";

/// An OpenSSL Cipher object
#[repr(C)]
pub struct MESALINK_CIPHER {
    magic: [u8; MAGIC_SIZE],
    ciphersuite: &'static rustls::SupportedCipherSuite,
}

impl MESALINK_CIPHER {
    fn new(ciphersuite: &'static rustls::SupportedCipherSuite) -> MESALINK_CIPHER {
        MESALINK_CIPHER {
            magic: *MAGIC,
            ciphersuite: ciphersuite,
        }
    }
}

/// A dispatch structure describing the internal ssl library methods/functions
/// which implement the various protocol versions such as TLS v1.2.
///
/// This is a structure describing a specific TLS protocol version. It can be
/// created with a method like `TLSv1_2_client_method`. Then `SSL_CTX_new` can
/// consume it and create a new context. Note that a `SSL_METHOD` object is
/// implicitly freed in `SSL_CTX_new`. To avoid double free, do NOT reuse
/// `SSL_METHOD` objects; always create new ones when needed.
#[repr(C)]
pub struct MESALINK_METHOD {
    magic: [u8; MAGIC_SIZE],
    versions: Vec<rustls::ProtocolVersion>,
}

impl MESALINK_METHOD {
    fn new(versions: Vec<rustls::ProtocolVersion>) -> MESALINK_METHOD {
        MESALINK_METHOD {
            magic: *MAGIC,
            versions: versions,
        }
    }
}

/// A global context structure which is created by a server or a client once per
/// program. It holds default values for `SSL` objects which are later created
/// for individual connections.
///
/// Pass a valid `SSL_METHOD` object to `SSL_CTX_new` to create a `SSL_CTX`
/// object. Note that only TLS 1.2 and 1.3 (draft 18) are supported.
///
/// For a context to be used in a TLS server, call
/// `SSL_CTX_use_certificate_chain_file` and `SSL_CTX_use_PrivateKey_file` to
/// set the certificates and private key. Otherwise, `SSL_accept` would fail and
/// return an error code `NoCertificatesPresented`. If the context is created
/// for a TLS client, no further action is needed as MesaLink has built-in root
/// CA certificates and default ciphersuites. Support for configurable
/// ciphersuites will be added soon in the next release.
#[repr(C)]
pub struct MESALINK_CTX<'a> {
    magic: [u8; MAGIC_SIZE],
    methods: &'a mut MESALINK_METHOD,
    certificates: Option<Vec<rustls::Certificate>>,
    private_key: Option<rustls::PrivateKey>,
}

impl<'a> MESALINK_CTX<'a> {
    fn new(method: &'a mut MESALINK_METHOD) -> MESALINK_CTX {
        MESALINK_CTX {
            magic: *MAGIC,
            methods: method,
            certificates: None,
            private_key: None,
        }
    }
}

/// The main TLS structure which is created by a server or client per
/// established connection.
///
/// Pass a valid `SSL_CTX` object to `SSL_new` to create a new `SSL` object.
/// Then associate a valid socket file descriptor with `SSL_set_fd`.
#[repr(C)]
pub struct MESALINK_SSL<'a> {
    magic: [u8; MAGIC_SIZE],
    context: &'a mut MESALINK_CTX<'a>,
    hostname: Option<&'a std::ffi::CStr>,
    io: Option<TcpStream>,
    session: Option<Box<Session>>,
    error: ErrorCode,
    eof: bool,
}

impl<'a> MESALINK_SSL<'a> {
    fn new(ctx: &'a mut MESALINK_CTX<'a>) -> MESALINK_SSL<'a> {
        MESALINK_SSL {
            magic: *MAGIC,
            context: ctx,
            hostname: None,
            io: None,
            session: None,
            error: ErrorCode::SslErrorNone,
            eof: false,
        }
    }
}

#[doc(hidden)]
impl<'a> Read for MESALINK_SSL<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match (self.session.as_mut(), self.io.as_mut()) {
            (Some(session), Some(io)) => loop {
                self.error = match self.error {
                    ErrorCode::SslErrorNone
                    | ErrorCode::SslErrorWantRead
                    | ErrorCode::SslErrorWantWrite => ErrorCode::SslErrorNone,
                    _ => self.error,
                };
                match session.read(buf)? {
                    0 => if session.wants_write() {
                        match session.write_tls(io) {
                            Ok(_) => (), // ignore the result
                            Err(e) => {
                                if e.kind() == io::ErrorKind::WouldBlock {
                                    self.error = ErrorCode::SslErrorWantWrite;
                                }
                                return Err(e);
                            }
                        }
                    } else if session.wants_read() {
                        match session.read_tls(io) {
                            Ok(0) => {
                                self.eof = true;
                                return Ok(0); // EOF
                            }
                            Err(e) => {
                                if e.kind() == io::ErrorKind::WouldBlock {
                                    self.error = ErrorCode::SslErrorWantRead;
                                }
                                return Err(e);
                            }
                            Ok(_) => if let Err(err) = session.process_new_packets() {
                                if session.wants_write() {
                                    let _ = session.write_tls(io);
                                }
                                return Err(io::Error::new(io::ErrorKind::Other, err));
                            },
                        }
                    } else {
                        self.error = ErrorCode::SslErrorZeroReturn;
                        return Ok(0);
                    },
                    n => {
                        self.error = ErrorCode::SslErrorNone;
                        return Ok(n);
                    }
                }
            },
            _ => {
                mesalink_push_error(ErrorCode::NotConnected);
                Err(io::Error::from(io::ErrorKind::NotConnected))
            }
        }
    }
}

#[doc(hidden)]
impl<'a> Write for MESALINK_SSL<'a> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match (self.session.as_mut(), self.io.as_mut()) {
            (Some(session), Some(io)) => {
                let len = session.write(buf)?;
                let _ = session.write_tls(io)?;
                Ok(len)
            }
            _ => {
                mesalink_push_error(ErrorCode::NotConnected);
                Err(io::Error::from(io::ErrorKind::NotConnected))
            }
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match (self.session.as_mut(), self.io.as_mut()) {
            (Some(session), Some(io)) => {
                let ret = session.flush();
                let _ = session.write_tls(io)?;
                ret
            }
            _ => {
                mesalink_push_error(ErrorCode::NotConnected);
                Err(io::Error::from(io::ErrorKind::NotConnected))
            }
        }
    }
}

#[doc(hidden)]
#[repr(C)]
pub enum SslConstants {
    SslError = -1,
    SslFailure = 0,
    SslSuccess = 1,
    ShutdownNotDone = 2,
}

#[doc(hidden)]
#[repr(C)]
pub enum Filetypes {
    FiletypePEM = 1,
    FiletypeASN = 2,
    FiletypeRaw = 3,
}

macro_rules! sanitize_ptr_return_null {
    ( $ptr_var:ident ) => {
        if $ptr_var.is_null() {
            mesalink_push_error(ErrorCode::NullPointerException);
            return std::ptr::null_mut();
        }
        let obj = unsafe { &* $ptr_var };
        let magic = *MAGIC;
        if obj.magic != magic {
            mesalink_push_error(ErrorCode::MalformedObject);
            return std::ptr::null_mut();
        }
    }
}

macro_rules! sanitize_ptr_return_fail {
    ( $ptr_var:ident ) => {
        if $ptr_var.is_null() {
            mesalink_push_error(ErrorCode::NullPointerException);
            return SslConstants::SslFailure as c_int;
        }
        let obj = unsafe { &*$ptr_var };
        let magic = *MAGIC;
        if obj.magic != magic {
            mesalink_push_error(ErrorCode::MalformedObject);
            return SslConstants::SslFailure as c_int;
        }
    }
}

/// For OpenSSL compatibility only. Always returns 1.
///
/// ```
/// #include <mesalink/openssl/ssl.h>
///
/// int SSL_library_init(void);
/// int OpenSSL_add_ssl_algorithms(void);
/// ```
#[no_mangle]
pub extern "C" fn mesalink_library_init() -> c_int {
    /* compatibility only */
    SslConstants::SslSuccess as c_int
}

/// For OpenSSL compatibility only. Always returns 1.
///
/// ```
/// #include <mesalink/openssl/ssl.h>
///
/// int SSL_library_init(void);
/// int OpenSSL_add_ssl_algorithms(void);
/// ```
#[no_mangle]
pub extern "C" fn mesalink_add_ssl_algorithms() -> c_int {
    /* compatibility only */
    SslConstants::SslSuccess as c_int
}

/// For OpenSSL compatibility only.
///
/// ```
/// #include <mesalink/openssl/ssl.h>
///
/// void SSL_load_error_strings(void);
/// ```
#[no_mangle]
pub extern "C" fn mesalink_SSL_load_error_strings() {
    /* compatibility only */
}

/// SSL_METHOD APIs. Note that only TLS1_2_client_method, TLS1_3_client_method,
/// TLS1_2_server_method, and TLS1_3_server_method return valid SSL_METHOD
/// pointers. Others simply return NULL.
///
/// ```
/// #include <mesalink/openssl/ssl.h>
///
/// const SSL_METHOD *SSLv3_client_method(void);
/// ```
///
#[no_mangle]
pub extern "C" fn mesalink_SSLv3_client_method() -> *const MESALINK_METHOD {
    let p: *const MESALINK_METHOD = std::ptr::null();
    p
}

/// SSL_METHOD APIs. Note that only TLS1_2_client_method, TLS1_3_client_method,
/// TLS1_2_server_method, and TLS1_3_server_method return valid SSL_METHOD
/// pointers. Others simply return NULL.
///
/// ```
/// #include <mesalink/openssl/ssl.h>
///
/// const SSL_METHOD *SSLv23_client_method(void);
/// ```
///
#[no_mangle]
pub extern "C" fn mesalink_SSLv23_client_method() -> *const MESALINK_METHOD {
    let p: *const MESALINK_METHOD = std::ptr::null();
    p
}

/// SSL_METHOD APIs. Note that only TLS1_2_client_method, TLS1_3_client_method,
/// TLS1_2_server_method, and TLS1_3_server_method return valid SSL_METHOD
/// pointers. Others simply return NULL.
///
/// ```
/// #include <mesalink/openssl/ssl.h>
///
/// const SSL_METHOD *TLSv1_client_method(void);
/// ```
///
#[no_mangle]
pub extern "C" fn mesalink_TLSv1_client_method() -> *const MESALINK_METHOD {
    let p: *const MESALINK_METHOD = std::ptr::null();
    p
}

/// SSL_METHOD APIs. Note that only TLS1_2_client_method, TLS1_3_client_method,
/// TLS1_2_server_method, and TLS1_3_server_method return valid SSL_METHOD
/// pointers. Others simply return NULL.
///
/// ```
/// #include <mesalink/openssl/ssl.h>
///
/// const SSL_METHOD *TLSv1_1_client_method(void);
/// ```
///
#[no_mangle]
pub extern "C" fn mesalink_TLSv1_1_client_method() -> *const MESALINK_METHOD {
    let p: *const MESALINK_METHOD = std::ptr::null();
    p
}

/// SSL_METHOD APIs. Note that only TLS1_2_client_method, TLS1_3_client_method,
/// TLS1_2_server_method, and TLS1_3_server_method return valid SSL_METHOD
/// pointers. Others simply return NULL.
///
/// ```
/// #include <mesalink/openssl/ssl.h>
///
/// const SSL_METHOD *SSLv1_2_client_method(void);
/// ```
///
#[no_mangle]
pub extern "C" fn mesalink_TLSv1_2_client_method() -> *const MESALINK_METHOD {
    let method = MESALINK_METHOD::new(vec![rustls::ProtocolVersion::TLSv1_2]);
    Box::into_raw(Box::new(method))
}

/// SSL_METHOD APIs. Note that only TLS1_2_client_method, TLS1_3_client_method,
/// TLS1_2_server_method, and TLS1_3_server_method return valid SSL_METHOD
/// pointers. Others simply return NULL.
///
/// ```
/// #include <mesalink/openssl/ssl.h>
///
/// const SSL_METHOD *TLSv1_3_client_method(void);
/// ```
///
#[no_mangle]
pub extern "C" fn mesalink_TLSv1_3_client_method() -> *const MESALINK_METHOD {
    let method = MESALINK_METHOD::new(vec![rustls::ProtocolVersion::TLSv1_3]);
    Box::into_raw(Box::new(method))
}

/// SSL_METHOD APIs. Note that only TLS1_2_client_method, TLS1_3_client_method,
/// TLS1_2_server_method, and TLS1_3_server_method return valid SSL_METHOD
/// pointers. Others simply return NULL.
///
/// ```
/// #include <mesalink/openssl/ssl.h>
///
/// const SSL_METHOD *TLSv1_client_method(void);
/// ```
///
#[no_mangle]
pub extern "C" fn mesalink_TLS_client_method() -> *const MESALINK_METHOD {
    let method = MESALINK_METHOD::new(vec![
        rustls::ProtocolVersion::TLSv1_2,
        rustls::ProtocolVersion::TLSv1_3,
    ]);
    Box::into_raw(Box::new(method))
}

/// SSL_METHOD APIs. Note that only TLS1_2_client_method, TLS1_3_client_method,
/// TLS1_2_server_method, and TLS1_3_server_method return valid SSL_METHOD
/// pointers. Others simply return NULL.
///
/// ```
/// #include <mesalink/openssl/ssl.h>
///
/// const SSL_METHOD *SSLv3_server_method(void);
/// ```
///
#[no_mangle]
pub extern "C" fn mesalink_SSLv3_server_method() -> *const MESALINK_METHOD {
    let p: *const MESALINK_METHOD = std::ptr::null();
    p
}

/// SSL_METHOD APIs. Note that only TLS1_2_client_method, TLS1_3_client_method,
/// TLS1_2_server_method, and TLS1_3_server_method return valid SSL_METHOD
/// pointers. Others simply return NULL.
///
/// ```
/// #include <mesalink/openssl/ssl.h>
///
/// const SSL_METHOD *SSLv23_server_method(void);
/// ```
///
#[no_mangle]
pub extern "C" fn mesalink_SSLv23_server_method() -> *const MESALINK_METHOD {
    let p: *const MESALINK_METHOD = std::ptr::null();
    p
}

/// SSL_METHOD APIs. Note that only TLS1_2_client_method, TLS1_3_client_method,
/// TLS1_2_server_method, and TLS1_3_server_method return valid SSL_METHOD
/// pointers. Others simply return NULL.
///
/// ```
/// #include <mesalink/openssl/ssl.h>
///
/// const SSL_METHOD *TLSv1_server_method(void);
/// ```
///
#[no_mangle]
pub extern "C" fn mesalink_TLSv1_server_method() -> *const MESALINK_METHOD {
    let p: *const MESALINK_METHOD = std::ptr::null();
    p
}

/// SSL_METHOD APIs. Note that only TLS1_2_client_method, TLS1_3_client_method,
/// TLS1_2_server_method, and TLS1_3_server_method return valid SSL_METHOD
/// pointers. Others simply return NULL.
///
/// ```
/// #include <mesalink/openssl/ssl.h>
///
/// const SSL_METHOD *TLSv1_1_server_method(void);
/// ```
///
#[no_mangle]
pub extern "C" fn mesalink_TLSv1_1_server_method() -> *const MESALINK_METHOD {
    let p: *const MESALINK_METHOD = std::ptr::null();
    p
}

/// SSL_METHOD APIs. Note that only TLS1_2_client_method, TLS1_3_client_method,
/// TLS1_2_server_method, and TLS1_3_server_method return valid SSL_METHOD
/// pointers. Others simply return NULL.
///
/// ```
/// #include <mesalink/openssl/ssl.h>
///
/// const SSL_METHOD *TLSv1_2_server_method(void);
/// ```
///
#[no_mangle]
pub extern "C" fn mesalink_TLSv1_2_server_method() -> *const MESALINK_METHOD {
    let method = MESALINK_METHOD::new(vec![rustls::ProtocolVersion::TLSv1_2]);
    Box::into_raw(Box::new(method))
}

/// SSL_METHOD APIs. Note that only TLS1_2_client_method, TLS1_3_client_method,
/// TLS1_2_server_method, and TLS1_3_server_method return valid SSL_METHOD
/// pointers. Others simply return NULL.
///
/// ```
/// #include <mesalink/openssl/ssl.h>
///
/// const SSL_METHOD *TLSv1_3_server_method(void);
/// ```
///
#[no_mangle]
pub extern "C" fn mesalink_TLSv1_3_server_method() -> *const MESALINK_METHOD {
    let method = MESALINK_METHOD::new(vec![rustls::ProtocolVersion::TLSv1_3]);
    Box::into_raw(Box::new(method))
}

/// SSL_METHOD APIs. Note that only TLS1_2_client_method, TLS1_3_client_method,
/// TLS1_2_server_method, and TLS1_3_server_method return valid SSL_METHOD
/// pointers. Others simply return NULL.
///
/// ```
/// #include <mesalink/openssl/ssl.h>
///
/// const SSL_METHOD *TLSv1_3_server_method(void);
/// ```
///
#[no_mangle]
pub extern "C" fn mesalink_TLS_server_method() -> *const MESALINK_METHOD {
    let method = MESALINK_METHOD::new(vec![
        rustls::ProtocolVersion::TLSv1_2,
        rustls::ProtocolVersion::TLSv1_3,
    ]);
    Box::into_raw(Box::new(method))
}

/// `SSL_CTX_new` - create a new SSL_CTX object as framework to establish TLS/SSL
/// enabled connections.
///
/// ```
/// #include <mesalink/openssl/ssl.h>
///
/// SSL_CTX *SSL_CTX_new(const SSL_METHOD *method);
/// ```
#[no_mangle]
pub extern "C" fn mesalink_CTX_new<'a>(method_ptr: *mut MESALINK_METHOD) -> *mut MESALINK_CTX<'a> {
    sanitize_ptr_return_null!(method_ptr);
    let method = unsafe { &mut *method_ptr };
    let context = MESALINK_CTX::new(method);
    Box::into_raw(Box::new(context))
}

/// `SSL_CTX_use_certificate_chain_file` - load a certificate chain from file into
/// ctx. The certificates must be in PEM format and must be sorted starting with
/// the subject's certificate (actual client or server certificate), followed by
/// intermediate CA certificates if applicable, and ending at the highest level
/// (root) CA.
///
/// ```
/// #include <mesalink/openssl/ssl.h>
///
/// int SSL_CTX_use_certificate_chain_file(SSL_CTX *ctx, const char *file);
/// ```
#[no_mangle]
pub extern "C" fn mesalink_SSL_CTX_use_certificate_chain_file(
    ctx_ptr: *mut MESALINK_CTX,
    filename_ptr: *const c_char,
    _format: c_int,
) -> c_int {
    sanitize_ptr_return_fail!(ctx_ptr);
    let ctx = unsafe { &mut *ctx_ptr };
    let filename_cstr = unsafe { std::ffi::CStr::from_ptr(filename_ptr) };
    if let Ok(filename) = filename_cstr.to_str() {
        match std::fs::File::open(filename) {
            Ok(f) => {
                let mut reader = std::io::BufReader::new(f);
                let certs = rustls::internal::pemfile::certs(&mut reader);
                if certs.is_ok() {
                    ctx.certificates = Some(certs.unwrap());
                    return SslConstants::SslSuccess as c_int;
                } else {
                    mesalink_push_error(ErrorCode::BadKey);
                    return SslConstants::SslFailure as c_int;
                }
            }
            Err(e) => {
                mesalink_push_error(ErrorCode::from(e));
                return SslConstants::SslFailure as c_int;
            }
        }
    } else {
        mesalink_push_error(ErrorCode::BadFileName);
        SslConstants::SslFailure as c_int
    }
}

/// `SSL_CTX_use_PrivateKey_file` - add the first private key found in file to
/// ctx. The formatting type of the certificate must be specified from the known
/// types SSL_FILETYPE_PEM and SSL_FILETYPE_ASN1.
///
/// ```
/// #include <mesalink/openssl/ssl.h>
///
/// int SSL_CTX_use_PrivateKey_file(SSL_CTX *ctx, const char *file, int type);
/// ```
#[no_mangle]
pub extern "C" fn mesalink_SSL_CTX_use_PrivateKey_file(
    ctx_ptr: *mut MESALINK_CTX,
    filename_ptr: *const c_char,
    _format: c_int,
) -> c_int {
    sanitize_ptr_return_fail!(ctx_ptr);
    let ctx = unsafe { &mut *ctx_ptr };
    let filename_cstr = unsafe { std::ffi::CStr::from_ptr(filename_ptr) };
    if let Ok(filename) = filename_cstr.to_str() {
        let rsa_keys = match std::fs::File::open(filename) {
            Ok(f) => {
                let mut reader = std::io::BufReader::new(f);
                let keys = rustls::internal::pemfile::rsa_private_keys(&mut reader);
                if keys.is_ok() {
                    keys.unwrap()
                } else {
                    mesalink_push_error(ErrorCode::BadKey);
                    return SslConstants::SslFailure as c_int;
                }
            }
            Err(e) => {
                mesalink_push_error(ErrorCode::from(e));
                return SslConstants::SslFailure as c_int;
            }
        };
        let pk8_keys = match std::fs::File::open(filename) {
            Ok(f) => {
                let mut reader = std::io::BufReader::new(f);
                let keys = rustls::internal::pemfile::pkcs8_private_keys(&mut reader);
                if keys.is_ok() {
                    keys.unwrap()
                } else {
                    mesalink_push_error(ErrorCode::BadKey);
                    return SslConstants::SslFailure as c_int;
                }
            }
            Err(e) => {
                mesalink_push_error(ErrorCode::from(e));
                return SslConstants::SslFailure as c_int;
            }
        };
        if !pk8_keys.is_empty() {
            ctx.private_key = Some(pk8_keys[0].clone());
        } else {
            ctx.private_key = Some(rsa_keys[0].clone())
        }
        return SslConstants::SslSuccess as c_int;
    } else {
        mesalink_push_error(ErrorCode::BadFileName);
        SslConstants::SslFailure as c_int
    }
}

/// `SSL_CTX_check_private_key` - check the consistency of a private key with the
/// corresponding certificate loaded into ctx
///
/// ```
/// #include <mesalink/openssl/ssl.h>
///
/// int SSL_CTX_check_private_key(const SSL_CTX *ctx);
/// ```
#[no_mangle]
pub extern "C" fn mesalink_SSL_CTX_check_private_key(ctx_ptr: *mut MESALINK_CTX) -> c_int {
    sanitize_ptr_return_fail!(ctx_ptr);
    let ctx = unsafe { &mut *ctx_ptr };
    match (&ctx.certificates, &ctx.private_key) {
        (&Some(ref certs), &Some(ref key)) => {
            if let Ok(rsa_key) = rustls::sign::RSASigningKey::new(key) {
                let certified_key =
                    rustls::sign::CertifiedKey::new(certs.clone(), Arc::new(Box::new(rsa_key)));
                if certified_key.cross_check_end_entity_cert(None).is_ok() {
                    return SslConstants::SslSuccess as c_int;
                } else {
                    mesalink_push_error(ErrorCode::CertKeyMismatch);
                    return SslConstants::SslFailure as c_int;
                }
            }
        }
        _ => (),
    }
    mesalink_push_error(ErrorCode::BadKey);
    SslConstants::SslFailure as c_int
}

/// `SSL_new` - create a new SSL structure which is needed to hold the data for a
/// TLS/SSL connection
///
/// ```
/// #include <mesalink/openssl/ssl.h>
///
/// SSL *SSL_new(SSL_CTX *ctx);
/// ```
#[no_mangle]
pub extern "C" fn mesalink_SSL_new<'a>(ctx_ptr: *mut MESALINK_CTX<'a>) -> *mut MESALINK_SSL<'a> {
    sanitize_ptr_return_null!(ctx_ptr);
    let ctx = unsafe { &mut *ctx_ptr };
    let ssl = MESALINK_SSL::new(ctx);
    Box::into_raw(Box::new(ssl))
}

/// `SSL_get_SSL_CTX` - return a pointer to the SSL_CTX object, from which ssl was
/// created with SSL_new.
///
/// ```
/// #include <mesalink/openssl/ssl.h>
///
/// SSL_CTX *SSL_get_SSL_CTX(const SSL *ssl);
/// ```
#[no_mangle]
pub extern "C" fn mesalink_SSL_get_SSL_CTX(ssl_ptr: *const MESALINK_SSL) -> *const MESALINK_CTX {
    sanitize_ptr_return_null!(ssl_ptr);
    let ssl = unsafe { &*ssl_ptr };
    let ctx_ptr: *const MESALINK_CTX = ssl.context;
    ctx_ptr
}

/// `SSL_set_SSL_CTX` - set the SSL_CTX object of an SSL object.
///
/// ```
/// #include <mesalink/openssl/ssl.h>
///
/// SSL_CTX *SSL_set_SSL_CTX(SSL *ssl, SSL_CTX *ctx);
/// ```
#[no_mangle]
pub extern "C" fn mesalink_SSL_set_SSL_CTX<'a>(
    ssl_ptr: *mut MESALINK_SSL<'a>,
    ctx_ptr: *mut MESALINK_CTX<'a>,
) -> *mut MESALINK_CTX<'a> {
    sanitize_ptr_return_null!(ssl_ptr);
    let ssl = unsafe { &mut *ssl_ptr };
    sanitize_ptr_return_null!(ctx_ptr);
    let ctx = unsafe { &mut *ctx_ptr };
    ssl.context = ctx;
    ssl.context
}

/// `SSL_get_current_cipher` - returns a pointer to an SSL_CIPHER object
/// containing the description of the actually used cipher of a connection
/// established with the ssl object. See SSL_CIPHER_get_name for more details.
/// Note that this API allocates memory and needs to be properly freed. freed.
///
/// ```
/// #include <mesalink/openssl/ssl.h>
///
/// SSL_CIPHER *SSL_get_current_cipher(const SSL *ssl);
/// ```
#[no_mangle]
pub extern "C" fn mesalink_SSL_get_current_cipher(
    ssl_ptr: *const MESALINK_SSL,
) -> *mut MESALINK_CIPHER {
    sanitize_ptr_return_null!(ssl_ptr);
    let ssl = unsafe { &*ssl_ptr };
    match ssl.session.as_ref() {
        Some(session) => match session.get_negotiated_ciphersuite() {
            Some(cs) => {
                let cipher = MESALINK_CIPHER::new(cs);
                Box::into_raw(Box::new(cipher)) // Allocates memory!
            }
            None => std::ptr::null_mut(),
        },
        None => {
            mesalink_push_error(ErrorCode::NotConnected);
            std::ptr::null_mut()
        }
    }
}

/// `SSL_CIPHER_get_name` - return a pointer to the name of cipher. If the
/// argument is the NULL pointer, a pointer to the constant value "NONE" is
/// returned.
///
/// ```
/// #include <mesalink/openssl/ssl.h>
///
/// const char *SSL_CIPHER_get_name(const SSL_CIPHER *cipher);
/// ```
#[no_mangle]
#[cfg(feature = "error_strings")]
pub extern "C" fn mesalink_SSL_CIPHER_get_name(
    cipher_ptr: *const MESALINK_CIPHER,
) -> *const c_char {
    if !cipher_ptr.is_null() {
        sanitize_ptr_return_null!(cipher_ptr);
        let ciphersuite = unsafe { &*cipher_ptr };
        let name = suite_to_static_str(ciphersuite.ciphersuite.suite.get_u16());
        name.as_ptr() as *const c_char
    } else {
        CONST_NONE_STR.as_ptr() as *const c_char
    }
}

#[cfg(feature = "error_strings")]
fn suite_to_static_str(suite: u16) -> &'static [u8] {
    match suite {
        #[cfg(feature = "chachapoly")]
        0x1303 => b"TLS13_CHACHA20_POLY1305_SHA256\0",
        0xcca8 => b"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256\0",
        0xcca9 => b"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256\0",
        #[cfg(feature = "aesgcm")]
        0x1301 => b"TLS13_AES_128_GCM_SHA256\0",
        0x1302 => b"TLS13_AES_256_GCM_SHA384\0",
        0xc02b => b"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256\0",
        0xc02c => b"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384\0",
        0xc02f => b"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256\0",
        0xc030 => b"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384\0",
        _ => b"Unsupported ciphersuite\0",
    }
}

#[no_mangle]
#[cfg(not(feature = "error_strings"))]
pub extern "C" fn mesalink_SSL_CIPHER_get_name(
    cipher_ptr: *const MESALINK_CIPHER,
) -> *const c_char {
    if !cipher_ptr.is_null() {
        sanitize_ptr_return_null!(cipher_ptr);
        CONST_NOTBUILTIN_STR.as_ptr() as *const c_char
    } else {
        CONST_NONE_STR.as_ptr() as *const c_char
    }
}

/// `SSL_CIPHER_get_bits` - return the number of secret bits used for cipher. If
/// alg_bits is not NULL, it contains the number of bits processed by the chosen
/// algorithm. If cipher is NULL, 0 is returned.
///
/// ```
/// #include <mesalink/openssl/ssl.h>
///
/// int SSL_CIPHER_get_bits(const SSL_CIPHER *cipher, int *alg_bits);
/// ```
#[no_mangle]
pub extern "C" fn mesalink_SSL_CIPHER_get_bits(
    cipher_ptr: *const MESALINK_CIPHER,
    bits_ptr: *mut c_int,
) -> c_int {
    if !cipher_ptr.is_null() {
        sanitize_ptr_return_fail!(cipher_ptr);
        let ciphersuite = unsafe { &*cipher_ptr };
        unsafe { std::ptr::write(bits_ptr, ciphersuite.ciphersuite.enc_key_len as c_int) };
        SslConstants::SslSuccess as c_int
    } else {
        SslConstants::SslFailure as c_int
    }
}

/// `SSL_CIPHER_get_version` - returns string which indicates the SSL/TLS protocol
/// version that first defined the cipher. This is currently SSLv2 or
/// TLSv1/SSLv3. In some cases it should possibly return "TLSv1.2" but does not;
/// use SSL_CIPHER_description() instead. If cipher is NULL, "(NONE)" is
/// returned.
///
/// ```
/// #include <mesalink/openssl/ssl.h>
///
/// char *SSL_CIPHER_get_version(const SSL_CIPHER *cipher);
/// ```
#[no_mangle]
pub extern "C" fn mesalink_SSL_CIPHER_get_version(
    cipher_ptr: *const MESALINK_CIPHER,
) -> *const c_char {
    if !cipher_ptr.is_null() {
        sanitize_ptr_return_null!(cipher_ptr);
        let ciphersuite = unsafe { &*cipher_ptr };
        let suite_number = ciphersuite.ciphersuite.suite.get_u16() & 0xffff;
        if suite_number >> 8 == 0x13 {
            CONST_TLS13_STR.as_ptr() as *const c_char
        } else {
            CONST_TLS12_STR.as_ptr() as *const c_char
        }
    } else {
        CONST_NONE_STR.as_ptr() as *const c_char
    }
}

/// `SSL_get_cipher_name` - obtain the name of the currently used cipher.
///
/// ```
/// #include <mesalink/openssl/ssl.h>
///
/// char *SSL_get_cipher_name(const SSL *ssl);
/// ```
#[no_mangle]
pub extern "C" fn mesalink_SSL_get_cipher_name(ssl_ptr: *const MESALINK_SSL) -> *const c_char {
    let cipher = mesalink_SSL_get_current_cipher(ssl_ptr);
    let ret = mesalink_SSL_CIPHER_get_name(cipher);
    let _ = unsafe { Box::from_raw(cipher) };
    ret
}

/// `SSL_get_cipher` - obtain the name of the currently used cipher.
///
/// ```
/// #include <mesalink/openssl/ssl.h>
///
/// char *SSL_get_cipher(const SSL *ssl);
/// ```
#[no_mangle]
pub extern "C" fn mesalink_SSL_get_cipher(ssl_ptr: *const MESALINK_SSL) -> *const c_char {
    mesalink_SSL_get_cipher_name(ssl_ptr)
}

/// `SSL_get_cipher_bits` - obtain the number of secret/algorithm bits used.
///
/// ```
/// #include <mesalink/openssl/ssl.h>
///
/// int SSL_get_cipher_bits(const SSL *ssl, int* np);
/// ```
#[no_mangle]
pub extern "C" fn mesalink_SSL_get_cipher_bits(
    ssl_ptr: *const MESALINK_SSL,
    bits_ptr: *mut c_int,
) -> c_int {
    let cipher = mesalink_SSL_get_current_cipher(ssl_ptr);
    let ret = mesalink_SSL_CIPHER_get_bits(cipher, bits_ptr);
    let _ = unsafe { Box::from_raw(cipher) };
    ret
}

/// `SSL_get_cipher_version` - returns the protocol name.
///
/// ```
/// #include <mesalink/openssl/ssl.h>
///
/// char* SSL_get_cipher_version(const SSL *ssl);
/// ```
#[no_mangle]
pub extern "C" fn mesalink_SSL_get_cipher_version(ssl_ptr: *const MESALINK_SSL) -> *const c_char {
    let cipher = mesalink_SSL_get_current_cipher(ssl_ptr);
    let ret = mesalink_SSL_CIPHER_get_version(cipher);
    let _ = unsafe { Box::from_raw(cipher) };
    ret
}

/// `SSL_set_tlsext_host_name` - set the server name indication ClientHello
/// extension to contain the value name.
///
/// ```
/// #include <mesalink/openssl/ssl.h>
///
/// int SSL_set_tlsext_host_name(const SSL *s, const char *name);
/// ```
#[no_mangle]
pub extern "C" fn mesalink_SSL_set_tlsext_host_name(
    ssl_ptr: *mut MESALINK_SSL,
    hostname_ptr: *const c_char,
) -> c_int {
    sanitize_ptr_return_fail!(ssl_ptr);
    let ssl = unsafe { &mut *ssl_ptr };
    if hostname_ptr.is_null() {
        mesalink_push_error(ErrorCode::InvalidDNSName);
        return SslConstants::SslFailure as c_int;
    }
    let hostname = unsafe { std::ffi::CStr::from_ptr(hostname_ptr) };
    ssl.hostname = Some(hostname);
    SslConstants::SslSuccess as c_int
}

/// `SSL_get_servername` - return a servername extension value of the specified
/// type if provided in the Client Hello or NULL. The `type` argument is not
/// used.
///
/// ```
/// #include <mesalink/openssl/ssl.h>
///
/// const char *SSL_get_servername(const SSL *s, const int type);
/// ```
#[no_mangle]
pub extern "C" fn mesalink_SSL_get_servername(
    ssl_ptr: *const MESALINK_SSL,
    _type: c_int,
) -> *const c_char {
    sanitize_ptr_return_null!(ssl_ptr);
    let ssl = unsafe { &*ssl_ptr };
    match ssl.hostname {
        Some(hostname_cstr) => hostname_cstr.as_ptr(),
        None => std::ptr::null(),
    }
}

/// `SSL_set_fd` - set the file descriptor fd as the input/output facility for the
/// TLS/SSL (encrypted) side of ssl. fd will typically be the socket file
/// descriptor of a network connection.
///
/// ```
/// #include <mesalink/openssl/ssl.h>
///
/// int SSL_set_fd(SSL *ssl, int fd);
/// ```
#[no_mangle]
pub extern "C" fn mesalink_SSL_set_fd(ssl_ptr: *mut MESALINK_SSL, fd: c_int) -> c_int {
    sanitize_ptr_return_fail!(ssl_ptr);
    let ssl = unsafe { &mut *ssl_ptr };
    let socket = unsafe { TcpStream::from_raw_fd(fd) };
    ssl.io = Some(socket);
    SslConstants::SslSuccess as c_int
}

/// `SSL_get_fd` - return the file descriptor which is linked to ssl.
///
/// ```
/// #include <mesalink/openssl/ssl.h>
///
/// int SSL_get_fd(const SSL *ssl);
/// ```
#[no_mangle]
pub extern "C" fn mesalink_SSL_get_fd(ssl_ptr: *const MESALINK_SSL) -> c_int {
    sanitize_ptr_return_fail!(ssl_ptr);
    let ssl = unsafe { &*ssl_ptr };
    match ssl.io {
        Some(ref socket) => socket.as_raw_fd(),
        None => {
            mesalink_push_error(ErrorCode::NotConnected);
            SslConstants::SslFailure as c_int
        }
    }
}

/// `SSL_connect` - initiate the TLS handshake with a server. The communication
/// channel must already have been set and assigned to the ssl with SSL_set_fd.
///
/// ```
/// #include <mesalink/openssl/ssl.h>
///
/// int SSL_connect(SSL *ssl);
/// ```
#[no_mangle]
pub extern "C" fn mesalink_SSL_connect(ssl_ptr: *mut MESALINK_SSL) -> c_int {
    sanitize_ptr_return_fail!(ssl_ptr);
    let ssl = unsafe { &mut *ssl_ptr };
    if let Some(hostname) = ssl.hostname {
        if let Ok(hostname_str) = hostname.to_str() {
            if let Ok(dns_name) = webpki::DNSNameRef::try_from_ascii_str(hostname_str) {
                let mut client_config = rustls::ClientConfig::new();
                client_config.versions = ssl.context.methods.versions.clone();
                client_config
                    .root_store
                    .add_server_trust_anchors(&TLS_SERVER_ROOTS);
                let mut session = rustls::ClientSession::new(&Arc::new(client_config), dns_name);
                session.process_new_packets().unwrap();
                ssl.session = Some(Box::new(session));
                return SslConstants::SslSuccess as c_int;
            }
        }
    }
    mesalink_push_error(ErrorCode::InvalidDNSName);
    SslConstants::SslFailure as c_int
}

/// `SSL_accept` - wait for a TLS client to initiate the TLS handshake. The
/// communication channel must already have been set and assigned to the ssl by
/// setting SSL_set_fd.
///
/// ```
/// #include <mesalink/openssl/ssl.h>
///
/// int SSL_accept(SSL *ssl);
/// ```
#[no_mangle]
pub extern "C" fn mesalink_SSL_accept(ssl_ptr: *mut MESALINK_SSL) -> c_int {
    sanitize_ptr_return_fail!(ssl_ptr);
    let ssl = unsafe { &mut *ssl_ptr };
    let mut server_config = rustls::ServerConfig::new(rustls::NoClientAuth::new());
    match (&ssl.context.certificates, &ssl.context.private_key) {
        (&Some(ref certs), &Some(ref key)) => {
            server_config.set_single_cert(certs.clone(), key.clone());
            let session = rustls::ServerSession::new(&Arc::new(server_config));
            ssl.session = Some(Box::new(session));
            SslConstants::SslSuccess as c_int
        }
        _ => {
            mesalink_push_error(ErrorCode::NoCertificatesPresented);
            SslConstants::SslFailure as c_int
        }
    }
}

/// `SSL_get_error` - obtain result code for TLS/SSL I/O operation
///
/// ```
/// #include <mesalink/openssl/ssl.h>
///
/// int SSL_get_error(const SSL *ssl, int ret);
/// ```
#[no_mangle]
pub extern "C" fn mesalink_SSL_get_error(ssl_ptr: *const MESALINK_SSL, ret: c_int) -> c_int {
    if ret > 0 {
        return ErrorCode::SslErrorNone as c_int;
    }
    sanitize_ptr_return_fail!(ssl_ptr);
    let ssl = unsafe { &*ssl_ptr };
    ssl.error as c_int
}

/// `SSL_read` - read `num` bytes from the specified `ssl` into the
/// buffer `buf`.
///
/// ```
/// #include <mesalink/openssl/ssl.h>
///
/// int SSL_read(SSL *ssl, void *buf, int num);
/// ```
#[no_mangle]
pub extern "C" fn mesalink_SSL_read(
    ssl_ptr: *mut MESALINK_SSL,
    buf_ptr: *mut c_uchar,
    buf_len: c_int,
) -> c_int {
    sanitize_ptr_return_fail!(ssl_ptr);
    let ssl = unsafe { &mut *ssl_ptr };
    let buf = unsafe { std::slice::from_raw_parts_mut(buf_ptr, buf_len as usize) };
    match ssl.read(buf) {
        Ok(count) => count as c_int,
        Err(e) => match e.kind() {
            io::ErrorKind::WouldBlock => SslConstants::SslError as c_int,
            _ => SslConstants::SslFailure as c_int,
        },
    }
}

/// `SSL_write` - write `num` bytes from the buffer `buf` into the
/// specified `ssl` connection.
///
/// ```
/// #include <mesalink/openssl/ssl.h>
///
/// int SSL_write(SSL *ssl, const void *buf, int num);
/// ```
#[no_mangle]
pub extern "C" fn mesalink_SSL_write(
    ssl_ptr: *mut MESALINK_SSL,
    buf_ptr: *const c_uchar,
    buf_len: c_int,
) -> c_int {
    sanitize_ptr_return_fail!(ssl_ptr);
    let ssl = unsafe { &mut *ssl_ptr };
    let buf = unsafe { std::slice::from_raw_parts(buf_ptr, buf_len as usize) };
    match ssl.write(buf) {
        Ok(count) => count as c_int,
        Err(e) => match e.kind() {
            io::ErrorKind::WouldBlock => SslConstants::SslError as c_int,
            _ => SslConstants::SslFailure as c_int,
        },
    }
}

/// `SSL_shutdown` - shut down a TLS connection
///
/// ```
/// #include <mesalink/openssl/ssl.h>
///
/// int SSL_shutdown(SSL *ssl);
/// ```
#[no_mangle]
pub extern "C" fn mesalink_SSL_shutdown(ssl_ptr: *mut MESALINK_SSL) -> c_int {
    sanitize_ptr_return_fail!(ssl_ptr);
    let ssl = unsafe { &mut *ssl_ptr };
    match ssl.session {
        Some(ref mut s) => {
            s.send_close_notify();
            SslConstants::SslSuccess as c_int
        }
        None => {
            mesalink_push_error(ErrorCode::NotConnected);
            SslConstants::SslFailure as c_int
        }
    }
}

/// `SSL_get_version` - get the protocol information of a connection
///
/// ```
/// #include <mesalink/openssl/ssl.h>
///
/// const char *SSL_get_version(const SSL *ssl);
/// ```
#[no_mangle]
pub extern "C" fn mesalink_SSL_get_version(ssl_ptr: *mut MESALINK_SSL) -> *const c_char {
    sanitize_ptr_return_null!(ssl_ptr);
    let ssl = unsafe { &*ssl_ptr };
    match ssl.session {
        Some(ref s) => match s.get_protocol_version() {
            Some(rustls::ProtocolVersion::TLSv1_2) => CONST_TLS12_STR.as_ptr() as *const c_char,
            Some(rustls::ProtocolVersion::TLSv1_3) => CONST_TLS13_STR.as_ptr() as *const c_char,
            _ => CONST_NONE_STR.as_ptr() as *const c_char,
        },
        None => {
            mesalink_push_error(ErrorCode::NotConnected);
            std::ptr::null()
        }
    }
}

/// `SSL_CTX_free` - free an allocated SSL_CTX object
///
/// ```
/// #include <mesalink/openssl/ssl.h>
///
/// void SSL_CTX_free(SSL_CTX *ctx);
/// ```
#[no_mangle]
pub extern "C" fn mesalink_CTX_free(ctx_ptr: *mut MESALINK_CTX) {
    let _ = unsafe { Box::from_raw(ctx_ptr) };
}

/// `SSL_free` - free an allocated SSL object
///
/// ```
/// #include <mesalink/openssl/ssl.h>
///
/// void SSL_free(SSL *ssl);
/// ```
#[no_mangle]
pub extern "C" fn mesalink_SSL_free(ssl_ptr: *mut MESALINK_SSL) {
    let _ = unsafe { Box::from_raw(ssl_ptr) };
}
