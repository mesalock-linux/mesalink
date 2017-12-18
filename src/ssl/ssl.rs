/*
 *   __  __                 _     _       _
 *  |  \/  | ___  ___  __ _| |   (_)_ __ | | __
 *  | |\/| |/ _ \/ __|/ _` | |   | | '_ \| |/ /
 *  | |  | |  __/\__ \ (_| | |___| | | | |   <
 *  |_|  |_|\___||___/\__,_|_____|_|_| |_|_|\_\
 *
 * Copyright (c) 2017, The MesaLink Authors.
 * All rights reserved.
 *
 * This work is licensed under the terms of the BSD 3-Clause License.
 * For a copy, see the LICENSE file.
 *
 */

//! # Synopsis
//! This sub-module implements the necessary APIs to establish a TLS session.
//! All the APIs are compatible to their OpenSSL counterparts except their names
//! start with `mesalink_` instead. 
//!
//! # Usage
//! The first step is to create a `MESALINK_CTX` object with `mesalink_CTX_new`.
//!
//! Then `SSL_CTX_use_certificate_chain_file` and `SSL_CTX_use_PrivateKey_file`
//! must be called to set up the certificate and private key if the context is
//! to be used in a TLS server. 
//!
//! When a TCP socket has been created, a `MESALINK_SSL` object can be created
//! with `mesalink_SSL_new`. Afterwards, the socket can be assigned to the
//! `MESALINK_SSL` object with `mesalink_SSL_set_fd`. 
//! 
//! Then the TLS handshake is performed using `mesalink_SSL_connect` or
//! `mesalink_SSL_accept` for a client or a server respectively.
//! `mesalink_SSL_read` and `mesalink_SSL_write` are used to read and write data
//! on the TLS connection. Finally, `mesalink_SSL_shutdown` can be used to shut
//! down the connection. 

use std;
use std::sync::Arc;
use std::net::TcpStream;
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

/// A dispatch structure describing the internal ssl library methods/functions
/// which implement the various protocol versions (SSLv1, SSLv2 and TLSv1).
///
/// This is a structure describing a specific TLS protocol version. It can
/// be created with a method like `mesalink_TLSv1_2_client_method`. Then
/// `mesalink_CTX_new` can consume it and create a new context. Note that a
/// `MESALINK_METHOD` object is implicitly freed in `mesalink_CTX_new`. To
/// avoid double free, do NOT reuse `MESALINK_METHOD` objects; always create
/// new ones when needed.
#[repr(C)]
pub struct MESALINK_METHOD {
    magic: [u8; MAGIC_SIZE],
    tls_version: rustls::ProtocolVersion,
}

impl MESALINK_METHOD {
    fn new(version: rustls::ProtocolVersion) -> MESALINK_METHOD {
        MESALINK_METHOD {
            magic: *MAGIC,
            tls_version: version,
        }
    }
}


/// A global context structure which is created by a server or a client once per
/// program. It holds default values for `MESALINK_SSL` objects which are later
/// created for individual connections.
///
/// Pass a valid `MESALINK_METHOD` object to `mesalink_CTX_new` to create a
/// `MESALINK_CTX` object. Note that only TLS 1.2 and 1.3 (draft 18) are
/// supported.
///
/// For a context to be used in a TLS server, call
/// `SSL_CTX_use_certificate_chain_file` and `SSL_CTX_use_PrivateKey_file` to
/// set the certificates and private key. Otherwise, `mesalink_SSL_accept` would
/// fail and return an error code `NoCertificatesPresented`. If the context is
/// created for a TLS client, no further action is needed as MesaLink has
/// built-in root CA certificates and default ciphersuites. Support for
/// configurable ciphersuites will be added soon in the next release.
#[repr(C)]
pub struct MESALINK_CTX {
    magic: [u8; MAGIC_SIZE],
    methods: Option<Vec<rustls::ProtocolVersion>>,
    certificates: Option<Vec<rustls::Certificate>>,
    private_key: Option<rustls::PrivateKey>,
}

impl MESALINK_CTX {
    fn new<'a>(method: &'a MESALINK_METHOD) -> MESALINK_CTX {
        MESALINK_CTX {
            magic: *MAGIC,
            methods: Some(vec![method.tls_version]),
            certificates: None,
            private_key: None,
        }
    }
}

/// The main TLS structure which is created by a server or client per
/// established connection.
///
/// Pass a valid `MESALINK_CTX` object to `mesalink_SSL_new` to create a new
/// `MESALINK_SSL` object. Then associate a valid socket file descriptor with
/// `mesalink_SSL_set_fd`.
#[repr(C)]
pub struct MESALINK_SSL<'a> {
    magic: [u8; MAGIC_SIZE],
    context: &'a mut MESALINK_CTX,
    hostname: Option<&'a std::ffi::CStr>,
    io: Option<TcpStream>,
    session: Option<Box<Session>>,
}

impl<'a> MESALINK_SSL<'a> {
    fn new(ctx: &'a mut MESALINK_CTX) -> MESALINK_SSL {
        MESALINK_SSL {
            magic: *MAGIC,
            context: ctx,
            hostname: None,
            io: None,
            session: None,
        }
    }
}

impl<'a> Read for MESALINK_SSL<'a> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let session = self.session.as_mut().unwrap();
        let mut io = self.io.as_mut().unwrap();
        loop {
            match session.read(buf)? {
                0 => {
                    if session.wants_write() {
                        let _ = session.write_tls(&mut io)?;
                    } else if session.wants_read() {
                        if session.read_tls(&mut io)? == 0 {
                            return Ok(0); // there is no data left to read.
                        } else {
                            if let Err(err) = session.process_new_packets() {
                                // flush queued messages before returning an Err
                                // in order to send alerts instead of abruptly
                                // closing the socket
                                if session.wants_write() {
                                    // ignore result to avoid masking original error
                                    let _ = session.write_tls(&mut io);
                                }
                                return Err(std::io::Error::new(std::io::ErrorKind::Other, err));
                            }
                        }
                    } else {
                        return Ok(0);
                    }
                }
                n => return Ok(n),
            }
        }
    }
}

impl<'a> Write for MESALINK_SSL<'a> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let session = self.session.as_mut().unwrap();
        let mut io = self.io.as_mut().unwrap();
        let len = session.write(buf)?;
        let _ = session.write_tls(&mut io)?;
        Ok(len)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let session = self.session.as_mut().unwrap();
        let mut io = self.io.as_mut().unwrap();
        let ret = session.flush();
        let _ = session.write_tls(&mut io)?;
        ret
    }
}

pub enum SslConstants {
    SslFailure = 0,
    SslSuccess = 1,
}

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

#[no_mangle]
pub extern "C" fn mesalink_library_init() -> c_int {
    /* compatibility only */
    SslConstants::SslSuccess as c_int
}

#[no_mangle]
pub extern "C" fn mesalink_add_ssl_algorithms() -> c_int {
    /* compatibility only */
    SslConstants::SslSuccess as c_int
}

#[no_mangle]
pub extern "C" fn mesalink_SSL_load_error_strings() {
    /* compatibility only */
}

#[no_mangle]
pub extern "C" fn mesalink_SSLv3_client_method() -> *const MESALINK_METHOD {
    let p: *const MESALINK_METHOD = std::ptr::null();
    p
}

#[no_mangle]
pub extern "C" fn mesalink_SSLv23_client_method() -> *const MESALINK_METHOD {
    let p: *const MESALINK_METHOD = std::ptr::null();
    p
}

#[no_mangle]
pub extern "C" fn mesalink_TLSv1_client_method() -> *const MESALINK_METHOD {
    let p: *const MESALINK_METHOD = std::ptr::null();
    p
}

#[no_mangle]
pub extern "C" fn mesalink_TLSv1_1_client_method() -> *const MESALINK_METHOD {
    let p: *const MESALINK_METHOD = std::ptr::null();
    p
}

#[no_mangle]
pub extern "C" fn mesalink_TLSv1_2_client_method() -> *const MESALINK_METHOD {
    let method = MESALINK_METHOD {
        magic: *MAGIC,
        tls_version: rustls::ProtocolVersion::TLSv1_2,
    };
    Box::into_raw(Box::new(method))
}

#[no_mangle]
pub extern "C" fn mesalink_TLSv1_3_client_method() -> *const MESALINK_METHOD {
    let method = MESALINK_METHOD {
        magic: *MAGIC,
        tls_version: rustls::ProtocolVersion::TLSv1_3,
    };
    Box::into_raw(Box::new(method))
}

#[no_mangle]
pub extern "C" fn mesalink_SSLv3_server_method() -> *const MESALINK_METHOD {
    let p: *const MESALINK_METHOD = std::ptr::null();
    p
}

#[no_mangle]
pub extern "C" fn mesalink_SSLv23_server_method() -> *const MESALINK_METHOD {
    let p: *const MESALINK_METHOD = std::ptr::null();
    p
}

#[no_mangle]
pub extern "C" fn mesalink_TLSv1_server_method() -> *const MESALINK_METHOD {
    let p: *const MESALINK_METHOD = std::ptr::null();
    p
}

#[no_mangle]
pub extern "C" fn mesalink_TLSv1_1_server_method() -> *const MESALINK_METHOD {
    let p: *const MESALINK_METHOD = std::ptr::null();
    p
}

#[no_mangle]
pub extern "C" fn mesalink_TLSv1_2_server_method() -> *const MESALINK_METHOD {
    let method = MESALINK_METHOD::new(rustls::ProtocolVersion::TLSv1_2);
    Box::into_raw(Box::new(method))
}

#[no_mangle]
pub extern "C" fn mesalink_TLSv1_3_server_method() -> *const MESALINK_METHOD {
    let method = MESALINK_METHOD::new(rustls::ProtocolVersion::TLSv1_3);
    Box::into_raw(Box::new(method))
}

#[no_mangle]
pub extern "C" fn mesalink_CTX_new(method_ptr: *mut MESALINK_METHOD) -> *mut MESALINK_CTX {
    sanitize_ptr_return_null!(method_ptr);
    let method = unsafe { &*method_ptr };
    let context = MESALINK_CTX::new(method);
    let _ = unsafe { Box::from_raw(method_ptr) }; // Always free the method object
    Box::into_raw(Box::new(context))
}

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

#[no_mangle]
pub extern "C" fn mesalink_SSL_new<'a>(ctx_ptr: *mut MESALINK_CTX) -> *mut MESALINK_SSL<'a> {
    sanitize_ptr_return_null!(ctx_ptr);
    let ctx = unsafe { &mut *ctx_ptr };
    let ssl = MESALINK_SSL::new(ctx);
    Box::into_raw(Box::new(ssl))
}

#[no_mangle]
pub extern "C" fn mesalink_SSL_get_SSL_CTX(ssl_ptr: *const MESALINK_SSL) -> *const MESALINK_CTX {
    sanitize_ptr_return_null!(ssl_ptr);
    let ssl = unsafe { &*ssl_ptr };
    let ctx_ptr: *const MESALINK_CTX = ssl.context;
    ctx_ptr
}

#[no_mangle]
pub extern "C" fn mesalink_SSL_set_SSL_CTX(
    ssl_ptr: *mut MESALINK_SSL,
    ctx_ptr: *mut MESALINK_CTX,
) -> *mut MESALINK_CTX {
    sanitize_ptr_return_null!(ssl_ptr);
    let ssl = unsafe { &mut *ssl_ptr };
    sanitize_ptr_return_null!(ctx_ptr);
    let ctx = unsafe { &mut *ctx_ptr };
    ssl.context = ctx;
    ssl.context
}

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

#[no_mangle]
pub extern "C" fn mesalink_SSL_set_fd(ssl_ptr: *mut MESALINK_SSL, fd: c_int) -> c_int {
    sanitize_ptr_return_fail!(ssl_ptr);
    let ssl = unsafe { &mut *ssl_ptr };
    let socket = unsafe { TcpStream::from_raw_fd(fd) };
    ssl.io = Some(socket);
    SslConstants::SslSuccess as c_int
}

#[no_mangle]
pub extern "C" fn mesalink_SSL_get_fd(ssl_ptr: *mut MESALINK_SSL) -> c_int {
    sanitize_ptr_return_fail!(ssl_ptr);
    let ssl = unsafe { &mut *ssl_ptr };
    match ssl.io {
        Some(ref socket) => socket.as_raw_fd(),
        None => {
            mesalink_push_error(ErrorCode::NotConnected);
            SslConstants::SslFailure as c_int
        }
    }
}

#[no_mangle]
pub extern "C" fn mesalink_SSL_connect(ssl_ptr: *mut MESALINK_SSL) -> c_int {
    sanitize_ptr_return_fail!(ssl_ptr);
    let ssl = unsafe { &mut *ssl_ptr };
    if let Some(hostname) = ssl.hostname {
        if let Ok(hostname_str) = hostname.to_str() {
            if let Ok(dns_name) = webpki::DNSNameRef::try_from_ascii_str(hostname_str) {
                let mut client_config = rustls::ClientConfig::new();
                if let Some(ref versions) = ssl.context.methods {
                    client_config.versions = versions.clone();
                } else {
                    // Use defaults if no TLS version is set
                }
                client_config
                    .root_store
                    .add_server_trust_anchors(&TLS_SERVER_ROOTS);
                let session = rustls::ClientSession::new(&Arc::new(client_config), dns_name);
                ssl.session = Some(Box::new(session));
                return SslConstants::SslSuccess as c_int;
            }
        }
    }
    mesalink_push_error(ErrorCode::InvalidDNSName);
    SslConstants::SslFailure as c_int
}

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
        Err(e) => {
            mesalink_push_error(ErrorCode::from(e));
            SslConstants::SslFailure as c_int
        }
    }
}

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
        Err(e) => {
            mesalink_push_error(ErrorCode::from(e));
            SslConstants::SslFailure as c_int
        }
    }
}

#[no_mangle]
pub extern "C" fn mesalink_SSL_shutdown(ssl_ptr: *mut MESALINK_SSL) -> c_int {
    sanitize_ptr_return_fail!(ssl_ptr);
    let ssl = unsafe { &mut *ssl_ptr };
    let session = ssl.session.as_mut().unwrap();
    session.send_close_notify();
    SslConstants::SslSuccess as c_int
}

#[no_mangle]
pub extern "C" fn mesalink_CTX_free(ctx_ptr: *mut MESALINK_CTX) {
    let _ = unsafe { Box::from_raw(ctx_ptr) };
}

#[no_mangle]
pub extern "C" fn mesalink_SSL_free(ssl_ptr: *mut MESALINK_SSL) {
    let _ = unsafe { Box::from_raw(ssl_ptr) };
}
