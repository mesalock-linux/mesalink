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

// Module imports
use std::{ffi, fs, io, net, ptr, slice};
use std::sync::Arc;
use libc::{c_char, c_int, c_uchar};
use rustls::{self, internal, sign};
use ring::rand;
use webpki;
use ssl::err::{ErrorCode, ErrorQueue};

// Trait imports
use std::io::{Read, Write};
use std::os::unix::io::{AsRawFd, FromRawFd};
use ring::rand::SecureRandom;
use rustls::Session;

const MAGIC_SIZE: usize = 4;
lazy_static! {
    static ref MAGIC: [u8; MAGIC_SIZE] = {
        let mut number = [0u8; MAGIC_SIZE];
        if rand::SystemRandom::new().fill(&mut number).is_ok() {
            number
        } else {
            panic!("Getrandom error");
        }
    };
}

const CONST_NONE_STR: &'static [u8] = b"NONE\0";
const CONST_TLS12_STR: &'static [u8] = b"TLS1.2\0";
const CONST_TLS13_STR: &'static [u8] = b"TLS1.3\0";

const SSL_ERROR: c_int = SslConstants::SslError as c_int;
const SSL_FAILURE: c_int = SslConstants::SslFailure as c_int;
const SSL_SUCCESS: c_int = SslConstants::SslSuccess as c_int;

const CLIENT_CACHE_SIZE: usize = 32;
const SERVER_CACHE_SIZE: usize = 128;

#[cfg(not(feature = "error_strings"))]
const CONST_NOTBUILTIN_STR: &'static [u8] = b"(Ciphersuite string not built-in)\0";

trait MesalinkOpaquePointerType {
    fn check_magic(&self) -> bool;
}

/// An OpenSSL Cipher object
#[repr(C)]
pub struct MESALINK_CIPHER {
    magic: [u8; MAGIC_SIZE],
    ciphersuite: &'static rustls::SupportedCipherSuite,
}

impl MesalinkOpaquePointerType for MESALINK_CIPHER {
    fn check_magic(&self) -> bool {
        self.magic == *MAGIC
    }
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

impl MesalinkOpaquePointerType for MESALINK_METHOD {
    fn check_magic(&self) -> bool {
        self.magic == *MAGIC
    }
}

impl MESALINK_METHOD {
    fn new(versions: Vec<rustls::ProtocolVersion>) -> MESALINK_METHOD {
        MESALINK_METHOD {
            magic: *MAGIC,
            versions: versions,
        }
    }
}

struct NoServerAuth {}
impl rustls::ServerCertVerifier for NoServerAuth {
    fn verify_server_cert(
        &self,
        _roots: &rustls::RootCertStore,
        _certs: &[rustls::Certificate],
        _hostname: webpki::DNSNameRef,
        _ocsp: &[u8],
    ) -> Result<rustls::ServerCertVerified, rustls::TLSError> {
        Ok(rustls::ServerCertVerified::assertion())
    }
}

struct MesalinkClientSessionCache {
    cache: Arc<rustls::ClientSessionMemoryCache>,
}

impl MesalinkClientSessionCache {
    fn new(cache_size: usize) -> Arc<MesalinkClientSessionCache> {
        let session_cache = MesalinkClientSessionCache {
            cache: rustls::ClientSessionMemoryCache::new(cache_size),
        };
        Arc::new(session_cache)
    }
}

impl rustls::StoresClientSessions for MesalinkClientSessionCache {
    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool {
        if key.len() > 2 && key[0] == b'k' && key[1] == b'x' {
            true
        } else {
            self.cache.put(key, value)
        }
    }

    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.cache.get(key)
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
#[derive(Clone)]
pub struct MESALINK_CTX {
    magic: [u8; MAGIC_SIZE],
    client_config: rustls::ClientConfig,
    server_config: rustls::ServerConfig,
    certificates: Option<Vec<rustls::Certificate>>,
    private_key: Option<rustls::PrivateKey>,
}

#[allow(non_camel_case_types)]
pub type MESALINK_CTX_ARC = Arc<MESALINK_CTX>;

impl<'a> MesalinkOpaquePointerType for MESALINK_CTX_ARC {
    fn check_magic(&self) -> bool {
        self.magic == *MAGIC
    }
}

impl<'a> MESALINK_CTX {
    fn new(method: &'a MESALINK_METHOD) -> MESALINK_CTX {
        let mut client_config = rustls::ClientConfig::new();
        let mut server_config = rustls::ServerConfig::new(rustls::NoClientAuth::new());

        client_config.versions.clear();
        server_config.versions.clear();

        for v in method.versions.iter() {
            client_config.versions.push(*v);
            server_config.versions.push(*v);
        }

        client_config.set_persistence(MesalinkClientSessionCache::new(CLIENT_CACHE_SIZE));
        server_config.set_persistence(rustls::ServerSessionMemoryCache::new(SERVER_CACHE_SIZE));

        use webpki_roots;
        client_config
            .root_store
            .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
        server_config.ticketer = rustls::Ticketer::new(); // Enable ticketing for server

        MESALINK_CTX {
            magic: *MAGIC,
            client_config: client_config,
            server_config: server_config,
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
    context: Option<MESALINK_CTX_ARC>,
    client_config: Arc<rustls::ClientConfig>,
    server_config: Arc<rustls::ServerConfig>,
    hostname: Option<webpki::DNSNameRef<'a>>,
    io: Option<net::TcpStream>,
    session: Option<Box<Session>>,
    error: ErrorCode,
    eof: bool,
}

impl<'a> MesalinkOpaquePointerType for MESALINK_SSL<'a> {
    fn check_magic(&self) -> bool {
        self.magic == *MAGIC
    }
}

impl<'a> MESALINK_SSL<'a> {
    fn new(ctx: &'a MESALINK_CTX_ARC) -> MESALINK_SSL<'a> {
        MESALINK_SSL {
            magic: *MAGIC,
            context: Some(ctx.clone()), // reference count +1
            client_config: Arc::new(ctx.client_config.clone()),
            server_config: Arc::new(ctx.server_config.clone()),
            hostname: None,
            io: None,
            session: None,
            error: ErrorCode::default(),
            eof: false,
        }
    }
}

#[doc(hidden)]
impl<'a> Read for MESALINK_SSL<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match (self.session.as_mut(), self.io.as_mut()) {
            (Some(session), Some(io)) => loop {
                match self.error {
                    ErrorCode::MesalinkErrorNone
                    | ErrorCode::MesalinkErrorWantRead
                    | ErrorCode::MesalinkErrorWantWrite => self.error = ErrorCode::default(),
                    _ => (),
                };
                match session.read(buf) {
                    Ok(0) => if session.wants_write() {
                        match session.write_tls(io) {
                            Ok(_) => (), // ignore the result
                            Err(e) => {
                                if e.kind() == io::ErrorKind::WouldBlock {
                                    self.error = ErrorCode::MesalinkErrorWantWrite;
                                } else {
                                    self.error = ErrorCode::from(&e);
                                }
                                ErrorQueue::push_error(self.error);
                                return Err(e);
                            }
                        }
                    } else if session.wants_read() {
                        match session.read_tls(io) {
                            Ok(0) => {
                                if !session.is_handshaking() {
                                    self.eof = true;
                                    return Ok(0); // EOF
                                } else {
                                    self.error = ErrorCode::IoErrorUnexpectedEof;
                                    ErrorQueue::push_error(self.error);
                                    return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
                                }
                            }
                            Err(e) => {
                                if e.kind() == io::ErrorKind::WouldBlock {
                                    self.error = ErrorCode::MesalinkErrorWantRead;
                                } else {
                                    self.error = ErrorCode::from(&e);
                                }
                                ErrorQueue::push_error(self.error);
                                return Err(e);
                            }
                            Ok(_) => if let Err(tls_err) = session.process_new_packets() {
                                if session.wants_write() {
                                    let _ = session.write_tls(io);
                                }
                                self.error = ErrorCode::from(&tls_err);
                                ErrorQueue::push_error(self.error);
                                return Err(io::Error::new(io::ErrorKind::InvalidData, tls_err));
                            },
                        }
                    } else {
                        self.error = ErrorCode::MesalinkErrorZeroReturn;
                        ErrorQueue::push_error(self.error);
                        return Ok(0);
                    },
                    Ok(n) => {
                        self.error = ErrorCode::default();
                        return Ok(n);
                    }
                    Err(e) => {
                        self.error = ErrorCode::from(&e);
                        ErrorQueue::push_error(self.error);
                        return Err(e);
                    }
                }
            },
            _ => {
                ErrorQueue::push_error(ErrorCode::IoErrorInvalidInput);
                Err(io::Error::from(io::ErrorKind::Other))
            }
        }
    }
}

#[doc(hidden)]
impl<'a> Write for MESALINK_SSL<'a> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match (self.session.as_mut(), self.io.as_mut()) {
            (Some(session), Some(io)) => {
                let len = session.write(buf)?;
                let _ = session.write_tls(io)?;
                Ok(len)
            }
            _ => {
                ErrorQueue::push_error(ErrorCode::MesalinkErrorNullPointer);
                Err(io::Error::from(io::ErrorKind::Other))
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match (self.session.as_mut(), self.io.as_mut()) {
            (Some(session), Some(io)) => {
                let ret = session.flush();
                let _ = session.write_tls(io)?;
                ret
            }
            _ => {
                ErrorQueue::push_error(ErrorCode::MesalinkErrorNullPointer);
                Err(io::Error::from(io::ErrorKind::Other))
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
    SslShutdownNotDone = 2,
}

#[doc(hidden)]
#[repr(C)]
pub enum Filetypes {
    FiletypePEM = 1,
    FiletypeASN = 2,
    FiletypeRaw = 3,
}

#[doc(hidden)]
#[repr(C)]
pub enum VerifyModes {
    VerifyNone = 0,
    VerifyPeer = 1,
    VerifyFailIfNoPeerCert = 2,
}

fn sanitize_ptr_for_ref<'a, T>(ptr: *mut T) -> Result<&'a T, ()>
where
    T: MesalinkOpaquePointerType,
{
    sanitize_ptr_for_mut_ref(ptr).map(|r| r as &'a T)
}

fn sanitize_ptr_for_mut_ref<'a, T>(ptr: *mut T) -> Result<&'a mut T, ()>
where
    T: MesalinkOpaquePointerType,
{
    if ptr.is_null() {
        ErrorQueue::push_error(ErrorCode::MesalinkErrorNullPointer);
        return Err(());
    }
    let obj_ref: &mut T = unsafe { &mut *ptr };
    if !obj_ref.check_magic() {
        ErrorQueue::push_error(ErrorCode::MesalinkErrorMalformedObject);
        return Err(());
    }
    Ok(obj_ref)
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
    SSL_SUCCESS
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
    SSL_SUCCESS
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
    let p: *const MESALINK_METHOD = ptr::null();
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
    mesalink_SSLv3_client_method()
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
    mesalink_SSLv3_client_method()
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
    mesalink_SSLv3_client_method()
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
        rustls::ProtocolVersion::TLSv1_3,
        rustls::ProtocolVersion::TLSv1_2,
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
    mesalink_SSLv3_client_method()
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
    mesalink_SSLv3_client_method()
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
    mesalink_SSLv3_client_method()
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
    mesalink_SSLv3_client_method()
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
        rustls::ProtocolVersion::TLSv1_3,
        rustls::ProtocolVersion::TLSv1_2,
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
pub extern "C" fn mesalink_SSL_CTX_new(method_ptr: *mut MESALINK_METHOD) -> *mut MESALINK_CTX_ARC {
    match sanitize_ptr_for_ref(method_ptr) {
        Ok(method) => {
            let context = MESALINK_CTX::new(method);
            let _ = unsafe { Box::from_raw(method_ptr) };
            Box::into_raw(Box::new(Arc::new(context))) // initialize the referece counter
        }
        Err(_) => ptr::null_mut(),
    }
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
    ctx_ptr: *mut MESALINK_CTX_ARC,
    filename_ptr: *const c_char,
    _format: c_int,
) -> c_int {
    match sanitize_ptr_for_mut_ref(ctx_ptr) {
        Ok(ctx) => match unsafe { ffi::CStr::from_ptr(filename_ptr).to_str() } {
            Ok(filename) => match fs::File::open(filename) {
                Ok(f) => match internal::pemfile::certs(&mut io::BufReader::new(f)) {
                    Ok(certs) => {
                        util::get_context_mut(ctx).certificates = Some(certs);
                        match util::try_get_context_certs_and_key(ctx) {
                            Ok((certs, priv_key)) => util::get_context_mut(ctx)
                                .server_config
                                .set_single_cert(certs, priv_key),
                            Err(_) => (),
                        }
                        SSL_SUCCESS
                    }
                    Err(_) => {
                        // pemfile::certs failed
                        ErrorQueue::push_error(ErrorCode::TLSErrorWebpkiBadDER);
                        SSL_FAILURE
                    }
                },
                Err(e) => {
                    // File::open failed
                    ErrorQueue::push_error(ErrorCode::from(&e));
                    SSL_FAILURE
                }
            },
            Err(_) => {
                //CStr::from_ptr failed
                ErrorQueue::push_error(ErrorCode::IoErrorNotFound);
                SSL_FAILURE
            }
        },
        Err(_) => SSL_FAILURE, // sanitize_ptr_for_mut_ref failed
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
    ctx_ptr: *mut MESALINK_CTX_ARC,
    filename_ptr: *const c_char,
    _format: c_int,
) -> c_int {
    match sanitize_ptr_for_mut_ref(ctx_ptr) {
        Ok(ctx) => match unsafe { ffi::CStr::from_ptr(filename_ptr).to_str() } {
            Ok(filename) => {
                let rsa_keys = match fs::File::open(filename) {
                    Ok(f) => internal::pemfile::rsa_private_keys(&mut io::BufReader::new(f)),
                    Err(_) => Err(())
                };
                let pk8_keys = match fs::File::open(filename) {
                    Ok(f) => internal::pemfile::pkcs8_private_keys(&mut io::BufReader::new(f)),
                    Err(_) => Err(())
                };
                let mut valid_keys = None;
                if let Ok(keys) = rsa_keys {
                    valid_keys = if keys.len() > 0 { Some(keys) } else { None };
                } else if let Ok(keys) = pk8_keys {
                    valid_keys = if keys.len() > 0 { Some(keys) } else { None };
                }
                if let Some(keys) = valid_keys {
                    util::get_context_mut(ctx).private_key = Some(keys[0].clone());
                    match util::try_get_context_certs_and_key(ctx) {
                        Ok((certs, priv_key)) => util::get_context_mut(ctx)
                            .server_config
                            .set_single_cert(certs, priv_key),
                        Err(_) => (),
                    }
                    SSL_SUCCESS
                } else {
                    ErrorQueue::push_error(ErrorCode::TLSErrorWebpkiBadDER);
                    SSL_FAILURE
                }
            }
            Err(_) => {
                // CStr::from_ptr failed
                ErrorQueue::push_error(ErrorCode::MesalinkErrorBadFuncArg);
                SSL_FAILURE
            }
        },
        Err(_) => SSL_FAILURE, // sanitize_ptr_for_mut_ref failed
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
pub extern "C" fn mesalink_SSL_CTX_check_private_key(ctx_ptr: *mut MESALINK_CTX_ARC) -> c_int {
    match sanitize_ptr_for_mut_ref(ctx_ptr) {
        Ok(ctx) => match (&ctx.certificates, &ctx.private_key) {
            (&Some(ref certs), &Some(ref key)) => match sign::RSASigningKey::new(key) {
                Ok(rsa_key) => {
                    match sign::CertifiedKey::new(certs.clone(), Arc::new(Box::new(rsa_key)))
                        .cross_check_end_entity_cert(None)
                    {
                        Ok(_) => SSL_SUCCESS,
                        Err(e) => {
                            // cross_check_end_entity_cert failed
                            ErrorQueue::push_error(ErrorCode::from(&e));
                            SSL_FAILURE
                        }
                    }
                }
                Err(_) => {
                    // RSASigningKey::new() failed
                    ErrorQueue::push_error(ErrorCode::TLSErrorWebpkiBadDER);
                    SSL_FAILURE
                }
            },
            _ => {
                // either ctx.certificates or ctx.private_key is None
                ErrorQueue::push_error(ErrorCode::MesalinkErrorBadFuncArg);
                SSL_FAILURE
            }
        },
        Err(_) => SSL_FAILURE, // sanitize_ptr_for_mut_ref failed
    }
}

#[doc(hidden)]
#[no_mangle]
pub extern "C" fn mesalink_SSL_CTX_set_verify(
    ctx_ptr: *mut MESALINK_CTX_ARC,
    mode: c_int,
    _cb: Option<extern "C" fn(c_int, *mut MESALINK_CTX) -> c_int>,
) -> c_int {
    match sanitize_ptr_for_mut_ref(ctx_ptr) {
        Ok(ctx) => {
            if mode == VerifyModes::VerifyNone as c_int {
                util::get_context_mut(ctx)
                    .client_config
                    .dangerous()
                    .set_certificate_verifier(Arc::new(NoServerAuth {}));
            }
            SSL_SUCCESS
        }
        Err(_) => SSL_FAILURE,
    }
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
pub extern "C" fn mesalink_SSL_new<'a>(ctx_ptr: *mut MESALINK_CTX_ARC) -> *mut MESALINK_SSL<'a> {
    match sanitize_ptr_for_mut_ref(ctx_ptr) {
        Ok(ctx) => {
            let ssl = MESALINK_SSL::new(ctx);
            Box::into_raw(Box::new(ssl))
        }
        Err(_) => ptr::null_mut(),
    }
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
pub extern "C" fn mesalink_SSL_get_SSL_CTX(ssl_ptr: *mut MESALINK_SSL) -> *const MESALINK_CTX_ARC {
    match sanitize_ptr_for_ref(ssl_ptr) {
        Ok(ssl) => ssl.context.as_ref().unwrap() as *const MESALINK_CTX_ARC,
        Err(_) => ptr::null(),
    }
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
    ctx_ptr: *mut MESALINK_CTX_ARC,
) -> *const MESALINK_CTX_ARC {
    match (
        sanitize_ptr_for_mut_ref(ctx_ptr),
        sanitize_ptr_for_mut_ref(ssl_ptr),
    ) {
        (Ok(ctx), Ok(ssl)) => {
            // After this line, the previous MESALINK_CTX_ARC pointed by
            // ssl.context is out of scope and decreses its reference counter;
            // the new MESALINK_CTX_ARC object increases its reference counter
            ssl.context = Some(ctx.clone());

            ssl.client_config = Arc::new(ctx.client_config.clone());
            ssl.server_config = Arc::new(ctx.server_config.clone());
            ssl.context.as_ref().unwrap() as *const MESALINK_CTX_ARC
        }
        _ => ptr::null_mut(),
    }
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
    ssl_ptr: *mut MESALINK_SSL,
) -> *mut MESALINK_CIPHER {
    match sanitize_ptr_for_ref(ssl_ptr) {
        Ok(ssl) => match ssl.session.as_ref() {
            Some(session) => match session.get_negotiated_ciphersuite() {
                Some(cs) => {
                    let cipher = MESALINK_CIPHER::new(cs);
                    Box::into_raw(Box::new(cipher)) // Allocates memory!
                }
                None => ptr::null_mut(),
            },
            None => {
                ErrorQueue::push_error(ErrorCode::IoErrorInvalidInput);
                ptr::null_mut()
            }
        },
        Err(_) => ptr::null_mut(),
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
pub extern "C" fn mesalink_SSL_CIPHER_get_name(cipher_ptr: *mut MESALINK_CIPHER) -> *const c_char {
    match sanitize_ptr_for_ref(cipher_ptr) {
        Ok(ciphersuite) => {
            let name = util::suite_to_static_str(ciphersuite.ciphersuite.suite.get_u16());
            name.as_ptr() as *const c_char
        }
        Err(_) => CONST_NONE_STR.as_ptr() as *const c_char,
    }
}

#[no_mangle]
#[cfg(not(feature = "error_strings"))]
pub extern "C" fn mesalink_SSL_CIPHER_get_name(cipher_ptr: *mut MESALINK_CIPHER) -> *const c_char {
    match sanitize_ptr_for_ref(cipher_ptr) {
        Ok(_) => CONST_NOTBUILTIN_STR.as_ptr() as *const c_char,
        Err(_) => CONST_NONE_STR.as_ptr() as *const c_char,
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
    cipher_ptr: *mut MESALINK_CIPHER,
    bits_ptr: *mut c_int,
) -> c_int {
    match sanitize_ptr_for_ref(cipher_ptr) {
        Ok(ciphersuite) => match bits_ptr.is_null() {
            true => {
                ErrorQueue::push_error(ErrorCode::MesalinkErrorBadFuncArg);
                SSL_FAILURE
            }
            false => {
                unsafe { ptr::write(bits_ptr, ciphersuite.ciphersuite.enc_key_len as c_int) };
                SSL_SUCCESS
            }
        },
        Err(_) => SSL_FAILURE,
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
    cipher_ptr: *mut MESALINK_CIPHER,
) -> *const c_char {
    match sanitize_ptr_for_ref(cipher_ptr) {
        Ok(ciphersuite) => {
            let suite_number = ciphersuite.ciphersuite.suite.get_u16() & 0xffff;
            if suite_number >> 8 == 0x13 {
                CONST_TLS13_STR.as_ptr() as *const c_char
            } else {
                CONST_TLS12_STR.as_ptr() as *const c_char
            }
        }
        Err(_) => CONST_NONE_STR.as_ptr() as *const c_char,
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
pub extern "C" fn mesalink_SSL_get_cipher_name(ssl_ptr: *mut MESALINK_SSL) -> *const c_char {
    let cipher = mesalink_SSL_get_current_cipher(ssl_ptr);
    let ret = mesalink_SSL_CIPHER_get_name(cipher);
    if !cipher.is_null() {
        let _ = unsafe { Box::from_raw(cipher) };
    }
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
pub extern "C" fn mesalink_SSL_get_cipher(ssl_ptr: *mut MESALINK_SSL) -> *const c_char {
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
    ssl_ptr: *mut MESALINK_SSL,
    bits_ptr: *mut c_int,
) -> c_int {
    let cipher = mesalink_SSL_get_current_cipher(ssl_ptr);
    let ret = mesalink_SSL_CIPHER_get_bits(cipher, bits_ptr);
    if !cipher.is_null() {
        let _ = unsafe { Box::from_raw(cipher) };
    }
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
pub extern "C" fn mesalink_SSL_get_cipher_version(ssl_ptr: *mut MESALINK_SSL) -> *const c_char {
    let cipher = mesalink_SSL_get_current_cipher(ssl_ptr);
    let ret = mesalink_SSL_CIPHER_get_version(cipher);
    if !cipher.is_null() {
        let _ = unsafe { Box::from_raw(cipher) };
    }
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
    match sanitize_ptr_for_mut_ref(ssl_ptr) {
        Ok(ssl) => {
            if hostname_ptr.is_null() {
                ErrorQueue::push_error(ErrorCode::MesalinkErrorNullPointer);
                return SSL_FAILURE;
            }
            match unsafe { ffi::CStr::from_ptr(hostname_ptr).to_str() } {
                Ok(hostname_str) => match webpki::DNSNameRef::try_from_ascii_str(hostname_str) {
                    Ok(dnsname) => {
                        ssl.hostname = Some(dnsname);
                        SSL_SUCCESS
                    }
                    Err(_) => {
                        // DNSNameRef::try_from_ascii_str failed
                        ErrorQueue::push_error(ErrorCode::IoErrorInvalidInput);
                        SSL_FAILURE
                    }
                },
                Err(_) => {
                    // ffi::CStr::from_ptr failed
                    ErrorQueue::push_error(ErrorCode::IoErrorInvalidInput);
                    SSL_FAILURE
                }
            }
        }
        Err(_) => SSL_FAILURE, // sanitize_ptr_for_mut_ref failed
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
    match sanitize_ptr_for_mut_ref(ssl_ptr) {
        Ok(ssl) => {
            if fd < 0 {
                ErrorQueue::push_error(ErrorCode::MesalinkErrorBadFuncArg);
                return SSL_FAILURE;
            }
            let socket = unsafe { net::TcpStream::from_raw_fd(fd) };
            ssl.io = Some(socket);
            SSL_SUCCESS
        }
        Err(_) => SSL_FAILURE,
    }
}

/// `SSL_get_fd` - return the file descriptor which is linked to ssl.
///
/// ```
/// #include <mesalink/openssl/ssl.h>
///
/// int SSL_get_fd(const SSL *ssl);
/// ```
#[no_mangle]
pub extern "C" fn mesalink_SSL_get_fd(ssl_ptr: *mut MESALINK_SSL) -> c_int {
    match sanitize_ptr_for_ref(ssl_ptr) {
        Ok(ssl) => match ssl.io {
            Some(ref socket) => socket.as_raw_fd(),
            None => {
                ErrorQueue::push_error(ErrorCode::IoErrorInvalidInput);
                SSL_ERROR
            }
        },
        Err(_) => SSL_ERROR, // 0 is a valid fd. Return -1 for error
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
    match sanitize_ptr_for_mut_ref(ssl_ptr) {
        Ok(ssl) => match ssl.hostname {
            Some(hostname) => {
                let mut session = rustls::ClientSession::new(&ssl.client_config, hostname);
                match session.process_new_packets() {
                    Ok(_) => (),
                    Err(e) => ErrorQueue::push_error(ErrorCode::from(&e)),
                }
                ssl.session = Some(Box::new(session));
                SSL_SUCCESS
            }
            None => {
                ErrorQueue::push_error(ErrorCode::IoErrorInvalidInput);
                SSL_FAILURE
            }
        },
        Err(_) => SSL_FAILURE,
    }
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
    match sanitize_ptr_for_mut_ref(ssl_ptr) {
        Ok(ssl) => {
            let session = rustls::ServerSession::new(&ssl.server_config);
            ssl.session = Some(Box::new(session));
            SSL_SUCCESS
        }
        Err(_) => SSL_FAILURE,
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
pub extern "C" fn mesalink_SSL_get_error(ssl_ptr: *mut MESALINK_SSL, ret: c_int) -> c_int {
    if ret > 0 {
        return ErrorCode::MesalinkErrorNone as c_int;
    }
    match sanitize_ptr_for_mut_ref(ssl_ptr) {
        Ok(ssl) => ssl.error as c_int,
        Err(_) => SSL_FAILURE,
    }
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
    match sanitize_ptr_for_mut_ref(ssl_ptr) {
        Ok(ssl) => {
            if buf_ptr.is_null() || buf_len < 0 {
                ErrorQueue::push_error(ErrorCode::MesalinkErrorBadFuncArg);
                return SSL_FAILURE;
            }
            let buf = unsafe { slice::from_raw_parts_mut(buf_ptr, buf_len as usize) };
            match ssl.read(buf) {
                Ok(count) => count as c_int,
                Err(e) => match e.kind() {
                    // ErrorCode has been pushed in queue by io::Read::read()
                    io::ErrorKind::WouldBlock => SSL_ERROR,
                    _ => SSL_FAILURE,
                },
            }
        }
        Err(_) => SSL_FAILURE,
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
    match sanitize_ptr_for_mut_ref(ssl_ptr) {
        Ok(ssl) => {
            if buf_ptr.is_null() || buf_len < 0 {
                ErrorQueue::push_error(ErrorCode::MesalinkErrorBadFuncArg);
                return SSL_FAILURE;
            }
            let buf = unsafe { slice::from_raw_parts(buf_ptr, buf_len as usize) };
            match ssl.write(buf) {
                Ok(count) => count as c_int,
                Err(e) => match e.kind() {
                    io::ErrorKind::WouldBlock => {
                        ErrorQueue::push_error(ErrorCode::MesalinkErrorWantWrite);
                        SSL_ERROR
                    }
                    _ => {
                        ErrorQueue::push_error(ErrorCode::from(&e));
                        SSL_FAILURE
                    }
                },
            }
        }
        Err(_) => SSL_FAILURE,
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
    match sanitize_ptr_for_mut_ref(ssl_ptr) {
        Ok(ssl) => match ssl.session {
            Some(ref mut s) => {
                s.send_close_notify();
                SSL_SUCCESS
            }
            None => {
                ErrorQueue::push_error(ErrorCode::IoErrorInvalidInput);
                SSL_ERROR
            }
        },
        Err(_) => SSL_ERROR,
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
    match sanitize_ptr_for_mut_ref(ssl_ptr) {
        Ok(ssl) => match ssl.session {
            Some(ref s) => match s.get_protocol_version() {
                Some(rustls::ProtocolVersion::TLSv1_2) => CONST_TLS12_STR.as_ptr() as *const c_char,
                Some(rustls::ProtocolVersion::TLSv1_3) => CONST_TLS13_STR.as_ptr() as *const c_char,
                _ => CONST_NONE_STR.as_ptr() as *const c_char,
            },
            None => {
                ErrorQueue::push_error(ErrorCode::IoErrorInvalidInput);
                ptr::null()
            }
        },
        Err(_) => ptr::null(),
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
pub extern "C" fn mesalink_SSL_CTX_free(ctx_ptr: *mut MESALINK_CTX_ARC) {
    if sanitize_ptr_for_mut_ref(ctx_ptr).is_ok() {
        let _ = unsafe { Arc::from_raw(ctx_ptr) };
    }
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
    if sanitize_ptr_for_mut_ref(ssl_ptr).is_ok() {
        let _ = unsafe { Box::from_raw(ssl_ptr) };
    }
}

mod util {
    use ssl::ssl;
    use rustls;
    use std::sync::Arc;

    pub fn try_get_context_certs_and_key<'a>(
        ctx: &'a mut ssl::MESALINK_CTX_ARC,
    ) -> Result<(Vec<rustls::Certificate>, rustls::PrivateKey), ()> {
        let certs = ctx.certificates.as_ref().ok_or(())?;
        let priv_key = ctx.private_key.as_ref().ok_or(())?;
        Ok((certs.clone(), priv_key.clone()))
    }

    #[cfg(feature = "error_strings")]
    pub fn suite_to_static_str(suite: u16) -> &'static [u8] {
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

    pub fn get_context_mut<'a>(ctx: &'a mut ssl::MESALINK_CTX_ARC) -> &mut ssl::MESALINK_CTX {
        Arc::make_mut(ctx)
    }
}
