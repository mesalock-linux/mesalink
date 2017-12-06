/* ssl.rs
 *                            _ _       _
 *                           | (_)     | |
 *  _ __ ___   ___  ___  __ _| |_ _ __ | | __
 * | '_ ` _ \ / _ \/ __|/ _` | | | '_ \| |/ /
 * | | | | | |  __/\__ \ (_| | | | | | |   <
 * |_| |_| |_|\___||___/\__,_|_|_|_| |_|_|\_\
 *
 * Copyright (C) 2017 Baidu USA.
 *
 * This file is part of Mesalink.
 */

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

#[repr(C)]
pub struct MESALINK_METHOD {
    magic: [u8; MAGIC_SIZE],
    tls_version: rustls::ProtocolVersion,
}

#[repr(C)]
pub struct MESALINK_CTX {
    magic: [u8; MAGIC_SIZE],
    methods: Option<Vec<rustls::ProtocolVersion>>,
    certificates: Option<Vec<rustls::Certificate>>,
    private_key: Option<rustls::PrivateKey>,
}

#[repr(C)]
pub struct MESALINK_SSL<'a> {
    magic: [u8; MAGIC_SIZE],
    context: &'a mut MESALINK_CTX,
    hostname: Option<&'a std::ffi::CStr>,
    io: Option<TcpStream>,
    session: Option<Box<Session>>,
    eof: bool,
    is_shutdown: bool,
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
            return std::ptr::null_mut();
        }
        let obj = unsafe { &* $ptr_var };
        let magic = *MAGIC;
        if obj.magic != magic {
            return std::ptr::null_mut();
        }
    }
}

macro_rules! sanitize_ptr_return_fail {
    ( $ptr_var:ident ) => {
        if $ptr_var.is_null() {
            return SslConstants::SslFailure as c_int;
        }
        let obj = unsafe { &*$ptr_var };
        let magic = *MAGIC;
        if obj.magic != magic {
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
    let method = MESALINK_METHOD {
        magic: *MAGIC,
        tls_version: rustls::ProtocolVersion::TLSv1_2,
    };
    Box::into_raw(Box::new(method))
}

#[no_mangle]
pub extern "C" fn mesalink_TLSv1_3_server_method() -> *const MESALINK_METHOD {
    let method = MESALINK_METHOD {
        magic: *MAGIC,
        tls_version: rustls::ProtocolVersion::TLSv1_3,
    };
    Box::into_raw(Box::new(method))
}

#[no_mangle]
pub extern "C" fn mesalink_CTX_new(method_ptr: *mut MESALINK_METHOD) -> *mut MESALINK_CTX {
    sanitize_ptr_return_null!(method_ptr);
    let method = unsafe { &*method_ptr };
    let context = MESALINK_CTX {
        magic: *MAGIC,
        methods: Some(vec![method.tls_version]),
        certificates: None,
        private_key: None,
    };
    let _ = unsafe { Box::from_raw(method_ptr) }; // Always free the method object
    Box::into_raw(Box::new(context))
}

#[no_mangle]
pub extern "C" fn mesalink_SSL_CTX_use_certificate_file(
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
                let certs = rustls::internal::pemfile::certs(&mut reader).unwrap();
                ctx.certificates = Some(certs);
            }
            Err(_) => {
                mesalink_push_error(ErrorCode::General);
                return SslConstants::SslFailure as c_int;
            }
        }
    }
    SslConstants::SslSuccess as c_int
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
                rustls::internal::pemfile::rsa_private_keys(&mut reader).unwrap()
            }
            Err(_) => {
                mesalink_push_error(ErrorCode::General);
                return SslConstants::SslFailure as c_int;
            }
        };
        let pk8_keys = match std::fs::File::open(filename) {
            Ok(f) => {
                let mut reader = std::io::BufReader::new(f);
                rustls::internal::pemfile::pkcs8_private_keys(&mut reader).unwrap()
            }
            Err(_) => {
                mesalink_push_error(ErrorCode::General);
                return SslConstants::SslFailure as c_int;
            }
        };
        if !pk8_keys.is_empty() {
            ctx.private_key = Some(pk8_keys[0].clone());
        } else {
            ctx.private_key = Some(rsa_keys[0].clone())
        }
    }
    SslConstants::SslSuccess as c_int
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
                }
            }
        }
        _ => (),
    }
    mesalink_push_error(ErrorCode::General);
    SslConstants::SslFailure as c_int
}

#[no_mangle]
pub extern "C" fn mesalink_SSL_new<'a>(ctx_ptr: *mut MESALINK_CTX) -> *mut MESALINK_SSL<'a> {
    sanitize_ptr_return_null!(ctx_ptr);
    let ctx = unsafe { &mut *ctx_ptr };
    let ssl = MESALINK_SSL {
        magic: *MAGIC,
        context: ctx,
        hostname: None,
        io: None,
        session: None,
        eof: false,
        is_shutdown: false,
    };
    Box::into_raw(Box::new(ssl))
}

#[no_mangle]
pub extern "C" fn mesalink_SSL_set_tlsext_host_name(
    ssl_ptr: *mut MESALINK_SSL,
    hostname_ptr: *const c_char,
) -> c_int {
    sanitize_ptr_return_fail!(ssl_ptr);
    let ssl = unsafe { &mut *ssl_ptr };
    if hostname_ptr.is_null() {
        mesalink_push_error(ErrorCode::General);
        return SslConstants::SslFailure as c_int;
    }
    let hostname = unsafe { std::ffi::CStr::from_ptr(hostname_ptr) };
    ssl.hostname = Some(hostname);
    SslConstants::SslSuccess as c_int
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
        None => SslConstants::SslFailure as c_int,
    }
}

#[no_mangle]
pub extern "C" fn mesalink_SSL_connect(ssl_ptr: *mut MESALINK_SSL) -> c_int {
    sanitize_ptr_return_fail!(ssl_ptr);
    let ssl = unsafe { &mut *ssl_ptr };
    if let Some(hostname) = ssl.hostname {
        if let Ok(hostname_str) = hostname.to_str() {
            let mut client_config = rustls::ClientConfig::new();
            client_config.versions = ssl.context.methods.clone().unwrap();
            client_config
                .root_store
                .add_server_trust_anchors(&TLS_SERVER_ROOTS);
            let dns_name = webpki::DNSNameRef::try_from_ascii_str(hostname_str).unwrap();
            let session = rustls::ClientSession::new(&Arc::new(client_config), dns_name);
            ssl.session = Some(Box::new(session));
            return SslConstants::SslSuccess as c_int;
        }
    }
    mesalink_push_error(ErrorCode::General);
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
        }
        _ => (),
    }
    let session = rustls::ServerSession::new(&Arc::new(server_config));
    ssl.session = Some(Box::new(session));
    SslConstants::SslSuccess as c_int
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
            writeln!(&mut std::io::stderr(), "mesalink_SSL_read error: {:?}", e).unwrap();
            mesalink_push_error(ErrorCode::General);
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
            writeln!(&mut std::io::stderr(), "mesalink_SSL_write error: {:?}", e).unwrap();
            mesalink_push_error(ErrorCode::General);
            SslConstants::SslFailure as c_int
        }
    }
}

#[no_mangle]
pub extern "C" fn mesalink_CTX_free(ctx_ptr: *mut MESALINK_CTX) {
    let _ = unsafe { Box::from_raw(ctx_ptr) };
}

#[no_mangle]
pub extern "C" fn mesalink_SSL_free(ssl_ptr: *mut MESALINK_SSL) {
    let _ = unsafe { Box::from_raw(ssl_ptr) };
}
