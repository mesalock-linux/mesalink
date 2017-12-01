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
use std::ops::DerefMut;
use std::net::TcpStream;
use std::os::unix::io::{AsRawFd, FromRawFd};
use libc::{c_char, c_int, c_uchar};
use rustls;
use rustls::Session;
use webpki_roots::TLS_SERVER_ROOTS;
use ssl::err::{mesalink_push_error, ErrorCode};

const MAGIC: u32 = 0xc0d4c5a9;

#[repr(C)]
pub struct MESALINK_METHOD {
    magic: u32,
    tls_version: rustls::ProtocolVersion,
}

#[repr(C)]
pub struct MESALINK_CTX {
    magic: u32,
    client_config: Arc<rustls::ClientConfig>,
    server_config: Arc<rustls::ServerConfig>,
}

#[repr(C)]
pub struct MESALINK_SSL<'a> {
    magic: u32,
    context: &'a mut MESALINK_CTX,
    hostname: Option<&'a std::ffi::CStr>,
    socket: Option<TcpStream>,
    session: Option<Box<Session>>,
}

pub enum SslConstants {
    SslFailure = 0,
    SslSuccess = 1,
}

macro_rules! sanitize_ptr_return_null {
    ( $ptr_var:ident ) => {
        if $ptr_var.is_null() {
            return std::ptr::null_mut();
        }
        let obj = unsafe { &* $ptr_var };
        if obj.magic != MAGIC {
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
        if obj.magic != MAGIC {
            return SslConstants::SslFailure as c_int;
        }
    }
}

#[no_mangle]
pub extern "C" fn mesalink_library_init() -> c_int {
    /* compatibility only */
    1
}

#[no_mangle]
pub extern "C" fn mesalink_add_ssl_algorithms() -> c_int {
    /* compatibility only */
    1
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
        magic: MAGIC,
        tls_version: rustls::ProtocolVersion::TLSv1_2,
    };
    Box::into_raw(Box::new(method))
}

#[no_mangle]
pub extern "C" fn mesalink_TLSv1_3_client_method() -> *const MESALINK_METHOD {
    let method = MESALINK_METHOD {
        magic: MAGIC,
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
        magic: MAGIC,
        tls_version: rustls::ProtocolVersion::TLSv1_2,
    };
    Box::into_raw(Box::new(method))
}

#[no_mangle]
pub extern "C" fn mesalink_TLSv1_3_server_method() -> *const MESALINK_METHOD {
    let method = MESALINK_METHOD {
        magic: MAGIC,
        tls_version: rustls::ProtocolVersion::TLSv1_3,
    };
    Box::into_raw(Box::new(method))
}

#[no_mangle]
pub extern "C" fn mesalink_CTX_new(method_ptr: *mut MESALINK_METHOD) -> *mut MESALINK_CTX {
    sanitize_ptr_return_null!(method_ptr);
    let method = unsafe { &*method_ptr };
    let mut client_config = rustls::ClientConfig::new();
    client_config.versions = vec![method.tls_version];
    client_config
        .root_store
        .add_server_trust_anchors(&TLS_SERVER_ROOTS);
    let mut server_config = rustls::ServerConfig::new();
    server_config.versions = vec![method.tls_version];
    let context = MESALINK_CTX {
        magic: MAGIC,
        client_config: Arc::new(client_config),
        server_config: Arc::new(server_config),
    };
    let _ = unsafe { Box::from_raw(method_ptr) };
    Box::into_raw(Box::new(context))
}

#[no_mangle]
pub extern "C" fn mesalink_SSL_new<'a>(ctx_ptr: *mut MESALINK_CTX) -> *mut MESALINK_SSL<'a> {
    sanitize_ptr_return_null!(ctx_ptr);
    let ctx = unsafe { &mut *ctx_ptr };
    let ssl = MESALINK_SSL {
        magic: MAGIC,
        context: ctx,
        hostname: None,
        socket: None,
        session: None,
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
    ssl.socket = Some(socket);
    SslConstants::SslSuccess as c_int
}

#[no_mangle]
pub extern "C" fn mesalink_SSL_get_fd(ssl_ptr: *mut MESALINK_SSL) -> c_int {
    sanitize_ptr_return_fail!(ssl_ptr);
    let ssl = unsafe { &mut *ssl_ptr };
    match ssl.socket {
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
            let session = rustls::ClientSession::new(&ssl.context.client_config, hostname_str);
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
    let session = rustls::ServerSession::new(&ssl.context.server_config);
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
    let sock = ssl.socket.as_mut().unwrap();
    let buf = unsafe { std::slice::from_raw_parts_mut(buf_ptr, buf_len as usize) };
    let session = ssl.session.as_mut().unwrap();
    let ret = io_read(session.deref_mut(), sock, buf);
    match ret {
        Ok(count) => count as c_int,
        Err(_) => {
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
    let sock = ssl.socket.as_mut().unwrap();
    let buf = unsafe { std::slice::from_raw_parts(buf_ptr, buf_len as usize) };
    let session = ssl.session.as_mut().unwrap();
    let ret = io_write(session.deref_mut(), sock, buf);
    match ret {
        Ok(count) => count as c_int,
        Err(_) => {
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

fn complete_io(
    session: &mut Session,
    io: &mut TcpStream,
) -> Result<(usize, usize), std::io::Error> {
    let until_handshaked = session.is_handshaking();
    let mut eof = false;
    let mut wrlen = 0;
    let mut rdlen = 0;
    loop {
        while session.wants_write() {
            wrlen += session.write_tls(io)?;
        }
        if !until_handshaked && wrlen > 0 {
            return Ok((rdlen, wrlen));
        }
        if !eof && session.wants_read() {
            match session.read_tls(io)? {
                0 => eof = true,
                n => rdlen += n,
            }
        }
        match session.process_new_packets() {
            Ok(_) => {}
            Err(e) => {
                let _ignored = session.write_tls(io);
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, e));
            }
        };
        match (eof, until_handshaked, session.is_handshaking()) {
            (_, true, false) => return Ok((rdlen, wrlen)),
            (_, false, _) => return Ok((rdlen, wrlen)),
            (true, true, true) => {
                return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))
            }
            (..) => (),
        }
    }
}

fn io_read(
    session: &mut Session,
    sock: &mut TcpStream,
    buf: &mut [u8],
) -> Result<usize, std::io::Error> {
    if session.is_handshaking() {
        let _ = complete_io(session, sock)?;
    }
    if session.wants_write() {
        let _ = complete_io(session, sock)?;
    }
    if session.wants_read() {
        let _ = complete_io(session, sock)?;
    }
    let len = session.read(buf)?;
    let _ = complete_io(session, sock)?;
    Ok(len)
}

fn io_write(
    session: &mut Session,
    sock: &mut TcpStream,
    buf: &[u8],
) -> Result<usize, std::io::Error> {
    if session.is_handshaking() {
        let _ = complete_io(session, sock)?;
    }
    if session.wants_write() {
        let _ = complete_io(session, sock)?;
    }
    let len = session.write(buf)?;
    let _ = complete_io(session, sock)?;
    Ok(len)
}
