/* lib.rs
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

#![allow(non_snake_case)]

use std::sync::Arc;
use std::net::TcpStream;
use std::io::{Read, Write};
use std::os::unix::io::FromRawFd;
use std::slice;

extern crate rustls;
extern crate libc;
extern crate webpki;
extern crate webpki_roots;

use rustls::ClientConfig;
use rustls::ClientSession;
use rustls::Stream;
use libc::{c_uchar, c_int};

#[repr(C)]
pub struct MESALINK_METHOD {
    config: Arc<ClientConfig>,
}

#[repr(C)]
pub struct MESALINK_CTX {
    session: ClientSession,
}

#[repr(C)]
pub struct MESALINK<'a> {
    session: &'a mut ClientSession,
    socket: Option<TcpStream>,
    stream: Option<Stream<'a, ClientSession, TcpStream>>,
}


#[no_mangle]
pub extern "C" fn mesalink_TLSv1_2_client_method() -> *mut MESALINK_METHOD {
    let mut client_config = rustls::ClientConfig::new();
    client_config.root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
    let method = MESALINK_METHOD {
        config: Arc::new(client_config),
    };
    Box::into_raw(Box::new(method))
}

#[no_mangle]
pub extern "C" fn mesalink_CTX_new(method_ptr: *mut MESALINK_METHOD) -> *mut MESALINK_CTX {
    let method = unsafe {
        assert!(!method_ptr.is_null());
        &*method_ptr
    };
    let dns_name = webpki::DNSNameRef::try_from_ascii_str("google.com").unwrap();
    let client_session = ClientSession::new(&method.config, dns_name);
    let ctx = MESALINK_CTX {
        session: client_session,
    };
    Box::into_raw(Box::new(ctx))
}


#[no_mangle]
pub extern "C" fn mesalink_new<'a>(ctx_ptr: *mut MESALINK_CTX) -> *mut MESALINK<'a> {
    let ctx = unsafe {
        assert!(!ctx_ptr.is_null());
        &mut *ctx_ptr
    };

    let ssl = MESALINK {
        session: &mut ctx.session,
        socket: None,
        stream: None,
    };
    Box::into_raw(Box::new(ssl))
}

#[no_mangle]
pub extern "C" fn mesalink_set_fd(ssl_ptr: *mut MESALINK, fd: c_int) -> c_int {
    let ssl = unsafe {
        assert!(!ssl_ptr.is_null());
        &mut *ssl_ptr
    };
    let socket = unsafe { TcpStream::from_raw_fd(fd) };
    ssl.socket = Some(socket);
    let stream = rustls::Stream::new(ssl.session, ssl.socket.as_mut().unwrap());
    ssl.stream = Some(stream);
    0
}

#[no_mangle]
pub extern "C" fn mesalink_connect(ssl_ptr: *mut MESALINK) -> c_int {
    let ssl = unsafe {
        assert!(!ssl_ptr.is_null());
        &mut *ssl_ptr
    };
    match ssl.stream {
        Some(_) => 0,
        None => -1,
    }
}

#[no_mangle]
pub extern "C" fn mesalink_read(ssl_ptr: *mut MESALINK, buf_ptr: *mut c_uchar, buf_len: c_int) -> c_int {
    let ssl = unsafe {
        assert!(!ssl_ptr.is_null());
        &mut *ssl_ptr
    };
    let mut buf = unsafe { slice::from_raw_parts_mut(buf_ptr, buf_len as usize) };
    let stream = ssl.stream.as_mut().unwrap();
    let rc = stream.read(&mut buf);
    if rc.is_err() {
        println!("TLS read error: {:?}", rc);
        return -1;
    }
    rc.unwrap() as c_int
}

#[no_mangle]
pub extern "C" fn mesalink_write(ssl_ptr: *mut MESALINK, buf_ptr: *const c_uchar, buf_len: c_int) -> c_int {
    let ssl = unsafe {
        assert!(!ssl_ptr.is_null());
        &mut *ssl_ptr
    };
    let buf = unsafe { slice::from_raw_parts(buf_ptr, buf_len as usize) };
    let stream = ssl.stream.as_mut().unwrap();
    let rc = stream.write(buf);
    if rc.is_err() {
        println!("TLS write error: {:?}", rc);
        return -1;
    }
    rc.unwrap() as c_int
}


#[no_mangle]
pub extern "C" fn mesalink_CTX_free(ptr: *mut MESALINK_CTX) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        Box::from_raw(ptr);
    }
}

#[no_mangle]
pub extern "C" fn mesalink_free(ptr: *mut MESALINK) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        Box::from_raw(ptr);
    }
}
