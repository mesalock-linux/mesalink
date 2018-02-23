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
//! This sub-module implements the error-handling APIs of OpenSSL. MesaLink
//! follows the same design as OpenSSL and uses a thread-local error queue. A
//! failed API call typically returns -1 and pushes an error code into the error
//! queue. The error code can be acquired by calling `ERR_get_error`.

use libc::{self, c_char, c_ulong, size_t};
use std;
use std::cell::RefCell;
use std::collections::VecDeque;
use rustls::TLSError;

#[doc(hidden)]
#[repr(C)]
#[derive(Copy, Clone)]
pub enum ErrorCode {
    // OpenSSL error codes
    SslErrorNone = 0,
    SslErrorZeroReturn = 6,
    SslErrorWantRead = 2,
    SslErrorWantWrite = 3,
    SslErrorWantConnect = 7,
    SslErrorWantAccept = 8,
    SslErrorSyscall = 5,
    SslErrorSsl = 85,
    // MesaLink build-in error codes
    NullPointerException = 0x2001,
    MalformedObject,
    BadFileName,
    BadKey,
    CertKeyMismatch,
    // std::io error codes
    NotFound = 0x3001,
    PermissionDenied,
    ConnectionRefused,
    ConnectionReset,
    ConnectionAborted,
    NotConnected,
    AddrInUse,
    AddrNotAvailable,
    BrokenPipe,
    AlreadyExists,
    WouldBlock,
    InvalidInput,
    InvalidData,
    TimedOut,
    WriteZero,
    Interrupted,
    Other,
    UnexpectedEof,
    // Rustls error codes
    InappropriateMessage = 0x4001,
    InappropriateHandshakeMessage,
    CorruptMessage,
    CorruptMessagePayload,
    NoCertificatesPresented,
    DecryptError,
    PeerIncompatibleError,
    PeerMisbehavedError,
    AlertReceived,
    WebPKIError,
    InvalidSCT,
    General,
    FailedToGetCurrentTime,
    InvalidDNSName,
    HandshakeNotComplete,
    PeerSentOversizedRecord,

    __Nonexhaustive = 0xFFFF,
}

thread_local! {
    static ERROR_QUEUE: RefCell<VecDeque<ErrorCode>> = RefCell::new(VecDeque::new());
}

impl ErrorCode {
    #[cfg(feature = "error_strings")]
    fn as_str(&self) -> &'static [u8] {
        match *self {
            // OpenSSL error codes
            ErrorCode::SslErrorNone => b"No error\0",
            ErrorCode::SslErrorZeroReturn => b"SSL error: zero return\0",
            ErrorCode::SslErrorWantRead => b"SSL error: want read\0",
            ErrorCode::SslErrorWantWrite => b"SSL error: want write\0",
            ErrorCode::SslErrorWantAccept => b"SSL error: want accept\0",
            ErrorCode::SslErrorWantConnect => b"SSL error: want connect\0",
            ErrorCode::SslErrorSyscall => b"SSL error: syscall\0",
            ErrorCode::SslErrorSsl => b"SSL error: protocol\0",
            // MesaLink build-in error codes
            ErrorCode::NullPointerException => b"Null pointer exception\0",
            ErrorCode::MalformedObject => b"Malformed object\0",
            ErrorCode::BadFileName => b"Bad file name\0",
            ErrorCode::BadKey => b"Bad key\0",
            ErrorCode::CertKeyMismatch => b"Certificate and private key do not match\0",
            // std::io error strings
            ErrorCode::NotFound => b"File not found\0",
            ErrorCode::PermissionDenied => b"Permission denied\0",
            ErrorCode::ConnectionRefused => b"Connection refused\0",
            ErrorCode::ConnectionReset => b"Connection reset\0",
            ErrorCode::ConnectionAborted => b"Connection aborted\0",
            ErrorCode::NotConnected => b"Not connected\0",
            ErrorCode::AddrInUse => b"Address in use\0",
            ErrorCode::AddrNotAvailable => b"Address not available\0",
            ErrorCode::BrokenPipe => b"Broken pipe\0",
            ErrorCode::AlreadyExists => b"File already exists\0",
            ErrorCode::WouldBlock => b"Would block\0",
            ErrorCode::InvalidInput => b"Invalid input\0",
            ErrorCode::InvalidData => b"Invalid data\0",
            ErrorCode::TimedOut => b"Timeout\0",
            ErrorCode::WriteZero => b"Write zero\0",
            ErrorCode::Interrupted => b"Interrupted\0",
            ErrorCode::Other => b"Other IO issues\0",
            ErrorCode::UnexpectedEof => b"Unexpected EOF\0",
            // rustls error strings
            ErrorCode::InappropriateMessage => b"Inappropriate message\0",
            ErrorCode::InappropriateHandshakeMessage => b"Inappropriate handshake message\0",
            ErrorCode::CorruptMessage => b"Corrupt message\0",
            ErrorCode::CorruptMessagePayload => b"Corrupt message payload\0",
            ErrorCode::NoCertificatesPresented => b"No certificates presented\0",
            ErrorCode::DecryptError => b"Decrypt error\0",
            ErrorCode::PeerIncompatibleError => b"Peer incompatible error\0",
            ErrorCode::PeerMisbehavedError => b"Peer misbehaved error\0",
            ErrorCode::AlertReceived => b"Alert received\0",
            ErrorCode::WebPKIError => b"Web PKI error\0",
            ErrorCode::InvalidSCT => b"Invalid SCT\0",
            ErrorCode::General => b"General\0",
            ErrorCode::FailedToGetCurrentTime => b"Failed to get current time\0",
            ErrorCode::InvalidDNSName => b"Invalid DNS name\0",
            ErrorCode::HandshakeNotComplete => b"Handshake not complete\0",
            ErrorCode::PeerSentOversizedRecord => b"Peer sent oversized record\0",
            ErrorCode::__Nonexhaustive => b"Invalid error code\0",
        }
    }

    #[cfg(not(feature = "error_strings"))]
    fn as_str(&self) -> &'static [u8] {
        b"No support for error strings built-in\0"
    }
}

impl From<u32> for ErrorCode {
    fn from(e: u32) -> ErrorCode {
        unsafe { std::mem::transmute::<u32, ErrorCode>(e) }
    }
}

impl From<u64> for ErrorCode {
    fn from(e: u64) -> ErrorCode {
        let e = e as u32;
        ErrorCode::from(e)
    }
}

impl From<std::io::Error> for ErrorCode {
    fn from(e: std::io::Error) -> ErrorCode {
        let errno: u8 = unsafe { std::mem::transmute::<std::io::ErrorKind, u8>(e.kind()) };
        ErrorCode::from(0x300 + errno as u32 + 1)
    }
}

#[allow(unused_variables)]
impl From<TLSError> for ErrorCode {
    fn from(e: TLSError) -> ErrorCode {
        match e {
            TLSError::InappropriateMessage {
                expect_types,
                got_type,
            } => ErrorCode::InappropriateMessage,
            TLSError::InappropriateHandshakeMessage {
                expect_types,
                got_type,
            } => ErrorCode::InappropriateHandshakeMessage,
            TLSError::CorruptMessage => ErrorCode::CorruptMessage,
            TLSError::CorruptMessagePayload(_) => ErrorCode::CorruptMessagePayload, // TODO: extend to cover more specific types
            TLSError::NoCertificatesPresented => ErrorCode::NoCertificatesPresented,
            TLSError::DecryptError => ErrorCode::DecryptError,
            TLSError::PeerIncompatibleError(_) => ErrorCode::PeerIncompatibleError,
            TLSError::PeerMisbehavedError(_) => ErrorCode::PeerMisbehavedError,
            TLSError::AlertReceived(_) => ErrorCode::AlertReceived, // TODO: extend to cover more specific alerts
            TLSError::WebPKIError(_) => ErrorCode::WebPKIError,
            TLSError::InvalidSCT(_) => ErrorCode::InvalidSCT,
            TLSError::General(_) => ErrorCode::General,
            TLSError::FailedToGetCurrentTime => ErrorCode::FailedToGetCurrentTime,
            TLSError::InvalidDNSName(_) => ErrorCode::InvalidDNSName,
            TLSError::HandshakeNotComplete => ErrorCode::HandshakeNotComplete,
            TLSError::PeerSentOversizedRecord => ErrorCode::PeerSentOversizedRecord,
        }
    }
}

/// `ERR_load_error_strings` - compatibility only
///
/// ```
/// #include <mesalink/openssl/err.h>
///
/// void SSL_load_error_strings(void);
/// ```
#[no_mangle]
pub extern "C" fn mesalink_ERR_load_error_strings() {
    // compatibility only
}

/// `ERR_free_error_strings` - compatibility only
///
/// ```
/// #include <mesalink/openssl/err.h>
///
/// void SSL_free_error_strings(void);
/// ```
#[no_mangle]
pub extern "C" fn mesalink_ERR_free_error_strings() {
    // compatibility only
}

/// `ERR_error_string_n` - generate a human-readable string representing the
/// error code `e`, and places `len` bytes at `buf`. Note that this function is
/// not thread-safe and does no checks on the size of the buffer.
///
/// ```
/// #include <mesalink/openssl/err.h>
///
/// void ERR_error_string_n(unsigned long e, char *buf, size_t len);
/// ```
#[no_mangle]
pub extern "C" fn mesalink_ERR_error_string_n(
    errno: c_ulong,
    buf_ptr: *mut c_char,
    buf_len: size_t,
) -> *const c_char {
    let src_ptr = mesalink_ERR_reason_error_string(errno);
    if !buf_ptr.is_null() {
        unsafe { libc::strncpy(buf_ptr, src_ptr, buf_len) }
    } else {
        src_ptr
    }
}

/// `ERR_error_reason_error_string` - return a human-readable string representing
/// the error code e. This API does not allocate additional memory.
///
/// ```
/// #include <mesalink/openssl/err.h>
///
/// const char *ERR_reason_error_string(unsigned long e);
/// ```
#[no_mangle]
pub extern "C" fn mesalink_ERR_reason_error_string(errno: c_ulong) -> *const c_char {
    let error_code = ErrorCode::from(errno);
    error_code.as_str().as_ptr() as *const c_char
}

#[doc(hidden)]
pub fn mesalink_push_error(err: ErrorCode) {
    ERROR_QUEUE.with(|f| {
        f.borrow_mut().push_back(err);
    });
}

/// `ERR_get_error` - return the earliest error code from the thread's error
/// queue and removes the entry. This function can be called repeatedly until
/// there are no more error codes to return.
///
/// ```
/// #include <mesalink/openssl/err.h>
///
/// unsigned long ERR_get_error(void);
/// ```
#[no_mangle]
pub extern "C" fn mesalink_ERR_get_error() -> c_ulong {
    ERROR_QUEUE.with(|f| match f.borrow_mut().pop_front() {
        Some(e) => e as c_ulong,
        None => 0,
    })
}

/// `ERR_peek_last_error` - return the latest error code from the thread's error
/// queue without modifying it.
///
/// ```
/// #include <mesalink/openssl/err.h>
///
/// unsigned long ERR_peek_last_error(void);
/// ```
#[no_mangle]
pub extern "C" fn mesalink_ERR_peek_last_error() -> c_ulong {
    ERROR_QUEUE.with(|f| match f.borrow().front() {
        Some(e) => *e as c_ulong,
        None => 0,
    })
}

/// `ERR_clear_error` - empty the current thread's error queue.
///
/// ```
/// #include <mesalink/openssl/err.h>
///
/// void ERR_clear_error(void);
/// ```
#[no_mangle]
pub extern "C" fn mesalink_ERR_clear_error() {
    ERROR_QUEUE.with(|f| {
        f.borrow_mut().clear();
    });
}

/// `ERR_print_errors_fp` - a convenience function that prints the error
/// strings for all errors that OpenSSL has recorded to `fp`, thus emptying the
/// error queue.
///
/// ```
/// #include <mesalink/openssl/err.h>
///
/// void ERR_print_errors_fp(FILE *fp);
/// ```
#[no_mangle]
pub extern "C" fn mesalink_ERR_print_errors_fp(fp: *mut libc::FILE) {
    let tid = std::thread::current().id();
    ERROR_QUEUE.with(|f| {
        let mut queue = f.borrow_mut();
        for error_code in queue.drain(0..) {
            let message = mesalink_ERR_reason_error_string(error_code as c_ulong);
            let _ = unsafe {
                libc::fprintf(
                    fp,
                    "[thread: %u]:[error code: 0x%x]:[%s]\n".as_ptr() as *const c_char,
                    tid,
                    error_code,
                    message,
                )
            };
        }
    });
}
