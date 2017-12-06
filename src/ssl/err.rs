/* err.rs
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

use libc::{c_char, c_ulong, size_t, strncpy};
use std;
use std::cell::RefCell;
use std::collections::VecDeque;

const MAX_ERROR_SZ: size_t = 128;

#[repr(C)]
#[derive(Copy, Clone)]
pub enum ErrorCode {
    InappropriateMessage = 401,
    InappropriateHandshakeMessage = 402,
    CorruptMessage = 403,
    CorruptMessagePayload = 404,
    NoCertificatesPresented = 405,
    DecryptError = 406,
    PeerIncompatibleError = 407,
    PeerMisbehavedError = 408,
    AlertReceived = 409,
    WebPKIError = 410,
    InvalidSCT = 411,
    General = 412,
    FailedToGetCurrentTime = 413,
    __Nonexhaustive = 999,
}

thread_local! {
    pub static ERROR_QUEUE: RefCell<VecDeque<ErrorCode>> = RefCell::new(VecDeque::new());
}

impl ErrorCode {
    #[cfg(feature = "error_strings")]
    fn as_str(&self) -> &'static str {
        match *self {
            ErrorCode::InappropriateMessage => "InappropriateMessage",
            ErrorCode::InappropriateHandshakeMessage => "InappropriateHandshakeMessage",
            ErrorCode::CorruptMessage => "CorruptMessage",
            ErrorCode::CorruptMessagePayload => "CorruptMessagePayload",
            ErrorCode::NoCertificatesPresented => "NoCertificatesPresented",
            ErrorCode::DecryptError => "DecryptError",
            ErrorCode::PeerIncompatibleError => "PeerIncompatibleError",
            ErrorCode::PeerMisbehavedError => "PeerMisbehavedError",
            ErrorCode::AlertReceived => "AlertReceived",
            ErrorCode::WebPKIError => "WebPKIError",
            ErrorCode::InvalidSCT => "InvalidSCT",
            ErrorCode::General => "General",
            ErrorCode::FailedToGetCurrentTime => "FailedToGetCurrentTime",
            ErrorCode::__Nonexhaustive => unreachable!(),
        }
    }

    #[cfg(not(feature = "error_strings"))]
    fn as_str(&self) -> &'static str {
        "No support for error strings built-in"
    }
}

impl From<c_ulong> for ErrorCode {
    fn from(t:c_ulong) -> ErrorCode {
        let t = t as u32;
        assert!(t <= 999);
        unsafe { std::mem::transmute(t) }
    }
}

#[no_mangle]
pub extern "C" fn mesalink_ERR_load_error_strings() {
    // compatibility only
}

#[no_mangle]
pub extern "C" fn mesalink_ERR_free_error_strings() {
    // compatibility only
}

#[no_mangle]
pub extern "C" fn mesalink_ERR_error_string(errno: c_ulong, buf_ptr: *mut c_char) -> *const c_char {
    mesalink_ERR_error_string_n(errno, buf_ptr, MAX_ERROR_SZ)
}

#[no_mangle]
pub extern "C" fn mesalink_ERR_error_string_n(
    errno: c_ulong,
    buf_ptr: *mut c_char,
    buf_len: size_t,
) -> *const c_char {
    let src_ptr = mesalink_ERR_reason_error_string(errno);
    if !buf_ptr.is_null() {
        unsafe { strncpy(buf_ptr, src_ptr, buf_len) }
    } else {
        src_ptr
    }
}

#[no_mangle]
pub extern "C" fn mesalink_ERR_reason_error_string(errno: c_ulong) -> *const c_char {
    let error_code = ErrorCode::from(errno);
    error_code.as_str().as_ptr() as *const c_char
}

pub fn mesalink_push_error(err: ErrorCode) {
    ERROR_QUEUE.with(|f| {
        f.borrow_mut().push_back(err);
    });
}

#[no_mangle]
pub extern "C" fn mesalink_ERR_get_error() -> c_ulong {
    ERROR_QUEUE.with(|f| match f.borrow_mut().pop_front() {
        Some(e) => e as c_ulong,
        None => 0,
    })
}

#[no_mangle]
pub extern "C" fn mesalink_ERR_peek_last_error() -> c_ulong {
    ERROR_QUEUE.with(|f| match f.borrow().front() {
        Some(e) => *e as c_ulong,
        None => 0,
    })
}

#[no_mangle]
pub extern "C" fn mesalink_ERR_clear_error() {
    ERROR_QUEUE.with(|f| {
        f.borrow_mut().clear();
    });
}
