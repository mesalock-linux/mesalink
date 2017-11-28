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

use libc::{c_char, c_ulong, size_t};
use libc::strncpy;
use std::ffi::CString;
use std::cell::RefCell;
use std::collections::VecDeque;

const MAX_ERROR_SZ: size_t = 128;

#[repr(C)]
#[derive(Copy, Clone)]
pub enum ErrorCode {
    InappropriateMessage = -401,
    InappropriateHandshakeMessage = -402,
    CorruptMessage = -403,
    CorruptMessagePayload = -404,
    NoCertificatesPresented = -405,
    DecryptError = -406,
    PeerIncompatibleError = -407,
    PeerMisbehavedError = -408,
    AlertReceived = -409,
    WebPKIError = -410,
    InvalidSCT = -411,
    General = -412,
    FailedToGetCurrentTime = -413,
}

thread_local! {
    pub static ERROR_QUEUE: RefCell<VecDeque<ErrorCode>> = RefCell::new(VecDeque::new());
}

#[cfg(feature = "error_strings")]
lazy_static! {
    static ref INAPPROPRIATE_MESSAGE: &'static str = "InappropriateMessage";
    static ref INAPPROPRIATE_HANDSHAKE_MESSAGE: &'static str = "InappropriateHandshakeMessage";
    static ref CORRUPT_MESSAGE: &'static str = "CorruptMessage";
    static ref CORRUPT_MESSAGE_PAYLOAD: &'static str = "CorruptMessagePayload";
    static ref NO_CERTIFICATES_PRESENTED: &'static str = "NoCertificatesPresented";
    static ref DECRYPT_ERROR: &'static str = "DecryptError";
    static ref PEER_INCOMPATIBLE_ERROR: &'static str = "PeerIncompatibleError";
    static ref PEER_MISBEHAVED_ERROR: &'static str = "PeerMisbehavedError";
    static ref ALERT_RECEIVED: &'static str = "AlertReceived";
    static ref WEBPKI_ERROR: &'static str = "WebPKIError";
    static ref INVALID_SCT: &'static str = "InvalidSCT";
    static ref GENERAL: &'static str = "General";
    static ref FAILED_TO_GET_CURRENT_TIME: &'static str = "FailedToGetCurrentTime";
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
    if buf_ptr.is_null() {
        src_ptr
    } else {
        unsafe { strncpy(buf_ptr, src_ptr, buf_len) }
    }
}

#[no_mangle]
pub extern "C" fn mesalink_ERR_reason_error_string(errno: c_ulong) -> *const c_char {
    match () {
        #[cfg(feature = "error_strings")]
        () => match errno {
            x if x == ErrorCode::InappropriateMessage as c_ulong => {
                INAPPROPRIATE_MESSAGE.as_ptr() as *const c_char
            }
            x if x == ErrorCode::InappropriateHandshakeMessage as c_ulong => {
                INAPPROPRIATE_HANDSHAKE_MESSAGE.as_ptr() as *const c_char
            }
            x if x == ErrorCode::CorruptMessage as c_ulong => {
                CORRUPT_MESSAGE.as_ptr() as *const c_char
            }
            x if x == ErrorCode::CorruptMessagePayload as c_ulong => {
                CORRUPT_MESSAGE_PAYLOAD.as_ptr() as *const c_char
            }
            x if x == ErrorCode::NoCertificatesPresented as c_ulong => {
                NO_CERTIFICATES_PRESENTED.as_ptr() as *const c_char
            }
            x if x == ErrorCode::DecryptError as c_ulong => DECRYPT_ERROR.as_ptr() as *const c_char,
            x if x == ErrorCode::PeerIncompatibleError as c_ulong => {
                PEER_INCOMPATIBLE_ERROR.as_ptr() as *const c_char
            }
            x if x == ErrorCode::PeerMisbehavedError as c_ulong => {
                PEER_MISBEHAVED_ERROR.as_ptr() as *const c_char
            }
            x if x == ErrorCode::AlertReceived as c_ulong => {
                ALERT_RECEIVED.as_ptr() as *const c_char
            }
            x if x == ErrorCode::WebPKIError as c_ulong => WEBPKI_ERROR.as_ptr() as *const c_char,
            x if x == ErrorCode::InvalidSCT as c_ulong => INVALID_SCT.as_ptr() as *const c_char,
            x if x == ErrorCode::General as c_ulong => GENERAL.as_ptr() as *const c_char,
            x if x == ErrorCode::FailedToGetCurrentTime as c_ulong => {
                FAILED_TO_GET_CURRENT_TIME.as_ptr() as *const c_char
            }
            _ => CString::new("Unknown error").unwrap().into_raw(),
        },
        #[cfg(not(feature = "error_strings"))]
        () => CString::new("No support for error strings builtin")
            .unwrap()
            .into_raw(),
    }
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
