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


use libc::{c_char, c_ulong};

#[cfg(feature = "error_strings")]
use std::collections::HashMap;

#[cfg(not(feature = "error_strings"))]
use std::ffi::CString;

pub enum ErrorCode {
    InappropriateMessage            = -401,
    InappropriateHandshakeMessage   = -402,
    CorruptMessage                  = -403,
    CorruptMessagePayload           = -404,
    NoCertificatesPresented         = -405,
    DecryptError                    = -406,
    PeerIncompatibleError           = -407,
    PeerMisbehavedError             = -408,    
    AlertReceived                   = -409,
    WebPKIError                     = -410,
    InvalidSCT                      = -411,
    General                         = -412,
    FailedToGetCurrentTime          = -413,
}

#[cfg(feature = "error_strings")]
lazy_static! {
    static ref ERR_MAP: HashMap<c_ulong, &'static str> = {
        let mut m = HashMap::new();
        let _ = m.insert(ErrorCode::InappropriateMessage as c_ulong, "InappropriateMessage");
        let _ = m.insert(ErrorCode::InappropriateHandshakeMessage as c_ulong, "InappropriateHandshakeMessage");
        let _ = m.insert(ErrorCode::CorruptMessage as c_ulong, "CorruptMessage");
        let _ = m.insert(ErrorCode::CorruptMessagePayload as c_ulong, "CorruptMessagePayload");
        let _ = m.insert(ErrorCode::NoCertificatesPresented as c_ulong, "NoCertificatesPresented");
        let _ = m.insert(ErrorCode::DecryptError as c_ulong, "DecryptError");
        let _ = m.insert(ErrorCode::PeerIncompatibleError as c_ulong, "PeerIncompatibleError");
        let _ = m.insert(ErrorCode::PeerMisbehavedError as c_ulong, "PeerMisbehavedError");
        let _ = m.insert(ErrorCode::AlertReceived as c_ulong, "AlertReceived");
        let _ = m.insert(ErrorCode::WebPKIError as c_ulong, "WebPKIError");
        let _ = m.insert(ErrorCode::InvalidSCT as c_ulong, "InvalidSCT");
        let _ = m.insert(ErrorCode::General as c_ulong, "General");
        let _ = m.insert(ErrorCode::FailedToGetCurrentTime as c_ulong, "FailedToGetCurrentTime");
        m
    };
}

#[no_mangle]
pub extern "C" fn mesalink_ERR_load_error_strings() {
    /* compatibility only */
}

#[no_mangle]
pub extern "C" fn mesalink_ERR_free_error_strings() {
    /* compatibility only */
}

#[no_mangle]
pub extern "C" fn mesalink_ERR_reason_error_string(_errno: c_ulong) -> *const c_char  {
    match () {
        #[cfg(feature = "error_strings")]
        () => ERR_MAP.get(&_errno).unwrap().as_ptr() as *const c_char,
        #[cfg(not(feature = "error_strings"))]
        () => CString::new("No support for error strings builtin").unwrap().into_raw(),
    }
}