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
//! failed API call typically returns -1/0 and pushes an error code into the error
//! queue. The error code can be acquired by calling `ERR_get_error` or
//! `SSL_get_error`.

use libc::{self, c_char, c_ulong, size_t};
use std;
use std::io::ErrorKind;
use std::cell::RefCell;
use std::collections::VecDeque;
use rustls::TLSError;
use rustls::internal::msgs::enums::{AlertDescription, ContentType};
use webpki;

/// MesaLink always use a 32-bit unsigned integer to represent error codes.
///
/// ```
///  7 6 5 4 3 2 1 0 7 6 5 4 3 2 1 0 7 6 5 4 3 2 1 0 7 6 5 4 3 2 1 0
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     source    |     unused    |     errno     |   sub errno   |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// The highest 8 bits represent the source of the error. 0x1: the error comes
/// from MesaLink itself. For example, a NULL or malformed SSL_CTX pointer is
/// used. 0x2: the error comes from system I/O. For example, a certificate file
/// is not found. 0x3: the error is TLS specific. For example, the remote server
/// does not have a valid certifcate. The lowest 16 bits represent the specific
/// error, including 8 bites error number and 8 bits optional sub error number.
/// For a human-readable decription of an ErrorCode, call `ERR_reason_error_string`.
#[repr(C)]
#[derive(PartialEq, Clone, Copy)]
#[cfg_attr(feature = "error_strings", derive(EnumToStr))]
pub enum ErrorCode {
    // OpenSSL error codes
    MesalinkErrorNone = 0,
    MesalinkErrorZeroReturn = 1,
    MesalinkErrorWantRead = 2,
    MesalinkErrorWantWrite = 3,
    MesalinkErrorWantConnect = 7,
    MesalinkErrorWantAccept = 8,
    MesalinkErrorSyscall = 5,
    MesalinkErrorSsl = 0x55,
    MesalinkErrorNullPointer = 0xe0,
    MesalinkErrorMalformedObject = 0xe1,
    // Rust IO ErrorKind codes
    IoErrorNotFound = 0x02000001,
    IoErrorPermissionDenied = 0x02000002,
    IoErrorConnectionRefused = 0x02000003,
    IoErrorConnectionReset = 0x02000004,
    IoErrorConnectionAborted = 0x02000005,
    IoErrorNotConnected = 0x02000006,
    IoErrorAddrInUse = 0x02000007,
    IoErrorAddrNotAvailable = 0x02000008,
    IoErrorBrokenPipe = 0x02000009,
    IoErrorAlreadyExists = 0x0200000a,
    IoErrorWouldBlock = 0x0200000b,
    IoErrorInvalidInput = 0x0200000c,
    IoErrorInvalidData = 0x0200000d,
    IoErrorTimedOut = 0x0200000e,
    IoErrorWriteZero = 0x0200000f,
    IoErrorInterrupted = 0x02000010,
    IoErrorOther = 0x02000011,
    IoErrorUnexpectedEof = 0x02000012,
    // TLS error codes
    TLSErrorInappropriateMessage = 0x03000100,
    TLSErrorInappropriateHandshakeMessage = 0x03000200,
    TLSErrorCorruptMessage = 0x03000300,
    TLSErrorCorruptMessagePayload = 0x03000400,
    TLSErrorCorruptMessagePayloadAlert = 0x03000401,
    TLSErrorCorruptMessagePayloadChangeCipherSpec = 0x03000402,
    TLSErrorCorruptMessagePayloadHandshake = 0x03000403,
    TLSErrorNoCertificatesPresented = 0x03000500,
    TLSErrorDecryptError = 0x03000600,
    TLSErrorPeerIncompatibleError = 0x03000700,
    TLSErrorPeerMisbehavedError = 0x03000800,
    TLSErrorAlertReceivedCloseNotify = 0x03000901,
    TLSErrorAlertReceivedUnexpectedMessage = 0x03000902,
    TLSErrorAlertReceivedBadRecordMac = 0x03000903,
    TLSErrorAlertReceivedDecryptionFailed = 0x03000904,
    TLSErrorAlertReceivedRecordOverflow = 0x03000905,
    TLSErrorAlertReceivedDecompressionFailure = 0x03000906,
    TLSErrorAlertReceivedHandshakeFailure = 0x03000907,
    TLSErrorAlertReceivedNoCertificate = 0x03000908,
    TLSErrorAlertReceivedBadCertificate = 0x03000909,
    TLSErrorAlertReceivedUnsupportedCertificate = 0x0300090a,
    TLSErrorAlertReceivedCertificateRevoked = 0x0300090b,
    TLSErrorAlertReceivedCertificateExpired = 0x0300090c,
    TLSErrorAlertReceivedCertificateUnknown = 0x0300090d,
    TLSErrorAlertReceivedIllegalParameter = 0x0300090e,
    TLSErrorAlertReceivedUnknownCA = 0x0300090f,
    TLSErrorAlertReceivedAccessDenied = 0x03000910,
    TLSErrorAlertReceivedDecodeError = 0x03000911,
    TLSErrorAlertReceivedDecryptError = 0x03000912,
    TLSErrorAlertReceivedExportRestriction = 0x03000913,
    TLSErrorAlertReceivedProtocolVersion = 0x03000914,
    TLSErrorAlertReceivedInsufficientSecurity = 0x03000915,
    TLSErrorAlertReceivedInternalError = 0x03000916,
    TLSErrorAlertReceivedInappropriateFallback = 0x03000917,
    TLSErrorAlertReceivedUserCanceled = 0x03000918,
    TLSErrorAlertReceivedNoRenegotiation = 0x03000919,
    TLSErrorAlertReceivedMissingExtension = 0x0300091a,
    TLSErrorAlertReceivedUnsupportedExtension = 0x0300091b,
    TLSErrorAlertReceivedCertificateUnobtainable = 0x0300091c,
    TLSErrorAlertReceivedUnrecognisedName = 0x0300091d,
    TLSErrorAlertReceivedBadCertificateStatusResponse = 0x0300091e,
    TLSErrorAlertReceivedBadCertificateHashValue = 0x0300091f,
    TLSErrorAlertReceivedUnknownPSKIdentity = 0x03000920,
    TLSErrorAlertReceivedCertificateRequired = 0x03000921,
    TLSErrorAlertReceivedNoApplicationProtocol = 0x03000922,
    TLSErrorAlertReceivedUnknown = 0x030009ff,
    TLSErrorWebpkiBadDER = 0x03000a01,
    TLSErrorWebpkiBadDERTime = 0x03000a02,
    TLSErrorWebpkiCAUsedAsEndEntity = 0x03000a03,
    TLSErrorWebpkiCertExpired = 0x03000a04,
    TLSErrorWebpkiCertNotValidForName = 0x03000a05,
    TLSErrorWebpkiCertNotValidYet = 0x03000a06,
    TLSErrorWebpkiEndEntityUsedAsCA = 0x03000a07,
    TLSErrorWebpkiExtensionValueInvalid = 0x03000a08,
    TLSErrorWebpkiInvalidCertValidity = 0x03000a09,
    TLSErrorWebpkiInvalidSignatureForPublicKey = 0x03000a0a,
    TLSErrorWebpkiNameConstraintViolation = 0x03000a0b,
    TLSErrorWebpkiPathLenConstraintViolated = 0x03000a0c,
    TLSErrorWebpkiSignatureAlgorithmMismatch = 0x03000a0d,
    TLSErrorWebpkiRequiredEKUNotFound = 0x03000a0e,
    TLSErrorWebpkiUnknownIssuer = 0x03000a0f,
    TLSErrorWebpkiUnsupportedCertVersion = 0x03000a10,
    TLSErrorWebpkiUnsupportedCriticalExtension = 0x03000a11,
    TLSErrorWebpkiUnsupportedSignatureAlgorithmForPublicKey = 0x03000a12,
    TLSErrorWebpkiUnsupportedSignatureAlgorithm = 0x03000a13,
    TLSErrorInvalidSCT = 0x03000b00,
    TLSErrorGeneral = 0x03000c00,
    TLSErrorFailedToGetCurrentTime = 0x03000d00,
    TLSErrorInvalidDNSName = 0x03000e00,
    TLSErrorHandshakeNotComplete = 0x03000f00,
    TLSErrorPeerSentOversizedRecord = 0x03001000,
    UndefinedError = 0xeeeeeeee,
}

#[doc(hidden)]
impl ErrorCode {
    #[cfg(feature="error_strings")]
    pub fn as_str(&self) -> &'static [u8] {
        self.enum_to_str()
    }

    #[cfg(not(feature="error_strings"))]
    pub fn as_str(&self) -> &'static [u8] {
        b"Error string not built-in\0"
    }
}

#[doc(hidden)]
impl Default for ErrorCode {
    fn default() -> ErrorCode {
        ErrorCode::MesalinkErrorNone
    }
}

#[doc(hidden)]
impl From<u32> for ErrorCode {
    fn from(e: u32) -> ErrorCode {
        unsafe { std::mem::transmute::<u32, ErrorCode>(e) }
    }
}

#[doc(hidden)]
impl From<u64> for ErrorCode {
    fn from(e: u64) -> ErrorCode {
        let e = e as u32;
        unsafe { std::mem::transmute::<u32, ErrorCode>(e) }
    }
}

#[doc(hidden)]
trait MesalinkErrorType {}

#[doc(hidden)]
#[repr(C)]
#[derive(PartialEq, Clone, Debug)]
pub enum MesalinkBuiltinError {
    ErrorNone,
    ErrorZeroReturn,
    ErrorWantRead,
    ErrorWantWrite,
    ErrorWantConnect,
    ErrorWantAccept,
    ErrorSyscall,
    ErrorSsl,
    ErrorNullPointer,
    ErrorMalformedObject,
}

impl MesalinkErrorType for MesalinkBuiltinError {}
impl MesalinkErrorType for TLSError {}
impl MesalinkErrorType for std::io::Error {}

#[doc(hidden)]
impl<'a> From<&'a MesalinkBuiltinError> for ErrorCode {
    fn from(e: &'a MesalinkBuiltinError) -> ErrorCode {
        match e {
            &MesalinkBuiltinError::ErrorNone => ErrorCode::MesalinkErrorNone,
            &MesalinkBuiltinError::ErrorZeroReturn => ErrorCode::MesalinkErrorZeroReturn,
            &MesalinkBuiltinError::ErrorWantRead => ErrorCode::MesalinkErrorWantRead,
            &MesalinkBuiltinError::ErrorWantWrite => ErrorCode::MesalinkErrorWantWrite,
            &MesalinkBuiltinError::ErrorWantConnect => ErrorCode::MesalinkErrorWantConnect,
            &MesalinkBuiltinError::ErrorWantAccept => ErrorCode::MesalinkErrorWantAccept,
            &MesalinkBuiltinError::ErrorSyscall => ErrorCode::MesalinkErrorSyscall,
            &MesalinkBuiltinError::ErrorSsl => ErrorCode::MesalinkErrorSsl,
            &MesalinkBuiltinError::ErrorNullPointer => ErrorCode::MesalinkErrorNullPointer,
            &MesalinkBuiltinError::ErrorMalformedObject => ErrorCode::MesalinkErrorMalformedObject,
        }
    }
}

#[doc(hidden)]
impl<'a> From<&'a std::io::Error> for ErrorCode {
    fn from(e: &'a std::io::Error) -> ErrorCode {
        match e.kind() {
            ErrorKind::NotFound => ErrorCode::IoErrorNotFound,
            ErrorKind::PermissionDenied => ErrorCode::IoErrorPermissionDenied,
            ErrorKind::ConnectionRefused => ErrorCode::IoErrorConnectionRefused,
            ErrorKind::ConnectionReset => ErrorCode::IoErrorConnectionReset,
            ErrorKind::ConnectionAborted => ErrorCode::IoErrorConnectionAborted,
            ErrorKind::NotConnected => ErrorCode::IoErrorNotConnected,
            ErrorKind::AddrInUse => ErrorCode::IoErrorAddrInUse,
            ErrorKind::AddrNotAvailable => ErrorCode::IoErrorAddrNotAvailable,
            ErrorKind::BrokenPipe => ErrorCode::IoErrorBrokenPipe,
            ErrorKind::AlreadyExists => ErrorCode::IoErrorAlreadyExists,
            ErrorKind::WouldBlock => ErrorCode::IoErrorWouldBlock,
            ErrorKind::InvalidInput => ErrorCode::IoErrorInvalidInput,
            ErrorKind::InvalidData => ErrorCode::IoErrorInvalidData,
            ErrorKind::TimedOut => ErrorCode::IoErrorTimedOut,
            ErrorKind::WriteZero => ErrorCode::IoErrorWriteZero,
            ErrorKind::Interrupted => ErrorCode::IoErrorInterrupted,
            ErrorKind::Other => ErrorCode::IoErrorOther,
            ErrorKind::UnexpectedEof => ErrorCode::IoErrorUnexpectedEof,
            _ => ErrorCode::UndefinedError,
        }
    }
}

#[doc(hidden)]
#[allow(unused_variables)]
impl<'a> From<&'a TLSError> for ErrorCode {
    fn from(e: &'a TLSError) -> ErrorCode {
        match e {
            &TLSError::InappropriateMessage {
                ref expect_types,
                ref got_type,
            } => ErrorCode::TLSErrorInappropriateMessage,
            &TLSError::InappropriateHandshakeMessage {
                ref expect_types,
                ref got_type,
            } => ErrorCode::TLSErrorInappropriateHandshakeMessage,
            &TLSError::CorruptMessage => ErrorCode::TLSErrorCorruptMessage,
            &TLSError::CorruptMessagePayload(c) => match c {
                ContentType::Alert => ErrorCode::TLSErrorCorruptMessagePayloadAlert,
                ContentType::ChangeCipherSpec => {
                    ErrorCode::TLSErrorCorruptMessagePayloadChangeCipherSpec
                }
                ContentType::Handshake => ErrorCode::TLSErrorCorruptMessagePayloadHandshake,
                _ => ErrorCode::TLSErrorCorruptMessagePayload,
            },
            &TLSError::NoCertificatesPresented => ErrorCode::TLSErrorNoCertificatesPresented,
            &TLSError::DecryptError => ErrorCode::TLSErrorDecryptError,
            &TLSError::PeerIncompatibleError(_) => ErrorCode::TLSErrorPeerIncompatibleError,
            &TLSError::PeerMisbehavedError(_) => ErrorCode::TLSErrorPeerMisbehavedError,
            &TLSError::AlertReceived(alert) => match alert {
                AlertDescription::CloseNotify => ErrorCode::TLSErrorAlertReceivedCloseNotify,
                AlertDescription::UnexpectedMessage => {
                    ErrorCode::TLSErrorAlertReceivedUnexpectedMessage
                }
                AlertDescription::BadRecordMac => ErrorCode::TLSErrorAlertReceivedBadRecordMac,
                AlertDescription::DecryptionFailed => ErrorCode::TLSErrorAlertReceivedDecryptionFailed,
                AlertDescription::RecordOverflow => ErrorCode::TLSErrorAlertReceivedRecordOverflow,
                AlertDescription::DecompressionFailure => {
                    ErrorCode::TLSErrorAlertReceivedDecompressionFailure
                }
                AlertDescription::HandshakeFailure => ErrorCode::TLSErrorAlertReceivedHandshakeFailure,
                AlertDescription::NoCertificate => ErrorCode::TLSErrorAlertReceivedNoCertificate,
                AlertDescription::BadCertificate => ErrorCode::TLSErrorAlertReceivedBadCertificate,
                AlertDescription::UnsupportedCertificate => {
                    ErrorCode::TLSErrorAlertReceivedUnsupportedCertificate
                }
                AlertDescription::CertificateRevoked => {
                    ErrorCode::TLSErrorAlertReceivedCertificateRevoked
                }
                AlertDescription::CertificateExpired => {
                    ErrorCode::TLSErrorAlertReceivedCertificateExpired
                }
                AlertDescription::CertificateUnknown => {
                    ErrorCode::TLSErrorAlertReceivedCertificateUnknown
                }
                AlertDescription::IllegalParameter => ErrorCode::TLSErrorAlertReceivedIllegalParameter,
                AlertDescription::UnknownCA => ErrorCode::TLSErrorAlertReceivedUnknownCA,
                AlertDescription::AccessDenied => ErrorCode::TLSErrorAlertReceivedAccessDenied,
                AlertDescription::DecodeError => ErrorCode::TLSErrorAlertReceivedDecodeError,
                AlertDescription::DecryptError => ErrorCode::TLSErrorAlertReceivedDecryptError,
                AlertDescription::ExportRestriction => {
                    ErrorCode::TLSErrorAlertReceivedExportRestriction
                }
                AlertDescription::ProtocolVersion => ErrorCode::TLSErrorAlertReceivedProtocolVersion,
                AlertDescription::InsufficientSecurity => {
                    ErrorCode::TLSErrorAlertReceivedInsufficientSecurity
                }
                AlertDescription::InternalError => ErrorCode::TLSErrorAlertReceivedInternalError,
                AlertDescription::InappropriateFallback => {
                    ErrorCode::TLSErrorAlertReceivedInappropriateFallback
                }
                AlertDescription::UserCanceled => ErrorCode::TLSErrorAlertReceivedUserCanceled,
                AlertDescription::NoRenegotiation => ErrorCode::TLSErrorAlertReceivedNoRenegotiation,
                AlertDescription::MissingExtension => ErrorCode::TLSErrorAlertReceivedMissingExtension,
                AlertDescription::UnsupportedExtension => {
                    ErrorCode::TLSErrorAlertReceivedUnsupportedExtension
                }
                AlertDescription::CertificateUnobtainable => {
                    ErrorCode::TLSErrorAlertReceivedCertificateUnobtainable
                }
                AlertDescription::UnrecognisedName => ErrorCode::TLSErrorAlertReceivedUnrecognisedName,
                AlertDescription::BadCertificateStatusResponse => {
                    ErrorCode::TLSErrorAlertReceivedBadCertificateStatusResponse
                }
                AlertDescription::BadCertificateHashValue => {
                    ErrorCode::TLSErrorAlertReceivedBadCertificateHashValue
                }
                AlertDescription::UnknownPSKIdentity => {
                    ErrorCode::TLSErrorAlertReceivedUnknownPSKIdentity
                }
                AlertDescription::CertificateRequired => {
                    ErrorCode::TLSErrorAlertReceivedCertificateRequired
                }
                AlertDescription::NoApplicationProtocol => {
                    ErrorCode::TLSErrorAlertReceivedNoApplicationProtocol
                }
                AlertDescription::Unknown(_) => ErrorCode::TLSErrorAlertReceivedUnknown,
            },
            &TLSError::WebPKIError(pki_err) => match pki_err {
                webpki::Error::BadDER => ErrorCode::TLSErrorWebpkiBadDER,
                webpki::Error::BadDERTime => ErrorCode::TLSErrorWebpkiBadDERTime,
                webpki::Error::CAUsedAsEndEntity => ErrorCode::TLSErrorWebpkiCAUsedAsEndEntity,
                webpki::Error::CertExpired => ErrorCode::TLSErrorWebpkiCertExpired,
                webpki::Error::CertNotValidForName => ErrorCode::TLSErrorWebpkiCertNotValidForName,
                webpki::Error::CertNotValidYet => ErrorCode::TLSErrorWebpkiCertNotValidYet,
                webpki::Error::EndEntityUsedAsCA => ErrorCode::TLSErrorWebpkiEndEntityUsedAsCA,
                webpki::Error::ExtensionValueInvalid => ErrorCode::TLSErrorWebpkiExtensionValueInvalid,
                webpki::Error::InvalidCertValidity => ErrorCode::TLSErrorWebpkiInvalidCertValidity,
                webpki::Error::InvalidSignatureForPublicKey => {
                    ErrorCode::TLSErrorWebpkiInvalidSignatureForPublicKey
                }
                webpki::Error::NameConstraintViolation => {
                    ErrorCode::TLSErrorWebpkiNameConstraintViolation
                }
                webpki::Error::PathLenConstraintViolated => {
                    ErrorCode::TLSErrorWebpkiPathLenConstraintViolated
                }
                webpki::Error::SignatureAlgorithmMismatch => {
                    ErrorCode::TLSErrorWebpkiSignatureAlgorithmMismatch
                }
                webpki::Error::RequiredEKUNotFound => ErrorCode::TLSErrorWebpkiRequiredEKUNotFound,
                webpki::Error::UnknownIssuer => ErrorCode::TLSErrorWebpkiUnknownIssuer,
                webpki::Error::UnsupportedCertVersion => {
                    ErrorCode::TLSErrorWebpkiUnsupportedCertVersion
                }
                webpki::Error::UnsupportedCriticalExtension => {
                    ErrorCode::TLSErrorWebpkiUnsupportedCriticalExtension
                }
                webpki::Error::UnsupportedSignatureAlgorithmForPublicKey => {
                    ErrorCode::TLSErrorWebpkiUnsupportedSignatureAlgorithmForPublicKey
                }
                webpki::Error::UnsupportedSignatureAlgorithm => {
                    ErrorCode::TLSErrorWebpkiUnsupportedSignatureAlgorithm
                }
            },
            &TLSError::InvalidSCT(_) => ErrorCode::TLSErrorInvalidSCT,
            &TLSError::General(_) => ErrorCode::TLSErrorGeneral,
            &TLSError::FailedToGetCurrentTime => ErrorCode::TLSErrorFailedToGetCurrentTime,
            &TLSError::InvalidDNSName(_) => ErrorCode::TLSErrorInvalidDNSName,
            &TLSError::HandshakeNotComplete => ErrorCode::TLSErrorHandshakeNotComplete,
            &TLSError::PeerSentOversizedRecord => ErrorCode::TLSErrorPeerSentOversizedRecord,
        }
    }
}

thread_local! {
    static ERROR_QUEUE: RefCell<VecDeque<ErrorCode>> = RefCell::new(VecDeque::new());
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
    error_code: c_ulong,
    buf_ptr: *mut c_char,
    buf_len: size_t,
) -> *const c_char {
    let src_ptr = mesalink_ERR_reason_error_string(error_code);
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
pub extern "C" fn mesalink_ERR_reason_error_string(e: c_ulong) -> *const c_char {
    let error_code: ErrorCode = ErrorCode::from(e);
    error_code.as_str().as_ptr() as *const c_char
}

#[doc(hidden)]
pub struct ErrorQueue {}

impl ErrorQueue {
    pub fn push_error(e: ErrorCode) {
        ERROR_QUEUE.with(|f| {
            f.borrow_mut().push_back(e);
        });
    }
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
        Some(e) => (*e) as c_ulong,
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
        for err in queue.drain(0..) {
            let description_c = std::ffi::CString::new(err.as_str());
            let _ = unsafe {
                libc::fprintf(
                    fp,
                    b"[thread: %u]:[error code: 0x%x]:[%s]\n\0".as_ptr() as *const c_char,
                    tid,
                    err as c_ulong,
                    description_c,
                )
            };
        }
    });
}
