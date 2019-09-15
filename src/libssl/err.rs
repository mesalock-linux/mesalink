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
//! failed API call typically returns -1/0 and pushes an error code into the
//! error queue. The error code can be acquired by calling `ERR_get_error` or
//! `SSL_get_error`.
//!
//! MesaLink always use a 32-bit unsigned integer to represent error codes.
//!
//! ```text
//!  7 6 5 4 3 2 1 0 7 6 5 4 3 2 1 0 7 6 5 4 3 2 1 0 7 6 5 4 3 2 1 0
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |     source    |     unused    |     errno     |   sub errno   |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! The highest 8 bits represent the source of the error. 0x1: the error comes
//! from MesaLink itself. For example, a NULL or malformed SSL_CTX pointer is
//! used. 0x2: the error comes from system I/O. For example, a certificate file
//! is not found. 0x3: the error is TLS specific. For example, the remote server
//! does not have a valid certifcate. The lowest 16 bits represent the specific
//! error, including 8 bites error number and 8 bits optional sub error number.
//! For a human-readable decription of an ErrorCode, call
//! `ERR_reason_error_string`. An non-exhaustive list of error codes is as
//! follows.
//!
//! ```c
//!   MESALINK_ERROR_NONE = 0,
//!   MESALINK_ERROR_ZERO_RETURN = 1,
//!   MESALINK_ERROR_WANT_READ = 2,
//!   MESALINK_ERROR_WANT_WRITE = 3,
//!   MESALINK_ERROR_WANT_CONNECT = 7,
//!   MESALINK_ERROR_WANT_ACCEPT = 8,
//!   MESALINK_ERROR_SYSCALL = 5,
//!   MESALINK_ERROR_SSL = 0x55,
//!   MESALINK_ERROR_NULL_POINTER = 0xe0,
//!   MESALINK_ERROR_MALFORMED_OBJECT = 0xe1,
//!   MESALINK_ERROR_BAD_FUNC_ARG = 0xe2,
//!   MESALINK_ERROR_PANIC = 0xe3,
//!   MESALINK_ERROR_LOCK = 0xe4,
//!   IO_ERROR_NOT_FOUND = 0x0200_0001,
//!   IO_ERROR_PERMISSION_DENIED = 0x0200_0002,
//!   IO_ERROR_CONNECTION_REFUSED = 0x0200_0003,
//!   IO_ERROR_CONNECTION_RESET = 0x0200_0004,
//!   IO_ERROR_CONNECTION_ABORTED = 0x0200_0005,
//!   IO_ERROR_NOT_CONNECTED = 0x0200_0006,
//!   IO_ERROR_ADDR_IN_USE = 0x0200_0007,
//!   IO_ERROR_ADDR_NOT_AVAILABLE = 0x0200_0008,
//!   IO_ERROR_BROKEN_PIPE = 0x0200_0009,
//!   IO_ERROR_ALREADY_EXISTS = 0x0200_000a,
//!   IO_ERROR_WOULD_BLOCK = 0x0200_000b,
//!   IO_ERROR_INVALID_INPUT = 0x0200_000c,
//!   IO_ERROR_INVALID_DATA = 0x0200_000d,
//!   IO_ERROR_TIMED_OUT = 0x0200_000e,
//!   IO_ERROR_WRITE_ZERO = 0x0200_000f,
//!   IO_ERROR_INTERRUPTED = 0x0200_0010,
//!   IO_ERROR_OTHER = 0x0200_0011,
//!   IO_ERROR_UNEXPECTED_EOF = 0x0200_0012,
//!   TLS_ERROR_INAPPROPRIATE_MESSAGE = 0x0300_0100,
//!   TLS_ERROR_INAPPROPRIATE_HANDSHAKE_MESSAGE = 0x0300_0200,
//!   TLS_ERROR_CORRUPT_MESSAGE = 0x0300_0300,
//!   TLS_ERROR_CORRUPT_MESSAGE_PAYLOAD = 0x0300_0400,
//!   TLS_ERROR_CORRUPT_MESSAGE_PAYLOAD_ALERT = 0x0300_0401,
//!   TLS_ERROR_CORRUPT_MESSAGE_PAYLOAD_CHANGE_CIPHER_SPEC = 0x0300_0402,
//!   TLS_ERROR_CORRUPT_MESSAGE_PAYLOAD_HANDSHAKE = 0x0300_0403,
//!   TLS_ERROR_NO_CERTIFICATES_PRESENTED = 0x0300_0500,
//!   TLS_ERROR_DECRYPT_ERROR = 0x0300_0600,
//!   TLS_ERROR_PEER_INCOMPATIBLE_ERROR = 0x0300_0700,
//!   TLS_ERROR_PEER_MISBEHAVED_ERROR = 0x0300_0800,
//!   TLS_ERROR_ALERT_RECEIVED_CLOSE_NOTIFY = 0x0300_0901,
//!   TLS_ERROR_ALERT_RECEIVED_UNEXPECTED_MESSAGE = 0x0300_0902,
//!   TLS_ERROR_ALERT_RECEIVED_BAD_RECORD_MAC = 0x0300_0903,
//!   TLS_ERROR_ALERT_RECEIVED_DECRYPTION_FAILED = 0x0300_0904,
//!   TLS_ERROR_ALERT_RECEIVED_RECORD_OVERFLOW = 0x0300_0905,
//!   TLS_ERROR_ALERT_RECEIVED_DECOMPRESSION_FAILURE = 0x0300_0906,
//!   TLS_ERROR_ALERT_RECEIVED_HANDSHAKE_FAILURE = 0x0300_0907,
//!   TLS_ERROR_ALERT_RECEIVED_NO_CERTIFICATE = 0x0300_0908,
//!   TLS_ERROR_ALERT_RECEIVED_BAD_CERTIFICATE = 0x0300_0909,
//!   TLS_ERROR_ALERT_RECEIVED_UNSUPPORTED_CERTIFICATE = 0x0300_090a,
//!   TLS_ERROR_ALERT_RECEIVED_CERTIFICATE_REVOKED = 0x0300_090b,
//!   TLS_ERROR_ALERT_RECEIVED_CERTIFICATE_EXPIRED = 0x0300_090c,
//!   TLS_ERROR_ALERT_RECEIVED_CERTIFICATE_UNKNOWN = 0x0300_090d,
//!   TLS_ERROR_ALERT_RECEIVED_ILLEGAL_PARAMETER = 0x0300_090e,
//!   TLS_ERROR_ALERT_RECEIVED_UNKNOWN_CA = 0x0300_090f,
//!   TLS_ERROR_ALERT_RECEIVED_ACCESS_DENIED = 0x0300_0910,
//!   TLS_ERROR_ALERT_RECEIVED_DECODE_ERROR = 0x0300_0911,
//!   TLS_ERROR_ALERT_RECEIVED_DECRYPT_ERROR = 0x0300_0912,
//!   TLS_ERROR_ALERT_RECEIVED_EXPORT_RESTRICTION = 0x0300_0913,
//!   TLS_ERROR_ALERT_RECEIVED_PROTOCOL_VERSION = 0x0300_0914,
//!   TLS_ERROR_ALERT_RECEIVED_INSUFFICIENT_SECURITY = 0x0300_0915,
//!   TLS_ERROR_ALERT_RECEIVED_INTERNAL_ERROR = 0x0300_0916,
//!   TLS_ERROR_ALERT_RECEIVED_INAPPROPRIATE_FALLBACK = 0x0300_0917,
//!   TLS_ERROR_ALERT_RECEIVED_USER_CANCELED = 0x0300_0918,
//!   TLS_ERROR_ALERT_RECEIVED_NO_RENEGOTIATION = 0x0300_0919,
//!   TLS_ERROR_ALERT_RECEIVED_MISSING_EXTENSION = 0x0300_091a,
//!   TLS_ERROR_ALERT_RECEIVED_UNSUPPORTED_EXTENSION = 0x0300_091b,
//!   TLS_ERROR_ALERT_RECEIVED_CERTIFICATE_UNOBTAINABLE = 0x0300_091c,
//!   TLS_ERROR_ALERT_RECEIVED_UNRECOGNISED_NAME = 0x0300_091d,
//!   TLS_ERROR_ALERT_RECEIVED_BAD_CERTIFICATE_STATUS_RESPONSE = 0x0300_091e,
//!   TLS_ERROR_ALERT_RECEIVED_BAD_CERTIFICATE_HASH_VALUE = 0x0300_091f,
//!   TLS_ERROR_ALERT_RECEIVED_UNKNOWN_PSK_IDENTITY = 0x0300_0920,
//!   TLS_ERROR_ALERT_RECEIVED_CERTIFICATE_REQUIRED = 0x0300_0921,
//!   TLS_ERROR_ALERT_RECEIVED_NO_APPLICATION_PROTOCOL = 0x0300_0922,
//!   TLS_ERROR_ALERT_RECEIVED_UNKNOWN = 0x0300_09ff,
//!   TLS_ERROR_WEBPKI_BAD_DER = 0x0300_0a01,
//!   TLS_ERROR_WEBPKI_BAD_DER_TIME = 0x0300_0a02,
//!   TLS_ERROR_WEBPKI_CA_USED_AS_END_ENTITY = 0x0300_0a03,
//!   TLS_ERROR_WEBPKI_CERT_EXPIRED = 0x0300_0a04,
//!   TLS_ERROR_WEBPKI_CERT_NOT_VALID_FOR_NAME = 0x0300_0a05,
//!   TLS_ERROR_WEBPKI_CERT_NOT_VALID_YET = 0x0300_0a06,
//!   TLS_ERROR_WEBPKI_END_ENTITY_USED_AS_CA = 0x0300_0a07,
//!   TLS_ERROR_WEBPKI_EXTENSION_VALUE_INVALID = 0x0300_0a08,
//!   TLS_ERROR_WEBPKI_INVALID_CERT_VALIDITY = 0x0300_0a09,
//!   TLS_ERROR_WEBPKI_INVALID_SIGNATURE_FOR_PUBLIC_KEY = 0x0300_0a0a,
//!   TLS_ERROR_WEBPKI_NAME_CONSTRAINT_VIOLATION = 0x0300_0a0b,
//!   TLS_ERROR_WEBPKI_PATH_LEN_CONSTRAINT_VIOLATED = 0x0300_0a0c,
//!   TLS_ERROR_WEBPKI_SIGNATURE_ALGORITHM_MISMATCH = 0x0300_0a0d,
//!   TLS_ERROR_WEBPKI_REQUIRED_EKU_NOT_FOUND = 0x0300_0a0e,
//!   TLS_ERROR_WEBPKI_UNKNOWN_ISSUER = 0x0300_0a0f,
//!   TLS_ERROR_WEBPKI_UNSUPPORTED_CERT_VERSION = 0x0300_0a10,
//!   TLS_ERROR_WEBPKI_UNSUPPORTED_CRITICAL_EXTENSION = 0x0300_0a11,
//!   TLS_ERROR_WEBPKI_UNSUPPORTED_SIGNATURE_ALGORITHM_FOR_PUBLIC_KEY = 0x0300_0a12,
//!   TLS_ERROR_WEBPKI_UNSUPPORTED_SIGNATURE_ALGORITHM = 0x0300_0a13,
//!   TLS_ERROR_INVALID_SCT = 0x0300_0b00,
//!   TLS_ERROR_GENERAL = 0x0300_0c00,
//!   TLS_ERROR_FAILED_TO_GET_CURRENT_TIME = 0x0300_0d00,
//!   TLS_ERROR_INVALID_DNS_NAME = 0x0300_0e00,
//!   TLS_ERROR_HANDSHAKE_NOT_COMPLETE = 0x0300_0f00,
//!   TLS_ERROR_PEER_SENT_OVERSIZED_RECORD = 0x0300_1000,
//!   UNDEFINED_ERROR = 0x0eeeeeee,
//! ```

use libc::{self, c_char, c_ulong, size_t};
use rustls;
use std::{error, fmt, io, slice};
use webpki;

use std::cell::RefCell;
use std::collections::VecDeque;
thread_local! {
    static ERROR_QUEUE: RefCell<VecDeque<MesalinkError>> = RefCell::new(VecDeque::new());
}

#[doc(hidden)]
#[repr(C)]
#[derive(PartialEq, Clone, Debug)]
#[allow(dead_code)]
pub(crate) enum MesalinkBuiltinError {
    None,
    ZeroReturn,
    WantRead,
    WantWrite,
    WantConnect,
    WantAccept,
    Syscall,
    Ssl,
    NullPointer,
    MalformedObject,
    BadFuncArg,
    Panic,
    Lock,
}

#[doc(hidden)]
impl fmt::Display for MesalinkBuiltinError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MesalinkBuiltinError: {:?}", self)
    }
}

#[doc(hidden)]
impl error::Error for MesalinkBuiltinError {
    fn description(&self) -> &str {
        match *self {
            MesalinkBuiltinError::None => "SSL_ERROR_NONE",
            MesalinkBuiltinError::ZeroReturn => "SSL_ERROR_ZERO_RETURN",
            MesalinkBuiltinError::WantRead => "SSL_ERROR_WANT_READ",
            MesalinkBuiltinError::WantWrite => "SSL_ERROR_WANT_WRITE",
            MesalinkBuiltinError::WantConnect => "SSL_ERROR_WANT_CONNECT",
            MesalinkBuiltinError::WantAccept => "SSL_ERROR_WANT_ACCEPT",
            MesalinkBuiltinError::Syscall => "SSL_ERROR_SYSCALL",
            MesalinkBuiltinError::Ssl => "SSL_ERROR_SSL",
            MesalinkBuiltinError::NullPointer => "MESALINK_ERROR_NULL_POINTER",
            MesalinkBuiltinError::MalformedObject => "MESALINK_ERROR_MALFORMED_OBJECT",
            MesalinkBuiltinError::BadFuncArg => "MESALINK_ERROR_BAD_FUNCTION_ARGUMENT",
            MesalinkBuiltinError::Panic => "MESALINK_ERROR_PANIC_AT_FFI",
            MesalinkBuiltinError::Lock => "MESALINK_ERROR_LOCK_FAILED",
        }
    }
}

#[cfg_attr(feature = "error_strings", derive(Debug))]
#[doc(hidden)]
pub(crate) enum MesalinkErrorType {
    Io(io::Error),
    Tls(rustls::TLSError),
    Builtin(MesalinkBuiltinError),
}

#[doc(hidden)]
impl From<io::Error> for MesalinkErrorType {
    fn from(err: io::Error) -> MesalinkErrorType {
        MesalinkErrorType::Io(err)
    }
}

#[doc(hidden)]
impl From<rustls::TLSError> for MesalinkErrorType {
    fn from(err: rustls::TLSError) -> MesalinkErrorType {
        MesalinkErrorType::Tls(err)
    }
}

#[doc(hidden)]
impl From<MesalinkBuiltinError> for MesalinkErrorType {
    fn from(err: MesalinkBuiltinError) -> MesalinkErrorType {
        MesalinkErrorType::Builtin(err)
    }
}

#[cfg_attr(feature = "error_strings", derive(Debug))]
#[doc(hidden)]
pub(crate) struct MesalinkError {
    pub error: MesalinkErrorType,
    call_site: &'static str,
}

impl MesalinkError {
    pub fn new(error: MesalinkErrorType, call_site: &'static str) -> MesalinkError {
        MesalinkError { error, call_site }
    }
}

#[doc(hidden)]
pub(crate) type MesalinkInnerResult<T> = Result<T, MesalinkError>;

#[doc(hidden)]
#[repr(C)]
#[derive(Clone, Copy, PartialEq)]
#[cfg_attr(feature = "error_strings", derive(EnumToU8, Debug))]
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
    MesalinkNullPointer = 0xe0,
    MesalinkErrorMalformedObject = 0xe1,
    MesalinkErrorBadFuncArg = 0xe2,
    MesalinkErrorPanic = 0xe3,
    MesalinkErrorLock = 0xe4,
    // Rust IO ErrorKind codes
    IoErrorNotFound = 0x0200_0001,
    IoErrorPermissionDenied = 0x0200_0002,
    IoErrorConnectionRefused = 0x0200_0003,
    IoErrorConnectionReset = 0x0200_0004,
    IoErrorConnectionAborted = 0x0200_0005,
    IoErrorNotConnected = 0x0200_0006,
    IoErrorAddrInUse = 0x0200_0007,
    IoErrorAddrNotAvailable = 0x0200_0008,
    IoErrorBrokenPipe = 0x0200_0009,
    IoErrorAlreadyExists = 0x0200_000a,
    IoErrorWouldBlock = 0x0200_000b,
    IoErrorInvalidInput = 0x0200_000c,
    IoErrorInvalidData = 0x0200_000d,
    IoErrorTimedOut = 0x0200_000e,
    IoErrorWriteZero = 0x0200_000f,
    IoErrorInterrupted = 0x0200_0010,
    IoErrorOther = 0x0200_0011,
    IoErrorUnexpectedEof = 0x0200_0012,
    // TLS error codes
    TLSErrorInappropriateMessage = 0x0300_0100,
    TLSErrorInappropriateHandshakeMessage = 0x0300_0200,
    TLSErrorCorruptMessage = 0x0300_0300,
    TLSErrorCorruptMessagePayload = 0x0300_0400,
    TLSErrorCorruptMessagePayloadAlert = 0x0300_0401,
    TLSErrorCorruptMessagePayloadChangeCipherSpec = 0x0300_0402,
    TLSErrorCorruptMessagePayloadHandshake = 0x0300_0403,
    TLSErrorNoCertificatesPresented = 0x0300_0500,
    TLSErrorDecryptError = 0x0300_0600,
    TLSErrorPeerIncompatibleError = 0x0300_0700,
    TLSErrorPeerMisbehavedError = 0x0300_0800,
    TLSErrorAlertReceivedCloseNotify = 0x0300_0901,
    TLSErrorAlertReceivedUnexpectedMessage = 0x0300_0902,
    TLSErrorAlertReceivedBadRecordMac = 0x0300_0903,
    TLSErrorAlertReceivedDecryptionFailed = 0x0300_0904,
    TLSErrorAlertReceivedRecordOverflow = 0x0300_0905,
    TLSErrorAlertReceivedDecompressionFailure = 0x0300_0906,
    TLSErrorAlertReceivedHandshakeFailure = 0x0300_0907,
    TLSErrorAlertReceivedNoCertificate = 0x0300_0908,
    TLSErrorAlertReceivedBadCertificate = 0x0300_0909,
    TLSErrorAlertReceivedUnsupportedCertificate = 0x0300_090a,
    TLSErrorAlertReceivedCertificateRevoked = 0x0300_090b,
    TLSErrorAlertReceivedCertificateExpired = 0x0300_090c,
    TLSErrorAlertReceivedCertificateUnknown = 0x0300_090d,
    TLSErrorAlertReceivedIllegalParameter = 0x0300_090e,
    TLSErrorAlertReceivedUnknownCA = 0x0300_090f,
    TLSErrorAlertReceivedAccessDenied = 0x0300_0910,
    TLSErrorAlertReceivedDecodeError = 0x0300_0911,
    TLSErrorAlertReceivedDecryptError = 0x0300_0912,
    TLSErrorAlertReceivedExportRestriction = 0x0300_0913,
    TLSErrorAlertReceivedProtocolVersion = 0x0300_0914,
    TLSErrorAlertReceivedInsufficientSecurity = 0x0300_0915,
    TLSErrorAlertReceivedInternalError = 0x0300_0916,
    TLSErrorAlertReceivedInappropriateFallback = 0x0300_0917,
    TLSErrorAlertReceivedUserCanceled = 0x0300_0918,
    TLSErrorAlertReceivedNoRenegotiation = 0x0300_0919,
    TLSErrorAlertReceivedMissingExtension = 0x0300_091a,
    TLSErrorAlertReceivedUnsupportedExtension = 0x0300_091b,
    TLSErrorAlertReceivedCertificateUnobtainable = 0x0300_091c,
    TLSErrorAlertReceivedUnrecognisedName = 0x0300_091d,
    TLSErrorAlertReceivedBadCertificateStatusResponse = 0x0300_091e,
    TLSErrorAlertReceivedBadCertificateHashValue = 0x0300_091f,
    TLSErrorAlertReceivedUnknownPSKIdentity = 0x0300_0920,
    TLSErrorAlertReceivedCertificateRequired = 0x0300_0921,
    TLSErrorAlertReceivedNoApplicationProtocol = 0x0300_0922,
    TLSErrorAlertReceivedUnknown = 0x0300_09ff,
    TLSErrorWebpkiBadDER = 0x0300_0a01,
    TLSErrorWebpkiBadDERTime = 0x0300_0a02,
    TLSErrorWebpkiCAUsedAsEndEntity = 0x0300_0a03,
    TLSErrorWebpkiCertExpired = 0x0300_0a04,
    TLSErrorWebpkiCertNotValidForName = 0x0300_0a05,
    TLSErrorWebpkiCertNotValidYet = 0x0300_0a06,
    TLSErrorWebpkiEndEntityUsedAsCA = 0x0300_0a07,
    TLSErrorWebpkiExtensionValueInvalid = 0x0300_0a08,
    TLSErrorWebpkiInvalidCertValidity = 0x0300_0a09,
    TLSErrorWebpkiInvalidSignatureForPublicKey = 0x0300_0a0a,
    TLSErrorWebpkiNameConstraintViolation = 0x0300_0a0b,
    TLSErrorWebpkiPathLenConstraintViolated = 0x0300_0a0c,
    TLSErrorWebpkiSignatureAlgorithmMismatch = 0x0300_0a0d,
    TLSErrorWebpkiRequiredEKUNotFound = 0x0300_0a0e,
    TLSErrorWebpkiUnknownIssuer = 0x0300_0a0f,
    TLSErrorWebpkiUnsupportedCertVersion = 0x0300_0a10,
    TLSErrorWebpkiUnsupportedCriticalExtension = 0x0300_0a11,
    TLSErrorWebpkiUnsupportedSignatureAlgorithmForPublicKey = 0x0300_0a12,
    TLSErrorWebpkiUnsupportedSignatureAlgorithm = 0x0300_0a13,
    TLSErrorInvalidSCT = 0x0300_0b00,
    TLSErrorGeneral = 0x0300_0c00,
    TLSErrorFailedToGetCurrentTime = 0x0300_0d00,
    TLSErrorInvalidDNSName = 0x0300_0e00,
    TLSErrorHandshakeNotComplete = 0x0300_0f00,
    TLSErrorPeerSentOversizedRecord = 0x0300_1000,
    UndefinedError = 0x0eee_eeee,
}

#[doc(hidden)]
impl ErrorCode {
    #[cfg(feature = "error_strings")]
    pub fn as_u8_slice(self) -> &'static [u8] {
        self.enum_to_u8()
    }

    #[cfg(not(feature = "error_strings"))]
    pub fn as_u8_slice(&self) -> &'static [u8] {
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
        match e {
            0 => ErrorCode::MesalinkErrorNone,
            1 => ErrorCode::MesalinkErrorZeroReturn,
            2 => ErrorCode::MesalinkErrorWantRead,
            3 => ErrorCode::MesalinkErrorWantWrite,
            7 => ErrorCode::MesalinkErrorWantConnect,
            8 => ErrorCode::MesalinkErrorWantAccept,
            5 => ErrorCode::MesalinkErrorSyscall,
            0x55 => ErrorCode::MesalinkErrorSsl,
            0xe0 => ErrorCode::MesalinkNullPointer,
            0xe1 => ErrorCode::MesalinkErrorMalformedObject,
            0xe2 => ErrorCode::MesalinkErrorBadFuncArg,
            0xe3 => ErrorCode::MesalinkErrorPanic,
            0xe4 => ErrorCode::MesalinkErrorLock,
            0x0200_0001 => ErrorCode::IoErrorNotFound,
            0x0200_0002 => ErrorCode::IoErrorPermissionDenied,
            0x0200_0003 => ErrorCode::IoErrorConnectionRefused,
            0x0200_0004 => ErrorCode::IoErrorConnectionReset,
            0x0200_0005 => ErrorCode::IoErrorConnectionAborted,
            0x0200_0006 => ErrorCode::IoErrorNotConnected,
            0x0200_0007 => ErrorCode::IoErrorAddrInUse,
            0x0200_0008 => ErrorCode::IoErrorAddrNotAvailable,
            0x0200_0009 => ErrorCode::IoErrorBrokenPipe,
            0x0200_000a => ErrorCode::IoErrorAlreadyExists,
            0x0200_000b => ErrorCode::IoErrorWouldBlock,
            0x0200_000c => ErrorCode::IoErrorInvalidInput,
            0x0200_000d => ErrorCode::IoErrorInvalidData,
            0x0200_000e => ErrorCode::IoErrorTimedOut,
            0x0200_000f => ErrorCode::IoErrorWriteZero,
            0x0200_0010 => ErrorCode::IoErrorInterrupted,
            0x0200_0011 => ErrorCode::IoErrorOther,
            0x0200_0012 => ErrorCode::IoErrorUnexpectedEof,
            0x0300_0100 => ErrorCode::TLSErrorInappropriateMessage,
            0x0300_0200 => ErrorCode::TLSErrorInappropriateHandshakeMessage,
            0x0300_0300 => ErrorCode::TLSErrorCorruptMessage,
            0x0300_0400 => ErrorCode::TLSErrorCorruptMessagePayload,
            0x0300_0401 => ErrorCode::TLSErrorCorruptMessagePayloadAlert,
            0x0300_0402 => ErrorCode::TLSErrorCorruptMessagePayloadChangeCipherSpec,
            0x0300_0403 => ErrorCode::TLSErrorCorruptMessagePayloadHandshake,
            0x0300_0500 => ErrorCode::TLSErrorNoCertificatesPresented,
            0x0300_0600 => ErrorCode::TLSErrorDecryptError,
            0x0300_0700 => ErrorCode::TLSErrorPeerIncompatibleError,
            0x0300_0800 => ErrorCode::TLSErrorPeerMisbehavedError,
            0x0300_0901 => ErrorCode::TLSErrorAlertReceivedCloseNotify,
            0x0300_0902 => ErrorCode::TLSErrorAlertReceivedUnexpectedMessage,
            0x0300_0903 => ErrorCode::TLSErrorAlertReceivedBadRecordMac,
            0x0300_0904 => ErrorCode::TLSErrorAlertReceivedDecryptionFailed,
            0x0300_0905 => ErrorCode::TLSErrorAlertReceivedRecordOverflow,
            0x0300_0906 => ErrorCode::TLSErrorAlertReceivedDecompressionFailure,
            0x0300_0907 => ErrorCode::TLSErrorAlertReceivedHandshakeFailure,
            0x0300_0908 => ErrorCode::TLSErrorAlertReceivedNoCertificate,
            0x0300_0909 => ErrorCode::TLSErrorAlertReceivedBadCertificate,
            0x0300_090a => ErrorCode::TLSErrorAlertReceivedUnsupportedCertificate,
            0x0300_090b => ErrorCode::TLSErrorAlertReceivedCertificateRevoked,
            0x0300_090c => ErrorCode::TLSErrorAlertReceivedCertificateExpired,
            0x0300_090d => ErrorCode::TLSErrorAlertReceivedCertificateUnknown,
            0x0300_090e => ErrorCode::TLSErrorAlertReceivedIllegalParameter,
            0x0300_090f => ErrorCode::TLSErrorAlertReceivedUnknownCA,
            0x0300_0910 => ErrorCode::TLSErrorAlertReceivedAccessDenied,
            0x0300_0911 => ErrorCode::TLSErrorAlertReceivedDecodeError,
            0x0300_0912 => ErrorCode::TLSErrorAlertReceivedDecryptError,
            0x0300_0913 => ErrorCode::TLSErrorAlertReceivedExportRestriction,
            0x0300_0914 => ErrorCode::TLSErrorAlertReceivedProtocolVersion,
            0x0300_0915 => ErrorCode::TLSErrorAlertReceivedInsufficientSecurity,
            0x0300_0916 => ErrorCode::TLSErrorAlertReceivedInternalError,
            0x0300_0917 => ErrorCode::TLSErrorAlertReceivedInappropriateFallback,
            0x0300_0918 => ErrorCode::TLSErrorAlertReceivedUserCanceled,
            0x0300_0919 => ErrorCode::TLSErrorAlertReceivedNoRenegotiation,
            0x0300_091a => ErrorCode::TLSErrorAlertReceivedMissingExtension,
            0x0300_091b => ErrorCode::TLSErrorAlertReceivedUnsupportedExtension,
            0x0300_091c => ErrorCode::TLSErrorAlertReceivedCertificateUnobtainable,
            0x0300_091d => ErrorCode::TLSErrorAlertReceivedUnrecognisedName,
            0x0300_091e => ErrorCode::TLSErrorAlertReceivedBadCertificateStatusResponse,
            0x0300_091f => ErrorCode::TLSErrorAlertReceivedBadCertificateHashValue,
            0x0300_0920 => ErrorCode::TLSErrorAlertReceivedUnknownPSKIdentity,
            0x0300_0921 => ErrorCode::TLSErrorAlertReceivedCertificateRequired,
            0x0300_0922 => ErrorCode::TLSErrorAlertReceivedNoApplicationProtocol,
            0x0300_09ff => ErrorCode::TLSErrorAlertReceivedUnknown,
            0x0300_0a01 => ErrorCode::TLSErrorWebpkiBadDER,
            0x0300_0a02 => ErrorCode::TLSErrorWebpkiBadDERTime,
            0x0300_0a03 => ErrorCode::TLSErrorWebpkiCAUsedAsEndEntity,
            0x0300_0a04 => ErrorCode::TLSErrorWebpkiCertExpired,
            0x0300_0a05 => ErrorCode::TLSErrorWebpkiCertNotValidForName,
            0x0300_0a06 => ErrorCode::TLSErrorWebpkiCertNotValidYet,
            0x0300_0a07 => ErrorCode::TLSErrorWebpkiEndEntityUsedAsCA,
            0x0300_0a08 => ErrorCode::TLSErrorWebpkiExtensionValueInvalid,
            0x0300_0a09 => ErrorCode::TLSErrorWebpkiInvalidCertValidity,
            0x0300_0a0a => ErrorCode::TLSErrorWebpkiInvalidSignatureForPublicKey,
            0x0300_0a0b => ErrorCode::TLSErrorWebpkiNameConstraintViolation,
            0x0300_0a0c => ErrorCode::TLSErrorWebpkiPathLenConstraintViolated,
            0x0300_0a0d => ErrorCode::TLSErrorWebpkiSignatureAlgorithmMismatch,
            0x0300_0a0e => ErrorCode::TLSErrorWebpkiRequiredEKUNotFound,
            0x0300_0a0f => ErrorCode::TLSErrorWebpkiUnknownIssuer,
            0x0300_0a10 => ErrorCode::TLSErrorWebpkiUnsupportedCertVersion,
            0x0300_0a11 => ErrorCode::TLSErrorWebpkiUnsupportedCriticalExtension,
            0x0300_0a12 => ErrorCode::TLSErrorWebpkiUnsupportedSignatureAlgorithmForPublicKey,
            0x0300_0a13 => ErrorCode::TLSErrorWebpkiUnsupportedSignatureAlgorithm,
            0x0300_0b00 => ErrorCode::TLSErrorInvalidSCT,
            0x0300_0c00 => ErrorCode::TLSErrorGeneral,
            0x0300_0d00 => ErrorCode::TLSErrorFailedToGetCurrentTime,
            0x0300_0e00 => ErrorCode::TLSErrorInvalidDNSName,
            0x0300_0f00 => ErrorCode::TLSErrorHandshakeNotComplete,
            0x0300_1000 => ErrorCode::TLSErrorPeerSentOversizedRecord,
            _ => ErrorCode::UndefinedError,
        }
    }
}

#[doc(hidden)]
impl From<u64> for ErrorCode {
    fn from(e: u64) -> ErrorCode {
        ErrorCode::from(e as u32)
    }
}

#[doc(hidden)]
#[allow(unused_variables)]
#[rustfmt::skip]
impl<'a> From<&'a MesalinkError> for ErrorCode {
    fn from(e: &'a MesalinkError) -> ErrorCode {
        use rustls::internal::msgs::enums::{AlertDescription, ContentType};
        use rustls::TLSError;
        match e.error {
            MesalinkErrorType::Builtin(ref e) => match *e {
                MesalinkBuiltinError::None => ErrorCode::MesalinkErrorNone,
                MesalinkBuiltinError::ZeroReturn => ErrorCode::MesalinkErrorZeroReturn,
                MesalinkBuiltinError::WantRead => ErrorCode::MesalinkErrorWantRead,
                MesalinkBuiltinError::WantWrite => ErrorCode::MesalinkErrorWantWrite,
                MesalinkBuiltinError::WantConnect => ErrorCode::MesalinkErrorWantConnect,
                MesalinkBuiltinError::WantAccept => ErrorCode::MesalinkErrorWantAccept,
                MesalinkBuiltinError::Syscall => ErrorCode::MesalinkErrorSyscall,
                MesalinkBuiltinError::Ssl => ErrorCode::MesalinkErrorSsl,
                MesalinkBuiltinError::NullPointer => ErrorCode::MesalinkNullPointer,
                MesalinkBuiltinError::MalformedObject => ErrorCode::MesalinkErrorMalformedObject,
                MesalinkBuiltinError::BadFuncArg => ErrorCode::MesalinkErrorBadFuncArg,
                MesalinkBuiltinError::Panic => ErrorCode::MesalinkErrorPanic,
                MesalinkBuiltinError::Lock => ErrorCode::MesalinkErrorLock,
            },
            MesalinkErrorType::Io(ref e) => match e.kind() {
                io::ErrorKind::NotFound => ErrorCode::IoErrorNotFound,
                io::ErrorKind::PermissionDenied => ErrorCode::IoErrorPermissionDenied,
                io::ErrorKind::ConnectionRefused => ErrorCode::IoErrorConnectionRefused,
                io::ErrorKind::ConnectionReset => ErrorCode::IoErrorConnectionReset,
                io::ErrorKind::ConnectionAborted => ErrorCode::IoErrorConnectionAborted,
                io::ErrorKind::NotConnected => ErrorCode::IoErrorNotConnected,
                io::ErrorKind::AddrInUse => ErrorCode::IoErrorAddrInUse,
                io::ErrorKind::AddrNotAvailable => ErrorCode::IoErrorAddrNotAvailable,
                io::ErrorKind::BrokenPipe => ErrorCode::IoErrorBrokenPipe,
                io::ErrorKind::AlreadyExists => ErrorCode::IoErrorAlreadyExists,
                io::ErrorKind::WouldBlock => ErrorCode::IoErrorWouldBlock,
                io::ErrorKind::InvalidInput => ErrorCode::IoErrorInvalidInput,
                io::ErrorKind::InvalidData => ErrorCode::IoErrorInvalidData,
                io::ErrorKind::TimedOut => ErrorCode::IoErrorTimedOut,
                io::ErrorKind::WriteZero => ErrorCode::IoErrorWriteZero,
                io::ErrorKind::Interrupted => ErrorCode::IoErrorInterrupted,
                io::ErrorKind::Other => ErrorCode::IoErrorOther,
                io::ErrorKind::UnexpectedEof => ErrorCode::IoErrorUnexpectedEof,
                _ => ErrorCode::UndefinedError,
            },
            MesalinkErrorType::Tls(ref e) => match *e {
                TLSError::InappropriateMessage {
                    ref expect_types,
                    ref got_type,
                } => ErrorCode::TLSErrorInappropriateMessage,
                TLSError::InappropriateHandshakeMessage {
                    ref expect_types,
                    ref got_type,
                } => ErrorCode::TLSErrorInappropriateHandshakeMessage,
                TLSError::CorruptMessage => ErrorCode::TLSErrorCorruptMessage,
                TLSError::CorruptMessagePayload(c) => match c {
                    ContentType::Alert => ErrorCode::TLSErrorCorruptMessagePayloadAlert,
                    ContentType::ChangeCipherSpec => ErrorCode::TLSErrorCorruptMessagePayloadChangeCipherSpec,
                    ContentType::Handshake => ErrorCode::TLSErrorCorruptMessagePayloadHandshake,
                    _ => ErrorCode::TLSErrorCorruptMessagePayload,
                },
                TLSError::NoCertificatesPresented => ErrorCode::TLSErrorNoCertificatesPresented,
                TLSError::DecryptError => ErrorCode::TLSErrorDecryptError,
                TLSError::PeerIncompatibleError(_) => ErrorCode::TLSErrorPeerIncompatibleError,
                TLSError::PeerMisbehavedError(_) => ErrorCode::TLSErrorPeerMisbehavedError,
                TLSError::AlertReceived(alert) => match alert {
                    AlertDescription::CloseNotify => ErrorCode::TLSErrorAlertReceivedCloseNotify,
                    AlertDescription::UnexpectedMessage => ErrorCode::TLSErrorAlertReceivedUnexpectedMessage,
                    AlertDescription::BadRecordMac => ErrorCode::TLSErrorAlertReceivedBadRecordMac,
                    AlertDescription::DecryptionFailed => ErrorCode::TLSErrorAlertReceivedDecryptionFailed,
                    AlertDescription::RecordOverflow => ErrorCode::TLSErrorAlertReceivedRecordOverflow,
                    AlertDescription::DecompressionFailure => ErrorCode::TLSErrorAlertReceivedDecompressionFailure,
                    AlertDescription::HandshakeFailure => ErrorCode::TLSErrorAlertReceivedHandshakeFailure,
                    AlertDescription::NoCertificate => ErrorCode::TLSErrorAlertReceivedNoCertificate,
                    AlertDescription::BadCertificate => ErrorCode::TLSErrorAlertReceivedBadCertificate,
                    AlertDescription::UnsupportedCertificate => ErrorCode::TLSErrorAlertReceivedUnsupportedCertificate,
                    AlertDescription::CertificateRevoked => ErrorCode::TLSErrorAlertReceivedCertificateRevoked,
                    AlertDescription::CertificateExpired => ErrorCode::TLSErrorAlertReceivedCertificateExpired,
                    AlertDescription::CertificateUnknown => ErrorCode::TLSErrorAlertReceivedCertificateUnknown,
                    AlertDescription::IllegalParameter => ErrorCode::TLSErrorAlertReceivedIllegalParameter,
                    AlertDescription::UnknownCA => ErrorCode::TLSErrorAlertReceivedUnknownCA,
                    AlertDescription::AccessDenied => ErrorCode::TLSErrorAlertReceivedAccessDenied,
                    AlertDescription::DecodeError => ErrorCode::TLSErrorAlertReceivedDecodeError,
                    AlertDescription::DecryptError => ErrorCode::TLSErrorAlertReceivedDecryptError,
                    AlertDescription::ExportRestriction => ErrorCode::TLSErrorAlertReceivedExportRestriction,
                    AlertDescription::ProtocolVersion => ErrorCode::TLSErrorAlertReceivedProtocolVersion,
                    AlertDescription::InsufficientSecurity => ErrorCode::TLSErrorAlertReceivedInsufficientSecurity,
                    AlertDescription::InternalError => ErrorCode::TLSErrorAlertReceivedInternalError,
                    AlertDescription::InappropriateFallback => ErrorCode::TLSErrorAlertReceivedInappropriateFallback,
                    AlertDescription::UserCanceled => ErrorCode::TLSErrorAlertReceivedUserCanceled,
                    AlertDescription::NoRenegotiation => ErrorCode::TLSErrorAlertReceivedNoRenegotiation,
                    AlertDescription::MissingExtension => ErrorCode::TLSErrorAlertReceivedMissingExtension,
                    AlertDescription::UnsupportedExtension => ErrorCode::TLSErrorAlertReceivedUnsupportedExtension,
                    AlertDescription::CertificateUnobtainable => ErrorCode::TLSErrorAlertReceivedCertificateUnobtainable,
                    AlertDescription::UnrecognisedName => ErrorCode::TLSErrorAlertReceivedUnrecognisedName,
                    AlertDescription::BadCertificateStatusResponse => ErrorCode::TLSErrorAlertReceivedBadCertificateStatusResponse,
                    AlertDescription::BadCertificateHashValue => ErrorCode::TLSErrorAlertReceivedBadCertificateHashValue,
                    AlertDescription::UnknownPSKIdentity => ErrorCode::TLSErrorAlertReceivedUnknownPSKIdentity,
                    AlertDescription::CertificateRequired => ErrorCode::TLSErrorAlertReceivedCertificateRequired,
                    AlertDescription::NoApplicationProtocol => ErrorCode::TLSErrorAlertReceivedNoApplicationProtocol,
                    AlertDescription::Unknown(_) => ErrorCode::TLSErrorAlertReceivedUnknown,
                },
                TLSError::WebPKIError(pki_err) => match pki_err {
                    webpki::Error::BadDER => ErrorCode::TLSErrorWebpkiBadDER,
                    webpki::Error::BadDERTime => ErrorCode::TLSErrorWebpkiBadDERTime,
                    webpki::Error::CAUsedAsEndEntity => ErrorCode::TLSErrorWebpkiCAUsedAsEndEntity,
                    webpki::Error::CertExpired => ErrorCode::TLSErrorWebpkiCertExpired,
                    webpki::Error::CertNotValidForName => ErrorCode::TLSErrorWebpkiCertNotValidForName,
                    webpki::Error::CertNotValidYet => ErrorCode::TLSErrorWebpkiCertNotValidYet,
                    webpki::Error::EndEntityUsedAsCA => ErrorCode::TLSErrorWebpkiEndEntityUsedAsCA,
                    webpki::Error::ExtensionValueInvalid => ErrorCode::TLSErrorWebpkiExtensionValueInvalid,
                    webpki::Error::InvalidCertValidity => ErrorCode::TLSErrorWebpkiInvalidCertValidity,
                    webpki::Error::InvalidSignatureForPublicKey => ErrorCode::TLSErrorWebpkiInvalidSignatureForPublicKey,
                    webpki::Error::NameConstraintViolation => ErrorCode::TLSErrorWebpkiNameConstraintViolation,
                    webpki::Error::PathLenConstraintViolated => ErrorCode::TLSErrorWebpkiPathLenConstraintViolated,
                    webpki::Error::SignatureAlgorithmMismatch => ErrorCode::TLSErrorWebpkiSignatureAlgorithmMismatch,
                    webpki::Error::RequiredEKUNotFound => ErrorCode::TLSErrorWebpkiRequiredEKUNotFound,
                    webpki::Error::UnknownIssuer => ErrorCode::TLSErrorWebpkiUnknownIssuer,
                    webpki::Error::UnsupportedCertVersion => ErrorCode::TLSErrorWebpkiUnsupportedCertVersion,
                    webpki::Error::UnsupportedCriticalExtension => ErrorCode::TLSErrorWebpkiUnsupportedCriticalExtension,
                    webpki::Error::UnsupportedSignatureAlgorithmForPublicKey => ErrorCode::TLSErrorWebpkiUnsupportedSignatureAlgorithmForPublicKey,
                    webpki::Error::UnsupportedSignatureAlgorithm => ErrorCode::TLSErrorWebpkiUnsupportedSignatureAlgorithm,
                },
                TLSError::InvalidSCT(_) => ErrorCode::TLSErrorInvalidSCT,
                TLSError::General(_) => ErrorCode::TLSErrorGeneral,
                TLSError::FailedToGetCurrentTime => ErrorCode::TLSErrorFailedToGetCurrentTime,
                TLSError::InvalidDNSName(_) => ErrorCode::TLSErrorInvalidDNSName,
                TLSError::HandshakeNotComplete => ErrorCode::TLSErrorHandshakeNotComplete,
                TLSError::PeerSentOversizedRecord => ErrorCode::TLSErrorPeerSentOversizedRecord,
            },
        }
    }
}

/// `ERR_load_error_strings` - compatibility only
///
/// ```c
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
/// ```c
/// #include <mesalink/openssl/err.h>
///
/// void SSL_free_error_strings(void);
/// ```
#[no_mangle]
pub extern "C" fn mesalink_ERR_free_error_strings() {
    // compatibility only
}

/// `ERR_error_string_n` - generates a human-readable string representing the
/// error code `e`, and places `len` bytes at `buf`. Note that this function is
/// not thread-safe and does no checks on the size of the buffer.
///
/// ```c
/// #include <mesalink/openssl/err.h>
///
/// void ERR_error_string_n(unsigned long e, char *buf, size_t len);
/// ```
#[no_mangle]
pub unsafe extern "C" fn mesalink_ERR_error_string_n(
    error_code: c_ulong,
    buf_ptr: *mut c_char,
    buf_len: size_t,
) -> *const c_char {
    let error_string: &'static [u8] = ErrorCode::from(error_code).as_u8_slice();
    let error_string_len = error_string.len();
    let buf_len: usize = buf_len;
    let error_string: &'static [c_char] = &*(error_string as *const [u8] as *const [c_char]);
    if buf_ptr.is_null() {
        return error_string.as_ptr() as *const c_char;
    }
    let buf = slice::from_raw_parts_mut(buf_ptr, buf_len);
    if error_string_len > buf_len {
        buf.copy_from_slice(&error_string[0..buf_len]);
        buf[buf_len - 1] = 0;
    } else {
        buf[0..error_string_len].copy_from_slice(error_string);
    }
    buf_ptr
}

/// `ERR_error_reason_error_string` - returns a human-readable string representing
/// the error code e. This API does not allocate additional memory.
///
/// ```c
/// #include <mesalink/openssl/err.h>
///
/// const char *ERR_reason_error_string(unsigned long e);
/// ```
#[no_mangle]
pub extern "C" fn mesalink_ERR_reason_error_string(e: c_ulong) -> *const c_char {
    let error_code: ErrorCode = ErrorCode::from(e);
    error_code.as_u8_slice().as_ptr() as *const c_char
}

#[doc(hidden)]
pub(crate) struct ErrorQueue {}

impl ErrorQueue {
    pub fn push_error(e: MesalinkError) {
        ERROR_QUEUE.with(|q| {
            if ErrorCode::from(&e) != ErrorCode::MesalinkErrorNone {
                q.borrow_mut().push_back(e);
            }
        });
    }
}

/// `ERR_get_error` - returns the earliest error code from the thread's error
/// queue and removes the entry. This function can be called repeatedly until
/// there are no more error codes to return.
///
/// ```c
/// #include <mesalink/openssl/err.h>
///
/// unsigned long ERR_get_error(void);
/// ```
#[no_mangle]
pub extern "C" fn mesalink_ERR_get_error() -> c_ulong {
    ERROR_QUEUE.with(|q| match q.borrow_mut().pop_front() {
        Some(e) => ErrorCode::from(&e) as c_ulong,
        None => 0,
    })
}

/// `ERR_peek_last_error` - returns the latest error code from the thread's error
/// queue without modifying it.
///
/// ```c
/// #include <mesalink/openssl/err.h>
///
/// unsigned long ERR_peek_last_error(void);
/// ```
#[no_mangle]
pub extern "C" fn mesalink_ERR_peek_last_error() -> c_ulong {
    ERROR_QUEUE.with(|q| match q.borrow().front() {
        Some(e) => ErrorCode::from(e) as c_ulong,
        None => 0,
    })
}

/// `ERR_clear_error` - empty the current thread's error queue.
///
/// ```c
/// #include <mesalink/openssl/err.h>
///
/// void ERR_clear_error(void);
/// ```
#[no_mangle]
pub extern "C" fn mesalink_ERR_clear_error() {
    ERROR_QUEUE.with(|q| {
        q.borrow_mut().clear();
    });
}

/// `ERR_print_errors_fp` - a convenience function that prints the error
/// strings for all errors that OpenSSL has recorded to `fp`, thus emptying the
/// error queue.
///
/// ```c
/// #include <mesalink/openssl/err.h>
///
/// void ERR_print_errors_fp(FILE *fp);
/// ```
#[no_mangle]
pub unsafe extern "C" fn mesalink_ERR_print_errors_fp(fp: *mut libc::FILE) {
    use crate::libcrypto::bio::FromFileStream;
    use std::io::Write;
    use std::{fs, str};
    if fp.is_null() {
        return;
    }
    let fd = libc::fileno(fp);
    if fd < 0 {
        return;
    }
    let mut file = fs::File::from_file_stream(fp);
    ERROR_QUEUE.with(|q| {
        let mut queue = q.borrow_mut();
        for e in queue.drain(0..) {
            let error_code = ErrorCode::from(&e);
            let error_string = format!(
                "error:[0x{:X}]:[mesalink]:[{}]:[{}]\n",
                error_code as c_ulong,
                e.call_site,
                str::from_utf8(error_code.as_u8_slice()).unwrap(),
            );
            let _ = file.write(error_string.as_bytes());
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr;
    use std::thread;

    macro_rules! error {
        ($code:expr) => {{
            use crate::libssl::err::MesalinkError;
            MesalinkError::new($code, call_site!())
        }};
    }

    #[test]
    fn empty() {
        assert_eq!(0, mesalink_ERR_get_error());
        mesalink_ERR_clear_error();
    }

    #[test]
    fn push() {
        let error_code = ErrorCode::MesalinkNullPointer;
        ErrorQueue::push_error(error!(MesalinkBuiltinError::NullPointer.into()));
        assert_eq!(error_code, ErrorCode::from(mesalink_ERR_get_error()));
        mesalink_ERR_clear_error();
    }

    #[test]
    fn clear() {
        ErrorQueue::push_error(error!(MesalinkBuiltinError::NullPointer.into()));
        mesalink_ERR_clear_error();
        assert_eq!(0, mesalink_ERR_get_error());
        mesalink_ERR_clear_error();
    }

    #[test]
    fn get_should_remove_error() {
        ErrorQueue::push_error(error!(MesalinkBuiltinError::NullPointer.into()));
        let _ = mesalink_ERR_get_error();
        assert_eq!(0, mesalink_ERR_get_error());
        mesalink_ERR_clear_error();
    }

    #[test]
    fn peek_should_not_remove_error() {
        let error_code = ErrorCode::MesalinkNullPointer;
        ErrorQueue::push_error(error!(MesalinkBuiltinError::NullPointer.into()));
        let _ = mesalink_ERR_peek_last_error();
        assert_eq!(error_code, ErrorCode::from(mesalink_ERR_get_error()));
        mesalink_ERR_clear_error();
    }

    #[test]
    fn error_queue_is_thread_local() {
        let thread = thread::spawn(|| {
            ErrorQueue::push_error(error!(MesalinkBuiltinError::NullPointer.into()));
            ErrorCode::from(mesalink_ERR_get_error())
        });
        ErrorQueue::push_error(error!(MesalinkBuiltinError::MalformedObject.into()));

        let main_thread_error_code = ErrorCode::from(mesalink_ERR_get_error());
        let sub_thread_error_code = thread.join().unwrap();
        assert_ne!(main_thread_error_code, sub_thread_error_code);
        mesalink_ERR_clear_error();
    }

    #[test]
    fn invalid_error_codes() {
        use std;
        assert_eq!(ErrorCode::UndefinedError, ErrorCode::from(std::u32::MAX));
        assert_eq!(ErrorCode::UndefinedError, ErrorCode::from(std::u64::MAX));
        assert_eq!(
            ErrorCode::UndefinedError,
            ErrorCode::from(std::i32::MIN as u64)
        );
        assert_eq!(
            ErrorCode::MesalinkErrorNone,
            ErrorCode::from(std::i64::MIN as u64)
        );
    }

    const ERROR_CODES: [ErrorCode; 103] = [
        ErrorCode::MesalinkErrorNone,
        ErrorCode::MesalinkErrorZeroReturn,
        ErrorCode::MesalinkErrorWantRead,
        ErrorCode::MesalinkErrorWantWrite,
        ErrorCode::MesalinkErrorWantConnect,
        ErrorCode::MesalinkErrorWantAccept,
        ErrorCode::MesalinkErrorSyscall,
        ErrorCode::MesalinkErrorSsl,
        ErrorCode::MesalinkNullPointer,
        ErrorCode::MesalinkErrorMalformedObject,
        ErrorCode::MesalinkErrorBadFuncArg,
        ErrorCode::MesalinkErrorPanic,
        ErrorCode::MesalinkErrorLock,
        ErrorCode::IoErrorNotFound,
        ErrorCode::IoErrorPermissionDenied,
        ErrorCode::IoErrorConnectionRefused,
        ErrorCode::IoErrorConnectionReset,
        ErrorCode::IoErrorConnectionAborted,
        ErrorCode::IoErrorNotConnected,
        ErrorCode::IoErrorAddrInUse,
        ErrorCode::IoErrorAddrNotAvailable,
        ErrorCode::IoErrorBrokenPipe,
        ErrorCode::IoErrorAlreadyExists,
        ErrorCode::IoErrorWouldBlock,
        ErrorCode::IoErrorInvalidInput,
        ErrorCode::IoErrorInvalidData,
        ErrorCode::IoErrorTimedOut,
        ErrorCode::IoErrorWriteZero,
        ErrorCode::IoErrorInterrupted,
        ErrorCode::IoErrorOther,
        ErrorCode::IoErrorUnexpectedEof,
        ErrorCode::TLSErrorInappropriateMessage,
        ErrorCode::TLSErrorInappropriateHandshakeMessage,
        ErrorCode::TLSErrorCorruptMessage,
        ErrorCode::TLSErrorCorruptMessagePayload,
        ErrorCode::TLSErrorCorruptMessagePayloadAlert,
        ErrorCode::TLSErrorCorruptMessagePayloadChangeCipherSpec,
        ErrorCode::TLSErrorCorruptMessagePayloadHandshake,
        ErrorCode::TLSErrorNoCertificatesPresented,
        ErrorCode::TLSErrorDecryptError,
        ErrorCode::TLSErrorPeerIncompatibleError,
        ErrorCode::TLSErrorPeerMisbehavedError,
        ErrorCode::TLSErrorAlertReceivedCloseNotify,
        ErrorCode::TLSErrorAlertReceivedUnexpectedMessage,
        ErrorCode::TLSErrorAlertReceivedBadRecordMac,
        ErrorCode::TLSErrorAlertReceivedDecryptionFailed,
        ErrorCode::TLSErrorAlertReceivedRecordOverflow,
        ErrorCode::TLSErrorAlertReceivedDecompressionFailure,
        ErrorCode::TLSErrorAlertReceivedHandshakeFailure,
        ErrorCode::TLSErrorAlertReceivedNoCertificate,
        ErrorCode::TLSErrorAlertReceivedBadCertificate,
        ErrorCode::TLSErrorAlertReceivedUnsupportedCertificate,
        ErrorCode::TLSErrorAlertReceivedCertificateRevoked,
        ErrorCode::TLSErrorAlertReceivedCertificateExpired,
        ErrorCode::TLSErrorAlertReceivedCertificateUnknown,
        ErrorCode::TLSErrorAlertReceivedIllegalParameter,
        ErrorCode::TLSErrorAlertReceivedUnknownCA,
        ErrorCode::TLSErrorAlertReceivedAccessDenied,
        ErrorCode::TLSErrorAlertReceivedDecodeError,
        ErrorCode::TLSErrorAlertReceivedDecryptError,
        ErrorCode::TLSErrorAlertReceivedExportRestriction,
        ErrorCode::TLSErrorAlertReceivedProtocolVersion,
        ErrorCode::TLSErrorAlertReceivedInsufficientSecurity,
        ErrorCode::TLSErrorAlertReceivedInternalError,
        ErrorCode::TLSErrorAlertReceivedInappropriateFallback,
        ErrorCode::TLSErrorAlertReceivedUserCanceled,
        ErrorCode::TLSErrorAlertReceivedNoRenegotiation,
        ErrorCode::TLSErrorAlertReceivedMissingExtension,
        ErrorCode::TLSErrorAlertReceivedUnsupportedExtension,
        ErrorCode::TLSErrorAlertReceivedCertificateUnobtainable,
        ErrorCode::TLSErrorAlertReceivedUnrecognisedName,
        ErrorCode::TLSErrorAlertReceivedBadCertificateStatusResponse,
        ErrorCode::TLSErrorAlertReceivedBadCertificateHashValue,
        ErrorCode::TLSErrorAlertReceivedUnknownPSKIdentity,
        ErrorCode::TLSErrorAlertReceivedCertificateRequired,
        ErrorCode::TLSErrorAlertReceivedNoApplicationProtocol,
        ErrorCode::TLSErrorAlertReceivedUnknown,
        ErrorCode::TLSErrorWebpkiBadDER,
        ErrorCode::TLSErrorWebpkiBadDERTime,
        ErrorCode::TLSErrorWebpkiCAUsedAsEndEntity,
        ErrorCode::TLSErrorWebpkiCertExpired,
        ErrorCode::TLSErrorWebpkiCertNotValidForName,
        ErrorCode::TLSErrorWebpkiCertNotValidYet,
        ErrorCode::TLSErrorWebpkiEndEntityUsedAsCA,
        ErrorCode::TLSErrorWebpkiExtensionValueInvalid,
        ErrorCode::TLSErrorWebpkiInvalidCertValidity,
        ErrorCode::TLSErrorWebpkiInvalidSignatureForPublicKey,
        ErrorCode::TLSErrorWebpkiNameConstraintViolation,
        ErrorCode::TLSErrorWebpkiPathLenConstraintViolated,
        ErrorCode::TLSErrorWebpkiSignatureAlgorithmMismatch,
        ErrorCode::TLSErrorWebpkiRequiredEKUNotFound,
        ErrorCode::TLSErrorWebpkiUnknownIssuer,
        ErrorCode::TLSErrorWebpkiUnsupportedCertVersion,
        ErrorCode::TLSErrorWebpkiUnsupportedCriticalExtension,
        ErrorCode::TLSErrorWebpkiUnsupportedSignatureAlgorithmForPublicKey,
        ErrorCode::TLSErrorWebpkiUnsupportedSignatureAlgorithm,
        ErrorCode::TLSErrorInvalidSCT,
        ErrorCode::TLSErrorGeneral,
        ErrorCode::TLSErrorFailedToGetCurrentTime,
        ErrorCode::TLSErrorInvalidDNSName,
        ErrorCode::TLSErrorHandshakeNotComplete,
        ErrorCode::TLSErrorPeerSentOversizedRecord,
        ErrorCode::UndefinedError,
    ];

    #[test]
    fn error_code_conversion_from_long() {
        for code in ERROR_CODES.into_iter() {
            assert_eq!(*code, ErrorCode::from(*code as c_ulong));
        }
    }

    #[test]
    fn mesalink_error_code_conversion() {
        let mesalink_errors: [MesalinkBuiltinError; 11] = [
            MesalinkBuiltinError::ZeroReturn,
            MesalinkBuiltinError::WantRead,
            MesalinkBuiltinError::WantWrite,
            MesalinkBuiltinError::WantConnect,
            MesalinkBuiltinError::WantAccept,
            MesalinkBuiltinError::Syscall,
            MesalinkBuiltinError::Ssl,
            MesalinkBuiltinError::NullPointer,
            MesalinkBuiltinError::MalformedObject,
            MesalinkBuiltinError::BadFuncArg,
            MesalinkBuiltinError::Panic,
        ];

        for error in mesalink_errors.into_iter() {
            use std::error::Error;
            let mesalink_error = error!(MesalinkErrorType::Builtin(error.clone()));
            let error_code = ErrorCode::from(&mesalink_error);
            println!("{}, {}", error, error.description());
            assert_eq!(true, 0 == error_code as c_ulong >> 24);
            assert_eq!(true, 0 != error_code as c_ulong & 0xFFFFFF);
        }
    }

    #[test]
    fn io_error_conversion() {
        let io_errors: [io::ErrorKind; 18] = [
            io::ErrorKind::NotFound,
            io::ErrorKind::PermissionDenied,
            io::ErrorKind::ConnectionRefused,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::ConnectionAborted,
            io::ErrorKind::NotConnected,
            io::ErrorKind::AddrInUse,
            io::ErrorKind::AddrNotAvailable,
            io::ErrorKind::BrokenPipe,
            io::ErrorKind::AlreadyExists,
            io::ErrorKind::WouldBlock,
            io::ErrorKind::InvalidInput,
            io::ErrorKind::InvalidData,
            io::ErrorKind::TimedOut,
            io::ErrorKind::WriteZero,
            io::ErrorKind::Interrupted,
            io::ErrorKind::Other,
            io::ErrorKind::UnexpectedEof,
        ];

        for error_kind in io_errors.into_iter() {
            let io_error = io::Error::from(*error_kind);
            let mesalink_error = error!(MesalinkErrorType::Io(io_error));
            let error_code = ErrorCode::from(&mesalink_error);
            assert_eq!(true, 2 == error_code as c_ulong >> 24);
            assert_eq!(true, 0 != error_code as c_ulong & 0xFFFFFF);
        }
    }

    #[test]
    fn tls_error_conversion() {
        use rustls::internal::msgs::enums::{AlertDescription, ContentType, HandshakeType};
        let tls_errors: [rustls::TLSError; 15] = [
            rustls::TLSError::InappropriateMessage {
                expect_types: vec![],
                got_type: ContentType::Heartbeat,
            },
            rustls::TLSError::InappropriateHandshakeMessage {
                expect_types: vec![],
                got_type: HandshakeType::Finished,
            },
            rustls::TLSError::CorruptMessage,
            rustls::TLSError::CorruptMessagePayload(ContentType::Heartbeat),
            rustls::TLSError::NoCertificatesPresented,
            rustls::TLSError::DecryptError,
            rustls::TLSError::PeerIncompatibleError("".to_string()),
            rustls::TLSError::PeerMisbehavedError("".to_string()),
            rustls::TLSError::AlertReceived(AlertDescription::CloseNotify),
            rustls::TLSError::WebPKIError(webpki::Error::BadDER),
            rustls::TLSError::General("".to_string()),
            rustls::TLSError::FailedToGetCurrentTime,
            rustls::TLSError::InvalidDNSName("".to_string()),
            rustls::TLSError::HandshakeNotComplete,
            rustls::TLSError::PeerSentOversizedRecord,
        ];

        for error in tls_errors.into_iter() {
            let mesalink_error = error!(MesalinkErrorType::Tls(error.clone()));
            let error_code = ErrorCode::from(&mesalink_error);
            assert_eq!(true, 3 == error_code as c_ulong >> 24);
            assert_eq!(true, 0 != error_code as c_ulong & 0xFFFFFF);
        }
    }

    #[test]
    fn webpki_error_conversion() {
        let webpki_errors: [webpki::Error; 19] = [
            webpki::Error::BadDER,
            webpki::Error::BadDERTime,
            webpki::Error::CAUsedAsEndEntity,
            webpki::Error::CertExpired,
            webpki::Error::CertNotValidForName,
            webpki::Error::CertNotValidYet,
            webpki::Error::EndEntityUsedAsCA,
            webpki::Error::ExtensionValueInvalid,
            webpki::Error::InvalidCertValidity,
            webpki::Error::InvalidSignatureForPublicKey,
            webpki::Error::NameConstraintViolation,
            webpki::Error::PathLenConstraintViolated,
            webpki::Error::SignatureAlgorithmMismatch,
            webpki::Error::RequiredEKUNotFound,
            webpki::Error::UnknownIssuer,
            webpki::Error::UnsupportedCertVersion,
            webpki::Error::UnsupportedCriticalExtension,
            webpki::Error::UnsupportedSignatureAlgorithmForPublicKey,
            webpki::Error::UnsupportedSignatureAlgorithm,
        ];

        for pki_error in webpki_errors.into_iter() {
            let error = rustls::TLSError::WebPKIError(*pki_error);
            let mesalink_error = error!(MesalinkErrorType::Tls(error));
            let error_code = ErrorCode::from(&mesalink_error);
            assert_eq!(true, 3 == error_code as c_ulong >> 24);
            assert_eq!(true, 0 != error_code as c_ulong & 0xFFFFFF);
        }
    }

    #[test]
    fn tls_alert_error_conversion() {
        use rustls::internal::msgs::enums::AlertDescription;
        let alerts: [AlertDescription; 34] = [
            AlertDescription::CloseNotify,
            AlertDescription::UnexpectedMessage,
            AlertDescription::BadRecordMac,
            AlertDescription::DecryptionFailed,
            AlertDescription::RecordOverflow,
            AlertDescription::DecompressionFailure,
            AlertDescription::HandshakeFailure,
            AlertDescription::NoCertificate,
            AlertDescription::BadCertificate,
            AlertDescription::UnsupportedCertificate,
            AlertDescription::CertificateRevoked,
            AlertDescription::CertificateExpired,
            AlertDescription::CertificateUnknown,
            AlertDescription::IllegalParameter,
            AlertDescription::UnknownCA,
            AlertDescription::AccessDenied,
            AlertDescription::DecodeError,
            AlertDescription::DecryptError,
            AlertDescription::ExportRestriction,
            AlertDescription::ProtocolVersion,
            AlertDescription::InsufficientSecurity,
            AlertDescription::InternalError,
            AlertDescription::InappropriateFallback,
            AlertDescription::UserCanceled,
            AlertDescription::NoRenegotiation,
            AlertDescription::MissingExtension,
            AlertDescription::UnsupportedExtension,
            AlertDescription::CertificateUnobtainable,
            AlertDescription::UnrecognisedName,
            AlertDescription::BadCertificateStatusResponse,
            AlertDescription::BadCertificateHashValue,
            AlertDescription::UnknownPSKIdentity,
            AlertDescription::CertificateRequired,
            AlertDescription::NoApplicationProtocol,
        ];

        for alert in alerts.into_iter() {
            let error = rustls::TLSError::AlertReceived(*alert);
            let mesalink_error = error!(MesalinkErrorType::Tls(error));
            let error_code = ErrorCode::from(&mesalink_error);
            assert_eq!(true, 3 == error_code as c_ulong >> 24);
            assert_eq!(true, 0 != error_code as c_ulong & 0xFFFFFF);
        }
    }

    #[test]
    fn error_strings() {
        for code in ERROR_CODES.into_iter() {
            let error_string_ptr: *const c_char =
                mesalink_ERR_reason_error_string(*code as c_ulong);
            assert_ne!(ptr::null(), error_string_ptr);
            let len = unsafe { libc::strlen(error_string_ptr) };
            let ptr = code.as_u8_slice().as_ptr() as *const c_char;
            assert_eq!(0, unsafe { libc::strncmp(ptr, error_string_ptr, len) });
        }
    }

    #[test]
    fn error_string_n_with_big_buf() {
        let mut buf = [0u8; 256];
        let buf_ptr = buf.as_mut_ptr() as *mut c_char;
        for code in ERROR_CODES.into_iter() {
            let builtin_error_string_ptr: *const c_char =
                mesalink_ERR_reason_error_string(*code as c_ulong);
            let buf_error_string_ptr =
                unsafe { mesalink_ERR_error_string_n(*code as c_ulong, buf_ptr, buf.len()) };
            let builtin_error_string_len = unsafe { libc::strlen(builtin_error_string_ptr) };
            let buf_error_string_len = unsafe { libc::strlen(buf_error_string_ptr) };
            assert_eq!(buf_error_string_len, builtin_error_string_len);
            assert_eq!(0, unsafe {
                libc::strncmp(
                    builtin_error_string_ptr,
                    buf_error_string_ptr,
                    builtin_error_string_len,
                )
            });
            assert_eq!(false, builtin_error_string_ptr == buf_error_string_ptr);
        }
    }

    #[test]
    fn error_string_n_with_small_buf() {
        const BUF_SIZE: usize = 10;
        let mut buf = [0u8; BUF_SIZE];
        let buf_ptr = buf.as_mut_ptr() as *mut c_char;
        for code in ERROR_CODES.into_iter() {
            let builtin_error_string_ptr: *const c_char =
                mesalink_ERR_reason_error_string(*code as c_ulong);
            let buf_error_string_ptr =
                unsafe { mesalink_ERR_error_string_n(*code as c_ulong, buf_ptr, buf.len()) };
            let buf_error_string_len = unsafe { libc::strlen(buf_error_string_ptr) };
            //assert_eq!(buf_error_string_len, buf_error_string_len);
            assert_eq!(0, unsafe {
                libc::strncmp(
                    builtin_error_string_ptr,
                    buf_error_string_ptr,
                    buf_error_string_len,
                )
            });
            assert_eq!(false, builtin_error_string_ptr == buf_error_string_ptr);
        }
    }

    #[test]
    fn error_string_n_with_null_buf() {
        for code in ERROR_CODES.into_iter() {
            let builtin_error_string_ptr: *const c_char =
                mesalink_ERR_reason_error_string(*code as c_ulong);
            let buf_error_string_ptr = unsafe {
                mesalink_ERR_error_string_n(*code as c_ulong, ptr::null_mut() as *mut c_char, 0)
            };

            let builtin_error_string_len = unsafe { libc::strlen(builtin_error_string_ptr) };
            let buf_error_string_len = unsafe { libc::strlen(buf_error_string_ptr) };
            assert_eq!(buf_error_string_len, builtin_error_string_len);
            assert_eq!(0, unsafe {
                libc::strncmp(
                    builtin_error_string_ptr,
                    buf_error_string_ptr,
                    builtin_error_string_len,
                )
            });
            assert_eq!(true, builtin_error_string_ptr == buf_error_string_ptr);
        }
    }

    #[test]
    fn err_print_errors_fp() {
        use crate::libcrypto::bio::OpenFileStream;
        use std::io;

        mesalink_ERR_load_error_strings();
        ErrorQueue::push_error(error!(MesalinkBuiltinError::None.into()));
        ErrorQueue::push_error(error!(MesalinkBuiltinError::BadFuncArg.into()));
        ErrorQueue::push_error(error!(MesalinkBuiltinError::MalformedObject.into()));
        let stderr = io::stderr();
        let file = unsafe { stderr.open_file_stream_w() };
        unsafe {
            mesalink_ERR_print_errors_fp(file);
            mesalink_ERR_print_errors_fp(ptr::null_mut());
        }
        mesalink_ERR_clear_error();
        mesalink_ERR_free_error_strings();
    }
}
