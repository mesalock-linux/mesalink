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
//! ```
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
//!   IO_ERROR_NOT_FOUND = 0x02000001,
//!   IO_ERROR_PERMISSION_DENIED = 0x02000002,
//!   IO_ERROR_CONNECTION_REFUSED = 0x02000003,
//!   IO_ERROR_CONNECTION_RESET = 0x02000004,
//!   IO_ERROR_CONNECTION_ABORTED = 0x02000005,
//!   IO_ERROR_NOT_CONNECTED = 0x02000006,
//!   IO_ERROR_ADDR_IN_USE = 0x02000007,
//!   IO_ERROR_ADDR_NOT_AVAILABLE = 0x02000008,
//!   IO_ERROR_BROKEN_PIPE = 0x02000009,
//!   IO_ERROR_ALREADY_EXISTS = 0x0200000a,
//!   IO_ERROR_WOULD_BLOCK = 0x0200000b,
//!   IO_ERROR_INVALID_INPUT = 0x0200000c,
//!   IO_ERROR_INVALID_DATA = 0x0200000d,
//!   IO_ERROR_TIMED_OUT = 0x0200000e,
//!   IO_ERROR_WRITE_ZERO = 0x0200000f,
//!   IO_ERROR_INTERRUPTED = 0x02000010,
//!   IO_ERROR_OTHER = 0x02000011,
//!   IO_ERROR_UNEXPECTED_EOF = 0x02000012,
//!   TLS_ERROR_INAPPROPRIATE_MESSAGE = 0x03000100,
//!   TLS_ERROR_INAPPROPRIATE_HANDSHAKE_MESSAGE = 0x03000200,
//!   TLS_ERROR_CORRUPT_MESSAGE = 0x03000300,
//!   TLS_ERROR_CORRUPT_MESSAGE_PAYLOAD = 0x03000400,
//!   TLS_ERROR_CORRUPT_MESSAGE_PAYLOAD_ALERT = 0x03000401,
//!   TLS_ERROR_CORRUPT_MESSAGE_PAYLOAD_CHANGE_CIPHER_SPEC = 0x03000402,
//!   TLS_ERROR_CORRUPT_MESSAGE_PAYLOAD_HANDSHAKE = 0x03000403,
//!   TLS_ERROR_NO_CERTIFICATES_PRESENTED = 0x03000500,
//!   TLS_ERROR_DECRYPT_ERROR = 0x03000600,
//!   TLS_ERROR_PEER_INCOMPATIBLE_ERROR = 0x03000700,
//!   TLS_ERROR_PEER_MISBEHAVED_ERROR = 0x03000800,
//!   TLS_ERROR_ALERT_RECEIVED_CLOSE_NOTIFY = 0x03000901,
//!   TLS_ERROR_ALERT_RECEIVED_UNEXPECTED_MESSAGE = 0x03000902,
//!   TLS_ERROR_ALERT_RECEIVED_BAD_RECORD_MAC = 0x03000903,
//!   TLS_ERROR_ALERT_RECEIVED_DECRYPTION_FAILED = 0x03000904,
//!   TLS_ERROR_ALERT_RECEIVED_RECORD_OVERFLOW = 0x03000905,
//!   TLS_ERROR_ALERT_RECEIVED_DECOMPRESSION_FAILURE = 0x03000906,
//!   TLS_ERROR_ALERT_RECEIVED_HANDSHAKE_FAILURE = 0x03000907,
//!   TLS_ERROR_ALERT_RECEIVED_NO_CERTIFICATE = 0x03000908,
//!   TLS_ERROR_ALERT_RECEIVED_BAD_CERTIFICATE = 0x03000909,
//!   TLS_ERROR_ALERT_RECEIVED_UNSUPPORTED_CERTIFICATE = 0x0300090a,
//!   TLS_ERROR_ALERT_RECEIVED_CERTIFICATE_REVOKED = 0x0300090b,
//!   TLS_ERROR_ALERT_RECEIVED_CERTIFICATE_EXPIRED = 0x0300090c,
//!   TLS_ERROR_ALERT_RECEIVED_CERTIFICATE_UNKNOWN = 0x0300090d,
//!   TLS_ERROR_ALERT_RECEIVED_ILLEGAL_PARAMETER = 0x0300090e,
//!   TLS_ERROR_ALERT_RECEIVED_UNKNOWN_CA = 0x0300090f,
//!   TLS_ERROR_ALERT_RECEIVED_ACCESS_DENIED = 0x03000910,
//!   TLS_ERROR_ALERT_RECEIVED_DECODE_ERROR = 0x03000911,
//!   TLS_ERROR_ALERT_RECEIVED_DECRYPT_ERROR = 0x03000912,
//!   TLS_ERROR_ALERT_RECEIVED_EXPORT_RESTRICTION = 0x03000913,
//!   TLS_ERROR_ALERT_RECEIVED_PROTOCOL_VERSION = 0x03000914,
//!   TLS_ERROR_ALERT_RECEIVED_INSUFFICIENT_SECURITY = 0x03000915,
//!   TLS_ERROR_ALERT_RECEIVED_INTERNAL_ERROR = 0x03000916,
//!   TLS_ERROR_ALERT_RECEIVED_INAPPROPRIATE_FALLBACK = 0x03000917,
//!   TLS_ERROR_ALERT_RECEIVED_USER_CANCELED = 0x03000918,
//!   TLS_ERROR_ALERT_RECEIVED_NO_RENEGOTIATION = 0x03000919,
//!   TLS_ERROR_ALERT_RECEIVED_MISSING_EXTENSION = 0x0300091a,
//!   TLS_ERROR_ALERT_RECEIVED_UNSUPPORTED_EXTENSION = 0x0300091b,
//!   TLS_ERROR_ALERT_RECEIVED_CERTIFICATE_UNOBTAINABLE = 0x0300091c,
//!   TLS_ERROR_ALERT_RECEIVED_UNRECOGNISED_NAME = 0x0300091d,
//!   TLS_ERROR_ALERT_RECEIVED_BAD_CERTIFICATE_STATUS_RESPONSE = 0x0300091e,
//!   TLS_ERROR_ALERT_RECEIVED_BAD_CERTIFICATE_HASH_VALUE = 0x0300091f,
//!   TLS_ERROR_ALERT_RECEIVED_UNKNOWN_PSK_IDENTITY = 0x03000920,
//!   TLS_ERROR_ALERT_RECEIVED_CERTIFICATE_REQUIRED = 0x03000921,
//!   TLS_ERROR_ALERT_RECEIVED_NO_APPLICATION_PROTOCOL = 0x03000922,
//!   TLS_ERROR_ALERT_RECEIVED_UNKNOWN = 0x030009ff,
//!   TLS_ERROR_WEBPKI_BAD_DER = 0x03000a01,
//!   TLS_ERROR_WEBPKI_BAD_DER_TIME = 0x03000a02,
//!   TLS_ERROR_WEBPKI_CA_USED_AS_END_ENTITY = 0x03000a03,
//!   TLS_ERROR_WEBPKI_CERT_EXPIRED = 0x03000a04,
//!   TLS_ERROR_WEBPKI_CERT_NOT_VALID_FOR_NAME = 0x03000a05,
//!   TLS_ERROR_WEBPKI_CERT_NOT_VALID_YET = 0x03000a06,
//!   TLS_ERROR_WEBPKI_END_ENTITY_USED_AS_CA = 0x03000a07,
//!   TLS_ERROR_WEBPKI_EXTENSION_VALUE_INVALID = 0x03000a08,
//!   TLS_ERROR_WEBPKI_INVALID_CERT_VALIDITY = 0x03000a09,
//!   TLS_ERROR_WEBPKI_INVALID_SIGNATURE_FOR_PUBLIC_KEY = 0x03000a0a,
//!   TLS_ERROR_WEBPKI_NAME_CONSTRAINT_VIOLATION = 0x03000a0b,
//!   TLS_ERROR_WEBPKI_PATH_LEN_CONSTRAINT_VIOLATED = 0x03000a0c,
//!   TLS_ERROR_WEBPKI_SIGNATURE_ALGORITHM_MISMATCH = 0x03000a0d,
//!   TLS_ERROR_WEBPKI_REQUIRED_EKU_NOT_FOUND = 0x03000a0e,
//!   TLS_ERROR_WEBPKI_UNKNOWN_ISSUER = 0x03000a0f,
//!   TLS_ERROR_WEBPKI_UNSUPPORTED_CERT_VERSION = 0x03000a10,
//!   TLS_ERROR_WEBPKI_UNSUPPORTED_CRITICAL_EXTENSION = 0x03000a11,
//!   TLS_ERROR_WEBPKI_UNSUPPORTED_SIGNATURE_ALGORITHM_FOR_PUBLIC_KEY = 0x03000a12,
//!   TLS_ERROR_WEBPKI_UNSUPPORTED_SIGNATURE_ALGORITHM = 0x03000a13,
//!   TLS_ERROR_INVALID_SCT = 0x03000b00,
//!   TLS_ERROR_GENERAL = 0x03000c00,
//!   TLS_ERROR_FAILED_TO_GET_CURRENT_TIME = 0x03000d00,
//!   TLS_ERROR_INVALID_DNS_NAME = 0x03000e00,
//!   TLS_ERROR_HANDSHAKE_NOT_COMPLETE = 0x03000f00,
//!   TLS_ERROR_PEER_SENT_OVERSIZED_RECORD = 0x03001000,
//!   UNDEFINED_ERROR = 0xeeeeeeee,
//! ```

use libc::{self, c_char, c_ulong, size_t};
use std::io;
use rustls;
use webpki;

use std::cell::RefCell;
use std::collections::VecDeque;

thread_local! {
    static ERROR_QUEUE: RefCell<VecDeque<ErrorCode>> = RefCell::new(VecDeque::new());
}

#[doc(hidden)]
#[repr(C)]
#[derive(Clone, Copy)]
#[cfg_attr(feature = "error_strings", derive(EnumToStr))]
#[cfg_attr(feature = "error_strings", derive(Debug))]
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
    #[cfg(feature = "error_strings")]
    pub fn as_str(&self) -> &'static [u8] {
        self.enum_to_str()
    }

    #[cfg(not(feature = "error_strings"))]
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
        match e {
            0 => ErrorCode::MesalinkErrorNone,
            1 => ErrorCode::MesalinkErrorZeroReturn,
            2 => ErrorCode::MesalinkErrorWantRead,
            3 => ErrorCode::MesalinkErrorWantWrite,
            7 => ErrorCode::MesalinkErrorWantConnect,
            8 => ErrorCode::MesalinkErrorWantAccept,
            5 => ErrorCode::MesalinkErrorSyscall,
            0x55 => ErrorCode::MesalinkErrorSsl,
            0xe0 => ErrorCode::MesalinkErrorNullPointer,
            0xe1 => ErrorCode::MesalinkErrorMalformedObject,
            0x02000001 => ErrorCode::IoErrorNotFound,
            0x02000002 => ErrorCode::IoErrorPermissionDenied,
            0x02000003 => ErrorCode::IoErrorConnectionRefused,
            0x02000004 => ErrorCode::IoErrorConnectionReset,
            0x02000005 => ErrorCode::IoErrorConnectionAborted,
            0x02000006 => ErrorCode::IoErrorNotConnected,
            0x02000007 => ErrorCode::IoErrorAddrInUse,
            0x02000008 => ErrorCode::IoErrorAddrNotAvailable,
            0x02000009 => ErrorCode::IoErrorBrokenPipe,
            0x0200000a => ErrorCode::IoErrorAlreadyExists,
            0x0200000b => ErrorCode::IoErrorWouldBlock,
            0x0200000c => ErrorCode::IoErrorInvalidInput,
            0x0200000d => ErrorCode::IoErrorInvalidData,
            0x0200000e => ErrorCode::IoErrorTimedOut,
            0x0200000f => ErrorCode::IoErrorWriteZero,
            0x02000010 => ErrorCode::IoErrorInterrupted,
            0x02000011 => ErrorCode::IoErrorOther,
            0x02000012 => ErrorCode::IoErrorUnexpectedEof,
            0x03000100 => ErrorCode::TLSErrorInappropriateMessage,
            0x03000200 => ErrorCode::TLSErrorInappropriateHandshakeMessage,
            0x03000300 => ErrorCode::TLSErrorCorruptMessage,
            0x03000400 => ErrorCode::TLSErrorCorruptMessagePayload,
            0x03000401 => ErrorCode::TLSErrorCorruptMessagePayloadAlert,
            0x03000402 => ErrorCode::TLSErrorCorruptMessagePayloadChangeCipherSpec,
            0x03000403 => ErrorCode::TLSErrorCorruptMessagePayloadHandshake,
            0x03000500 => ErrorCode::TLSErrorNoCertificatesPresented,
            0x03000600 => ErrorCode::TLSErrorDecryptError,
            0x03000700 => ErrorCode::TLSErrorPeerIncompatibleError,
            0x03000800 => ErrorCode::TLSErrorPeerMisbehavedError,
            0x03000901 => ErrorCode::TLSErrorAlertReceivedCloseNotify,
            0x03000902 => ErrorCode::TLSErrorAlertReceivedUnexpectedMessage,
            0x03000903 => ErrorCode::TLSErrorAlertReceivedBadRecordMac,
            0x03000904 => ErrorCode::TLSErrorAlertReceivedDecryptionFailed,
            0x03000905 => ErrorCode::TLSErrorAlertReceivedRecordOverflow,
            0x03000906 => ErrorCode::TLSErrorAlertReceivedDecompressionFailure,
            0x03000907 => ErrorCode::TLSErrorAlertReceivedHandshakeFailure,
            0x03000908 => ErrorCode::TLSErrorAlertReceivedNoCertificate,
            0x03000909 => ErrorCode::TLSErrorAlertReceivedBadCertificate,
            0x0300090a => ErrorCode::TLSErrorAlertReceivedUnsupportedCertificate,
            0x0300090b => ErrorCode::TLSErrorAlertReceivedCertificateRevoked,
            0x0300090c => ErrorCode::TLSErrorAlertReceivedCertificateExpired,
            0x0300090d => ErrorCode::TLSErrorAlertReceivedCertificateUnknown,
            0x0300090e => ErrorCode::TLSErrorAlertReceivedIllegalParameter,
            0x0300090f => ErrorCode::TLSErrorAlertReceivedUnknownCA,
            0x03000910 => ErrorCode::TLSErrorAlertReceivedAccessDenied,
            0x03000911 => ErrorCode::TLSErrorAlertReceivedDecodeError,
            0x03000912 => ErrorCode::TLSErrorAlertReceivedDecryptError,
            0x03000913 => ErrorCode::TLSErrorAlertReceivedExportRestriction,
            0x03000914 => ErrorCode::TLSErrorAlertReceivedProtocolVersion,
            0x03000915 => ErrorCode::TLSErrorAlertReceivedInsufficientSecurity,
            0x03000916 => ErrorCode::TLSErrorAlertReceivedInternalError,
            0x03000917 => ErrorCode::TLSErrorAlertReceivedInappropriateFallback,
            0x03000918 => ErrorCode::TLSErrorAlertReceivedUserCanceled,
            0x03000919 => ErrorCode::TLSErrorAlertReceivedNoRenegotiation,
            0x0300091a => ErrorCode::TLSErrorAlertReceivedMissingExtension,
            0x0300091b => ErrorCode::TLSErrorAlertReceivedUnsupportedExtension,
            0x0300091c => ErrorCode::TLSErrorAlertReceivedCertificateUnobtainable,
            0x0300091d => ErrorCode::TLSErrorAlertReceivedUnrecognisedName,
            0x0300091e => ErrorCode::TLSErrorAlertReceivedBadCertificateStatusResponse,
            0x0300091f => ErrorCode::TLSErrorAlertReceivedBadCertificateHashValue,
            0x03000920 => ErrorCode::TLSErrorAlertReceivedUnknownPSKIdentity,
            0x03000921 => ErrorCode::TLSErrorAlertReceivedCertificateRequired,
            0x03000922 => ErrorCode::TLSErrorAlertReceivedNoApplicationProtocol,
            0x030009ff => ErrorCode::TLSErrorAlertReceivedUnknown,
            0x03000a01 => ErrorCode::TLSErrorWebpkiBadDER,
            0x03000a02 => ErrorCode::TLSErrorWebpkiBadDERTime,
            0x03000a03 => ErrorCode::TLSErrorWebpkiCAUsedAsEndEntity,
            0x03000a04 => ErrorCode::TLSErrorWebpkiCertExpired,
            0x03000a05 => ErrorCode::TLSErrorWebpkiCertNotValidForName,
            0x03000a06 => ErrorCode::TLSErrorWebpkiCertNotValidYet,
            0x03000a07 => ErrorCode::TLSErrorWebpkiEndEntityUsedAsCA,
            0x03000a08 => ErrorCode::TLSErrorWebpkiExtensionValueInvalid,
            0x03000a09 => ErrorCode::TLSErrorWebpkiInvalidCertValidity,
            0x03000a0a => ErrorCode::TLSErrorWebpkiInvalidSignatureForPublicKey,
            0x03000a0b => ErrorCode::TLSErrorWebpkiNameConstraintViolation,
            0x03000a0c => ErrorCode::TLSErrorWebpkiPathLenConstraintViolated,
            0x03000a0d => ErrorCode::TLSErrorWebpkiSignatureAlgorithmMismatch,
            0x03000a0e => ErrorCode::TLSErrorWebpkiRequiredEKUNotFound,
            0x03000a0f => ErrorCode::TLSErrorWebpkiUnknownIssuer,
            0x03000a10 => ErrorCode::TLSErrorWebpkiUnsupportedCertVersion,
            0x03000a11 => ErrorCode::TLSErrorWebpkiUnsupportedCriticalExtension,
            0x03000a12 => ErrorCode::TLSErrorWebpkiUnsupportedSignatureAlgorithmForPublicKey,
            0x03000a13 => ErrorCode::TLSErrorWebpkiUnsupportedSignatureAlgorithm,
            0x03000b00 => ErrorCode::TLSErrorInvalidSCT,
            0x03000c00 => ErrorCode::TLSErrorGeneral,
            0x03000d00 => ErrorCode::TLSErrorFailedToGetCurrentTime,
            0x03000e00 => ErrorCode::TLSErrorInvalidDNSName,
            0x03000f00 => ErrorCode::TLSErrorHandshakeNotComplete,
            0x03001000 => ErrorCode::TLSErrorPeerSentOversizedRecord,
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
impl MesalinkErrorType for rustls::TLSError {}
impl MesalinkErrorType for io::Error {}

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
impl<'a> From<&'a io::Error> for ErrorCode {
    fn from(e: &'a io::Error) -> ErrorCode {
        match e.kind() {
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
        }
    }
}

#[doc(hidden)]
#[allow(unused_variables)]
impl<'a> From<&'a rustls::TLSError> for ErrorCode {
    fn from(e: &'a rustls::TLSError) -> ErrorCode {
        use rustls::TLSError;
        use rustls::internal::msgs::enums::{AlertDescription, ContentType};
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
                AlertDescription::DecryptionFailed => {
                    ErrorCode::TLSErrorAlertReceivedDecryptionFailed
                }
                AlertDescription::RecordOverflow => ErrorCode::TLSErrorAlertReceivedRecordOverflow,
                AlertDescription::DecompressionFailure => {
                    ErrorCode::TLSErrorAlertReceivedDecompressionFailure
                }
                AlertDescription::HandshakeFailure => {
                    ErrorCode::TLSErrorAlertReceivedHandshakeFailure
                }
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
                AlertDescription::IllegalParameter => {
                    ErrorCode::TLSErrorAlertReceivedIllegalParameter
                }
                AlertDescription::UnknownCA => ErrorCode::TLSErrorAlertReceivedUnknownCA,
                AlertDescription::AccessDenied => ErrorCode::TLSErrorAlertReceivedAccessDenied,
                AlertDescription::DecodeError => ErrorCode::TLSErrorAlertReceivedDecodeError,
                AlertDescription::DecryptError => ErrorCode::TLSErrorAlertReceivedDecryptError,
                AlertDescription::ExportRestriction => {
                    ErrorCode::TLSErrorAlertReceivedExportRestriction
                }
                AlertDescription::ProtocolVersion => {
                    ErrorCode::TLSErrorAlertReceivedProtocolVersion
                }
                AlertDescription::InsufficientSecurity => {
                    ErrorCode::TLSErrorAlertReceivedInsufficientSecurity
                }
                AlertDescription::InternalError => ErrorCode::TLSErrorAlertReceivedInternalError,
                AlertDescription::InappropriateFallback => {
                    ErrorCode::TLSErrorAlertReceivedInappropriateFallback
                }
                AlertDescription::UserCanceled => ErrorCode::TLSErrorAlertReceivedUserCanceled,
                AlertDescription::NoRenegotiation => {
                    ErrorCode::TLSErrorAlertReceivedNoRenegotiation
                }
                AlertDescription::MissingExtension => {
                    ErrorCode::TLSErrorAlertReceivedMissingExtension
                }
                AlertDescription::UnsupportedExtension => {
                    ErrorCode::TLSErrorAlertReceivedUnsupportedExtension
                }
                AlertDescription::CertificateUnobtainable => {
                    ErrorCode::TLSErrorAlertReceivedCertificateUnobtainable
                }
                AlertDescription::UnrecognisedName => {
                    ErrorCode::TLSErrorAlertReceivedUnrecognisedName
                }
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
                webpki::Error::ExtensionValueInvalid => {
                    ErrorCode::TLSErrorWebpkiExtensionValueInvalid
                }
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
    use std::{ffi, thread};
    let tid = thread::current().id();
    ERROR_QUEUE.with(|f| {
        let mut queue = f.borrow_mut();
        for err in queue.drain(0..) {
            let description_c = ffi::CString::new(err.as_str());
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
