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

//! # MesaLink: A safe, secure and OpenSSL-compatible TLS library
//!
//! Mesalink is a OpenSSL-compatible TLS library written in Rust, a programming
//! language that guaranteed memory safety and thread safety.
//!
//! ## Feature highlights
//!
//!  * **Memory safety**. MesaLink and its dependencies are written in
//!    [Rust](https://www.rust-lang.org), a programming language that guarantees
//!    memory safety. This extremely reduces attack surfaces of an TLS stack
//!    exposed in the wild, leaving the remaining attack surfaces auditable and
//!    restricted.
//!  * **Flexibility**. MesaLink offers flexible configurations tailored to
//!    various needs, for example IoT, connected home, automobiles, the cloud
//!    and more.
//!  * **Simplicity**. MesaLink does not support obselete or legacy TLS
//!    features, in case that misconfigurations introduce vulnerabilities.
//!  * **Compatibility**. MesaLink provides OpenSSL-compatible APIs. This makes
//!    it a breeze to port an existing OpenSSL project.
//!  * **Future proof**. MesaLink will support quantum-safe ciphersuites,
//!    safe-guarding TLS connections against even quantum computers.
//!
//! MesaLink depends on two Rust crates: [rustls](https://github.com/ctz/rustls)
//! and [sct](https://github.com/ctz/sct.rs). With them, MesaLink provides the
//! following features that are considered secure for most use cases:
//!
//! * TLS 1.2 and TLS 1.3 draft 23
//! * ECDSA or RSA server authentication
//! * Forced hostname validation
//! * Forward secrecy using ECDHE; with curve25519, nistp256 or nistp384 curves.
//! * Safe and fast crypto primitives from BoringSSL
//! * AES-128-GCM, AES-256-GCM and Chacha20-Poly1305 bulk encryption
//! * Built-in Mozilla's CA root certificates
//!

#![deny(trivial_numeric_casts, unused_qualifications)]
#![forbid(anonymous_parameters, unused_import_braces, unused_results, warnings)]

// libc for libc bindings
extern crate libc;

// *ring* for cryptography
extern crate ring;

// rustls for TLS; only TLS 1.2 and 1.3 draft 22 are supported
extern crate rustls;

// webpki for certificate verification
extern crate webpki;

// untrusted for parsing ASN.1 DER
extern crate untrusted;

// webpki_roots for Mozilla's CA certificates
extern crate webpki_roots;

// env_logger for logging rustls internal logs
extern crate env_logger;

// lazy_static for defining static variables
#[macro_use]
extern crate lazy_static;

// bitflags for C-style bitmask flags
#[macro_use]
extern crate bitflags;

// base64 for decoding PEM files
extern crate base64;

// enum_to_str_derive for human-readable error numbers
#[cfg(feature = "error_strings")]
#[macro_use]
extern crate enum_to_u8_slice_derive;

use ring::rand;
use ring::rand::SecureRandom;

#[doc(hidden)]
pub(self) const MAGIC_SIZE: usize = 4;

lazy_static! {
    #[doc(hidden)]
    pub(self) static ref MAGIC: [u8; MAGIC_SIZE] = {
        let mut number = [0u8; MAGIC_SIZE];
        if rand::SystemRandom::new().fill(&mut number).is_ok() {
            number
        } else {
            panic!("Getrandom error");
        }
    };
}

#[doc(hidden)]
pub(crate) trait MesalinkOpaquePointerType {
    fn check_magic(&self) -> bool;
}

#[macro_use]
mod macros;

#[macro_use]
mod error_san;

/// The ssl module is the counterpart of the OpenSSL ssl library.
pub mod libssl;

/// The crypo module is the counterpart of the OpenSSL crypto library.
pub mod libcrypto;
