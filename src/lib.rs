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

//! # MesaLink
//! MesaLink is a memory-safe and OpenSSL-compatible TLS library.
//!
//! MesaLink and its dependencies are written in
//! [Rust](https://www.rust-lang.org), a programming language that guarantees
//! memory safety. Furthermore, MesaLink makes it a breeze to port an existing
//! OpenSSL application thanks to its OpenSSL-compatible C APIs. Please refer to
//! the examples to see how MesaLink can serve as a drop-in replacement for
//! OpenSSL.
//!
//! ## Feature highlights
//!
//! MesaLink depends on two Rust crates: [rustls](https://github.com/ctz/rustls)
//! and [ring](https://github.com/briansmith/ring). With them, MesaLink provides
//! the following features that are considered secure for most use cases:
//!
//! * TLS 1.2 and TLS 1.3 draft 18
//! * Server Name Indication (SNI)
//! * Forced hostname validation
//! * Safe and fast crypto implementations from Google's BoringSSL
//! * ECDHE key exchange with forward secrecy
//! * AES-GCM and Chacha20Poly1305 bulk encryption
//! * Built-in Mozilla's CA root certificates
//!
//! ## Bullets dodged
//!
//! This section lists a few vulnerabilities that affected other TLS libraries
//! in 2017 but would not be possible in MesaLink.
//!
//! * [CVE-2017-3730](https://www.cvedetails.com/cve/CVE-2017-3730/) In OpenSSL
//!   1.1.0 before 1.1.0d, if a malicious server supplies bad parameters for a
//!   DHE or ECDHE key exchange then this can result in the client attempting to
//!   dereference a NULL pointer leading to a client crash. This could be
//!   exploited in a Denial of Service attack.
//! * [CVE-2017-3735](https://www.cvedetails.com/cve/CVE-2017-3735/): While
//!   OpenSSL parses an IPAddressFamily extension in an X.509 certificate, it is
//!   possible to do a one-byte overread.
//! * [CVE-2017-2784](https://www.cvedetails.com/cve/CVE-2017-2784/): An
//!   exploitable free of a stack pointer vulnerability exists in the x509
//!   certificate parsing code of ARM mbed TLS before 1.3.19, 2.x before 2.1.7,
//!   and 2.4.x before 2.4.2.
//! * [CVE-2017-2800](https://www.cvedetails.com/cve/CVE-2017-2800/): A
//!   specially crafted x509 certificate can cause a single out of bounds byte
//!   overwrite in wolfSSL through 3.10.2 resulting in potential certificate
//!   validation vulnerabilities, denial of service and possible remote code
//!   execution. 
//! * [CVE-2017-8854](https://www.cvedetails.com/cve/CVE-2017-8854/): wolfSSL
//!   before 3.10.2 has an out-of-bounds memory access with loading crafted DH
//!   parameters, aka a buffer overflow triggered by a malformed temporary DH
//!   file.
//!
//! ## Building
//! MesaLink requires autotools and a [Rust toolchain](https://www.rustup.rs/)
//! to build. Building is easy.
//!
//! ```
//! $ autoreconf -i
//! $ ./configure
//! $ make
//! ```
//!
//! CMake support will be introduced in future releases.
//! 
//! ## Examples
//! MesaLink comes with two examples that demonstrate a TLS client and a TLS
//! server.
//!
//! ### A sample run of the client example program
//!
//! ```
//! $ ./examples/client/client api.ipify.org
//! [+] Requesting api.ipify.org ...
//! [+] Sent 85 bytes
//!
//! GET / HTTP/1.1
//! Host: api.ipify.org
//! Connection: close
//! Accept-Encoding: identity
//!
//! HTTP/1.1 200 OK
//! Server: Cowboy
//! Connection: close
//! Content-Type: text/plain
//! Vary: Origin
//! Date: Fri, 15 Dec 2017 19:46:36 GMT
//! Content-Length: 10
//! Via: 1.1 vegur
//!
//! 1.2.3.4
//! [+] Received 177 bytes
//! ```
//!
//! ### A sample run of the server example program
//! 
//! This example comes with a pair of certificate and private key. The
//! certificate file is in PEM format and contains a chain of certificates from
//! the server's certificate to the root CA certificate. The private key file
//! contains a PKCS8-encoded private key in PEM format. Once the server is up
//! and running, open [https://127.0.0.1:8443](https://127.0.0.1:8443) and
//! expect to see the hello message. 
//!
//! ```
//! $ ./examples/server/server
//! Usage: ./examples/server/server <portnum> <cert_file> <private_key_file>
//! $ cd examples/server/server
//! $ ./server 8443 certificates private_key
//! [+] Listening at 0.0.0.0:8443
//! [+] Received:
//! GET / HTTP/1.1
//! Host: 127.0.0.1:8443
//! Connection: keep-alive
//! User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_2) AppleWebKit/537.36 
//! (KHTML, like Gecko) Chrome/63.0.3239.84 Safari/537.36
//! Upgrade-Insecure-Requests: 1
//! Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng
//! Accept-Encoding: gzip, deflate, br
//! Accept-Language: en-US,en;q=0.9
//! ```
//!
//!

#![deny(trivial_numeric_casts, unstable_features, unused_qualifications)]
#![forbid(anonymous_parameters, unused_extern_crates, unused_import_braces,
          unused_results, variant_size_differences, warnings)]

// libc for libc bindings
extern crate libc;

// *ring* for cryptography
extern crate ring;

// rustls for TLS; only TLS 1.2 and 1.3 draft 22 are supported
extern crate rustls;

// webpki for certificate verification
extern crate webpki;

// webpki_roots for Mozilla's CA certificates
extern crate webpki_roots;

// lazy_static for defining static variables
#[macro_use]
extern crate lazy_static;

// enum_to_str_derive for human-readable error numbers
#[cfg(feature="error_strings")]
#[macro_use] extern crate enum_to_str_derive;

/// The ssl module is the counterpart of the OpenSSL ssl library.
pub mod ssl;

/// The crypo module is the counterpart of the OpenSSL crypto library.
pub mod crypto;
