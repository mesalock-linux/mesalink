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
//! To get better functionality along with strong security guarantees, MesaLink
//! follows the following rules-of-thumb for hybrid memory-safe architecture
//! designing proposed by the [Rust SGX SDK](https://github.com/baidu/rust-sgx-sdk)
//! project.
//!
//! 1. Unsafe components must not taint safe components, especially for public APIs
//!    and data structures.
//! 2. Unsafe components should be as small as possible and decoupled from safe
//!    components.
//! 3. Unsafe components should be explicitly marked during deployment and ready to
//!    upgrade.
//!
//! ## Feature highlights
//!
//!  * **Memory safety**. MesaLink and its dependencies are written in
//!    [Rust](https://www.rust-lang.org), a programming language that guarantees
//!    memory safety. This extremely reduces attack surfaces of an TLS stack exposed
//!    in the wild, leaving the remaining attack surfaces auditable and restricted.
//!  * **Flexibility**. MesaLink offers flexible configurations tailored to various
//!    needs, for example IoT, connected home, automobiles, the cloud and more.
//!  * **Simplicity**. MesaLink does not support obselete or legacy TLS features, in
//!    case that misconfigurations introduce vulnerabilities.
//!  * **Compatibility**. MesaLink provides OpenSSL-compatible APIs. This makes it a
//!    breeze to port an existing OpenSSL project.
//!  * **Future proof**. MesaLink will support quantum-safe ciphersuites,
//!    safe-guarding TLS connections against even quantum computers.
//!
//! MesaLink depends on two Rust crates: [rustls](https://github.com/ctz/rustls) and
//! [sct](https://github.com/ctz/sct.rs). With them, MesaLink provides the following
//! features that are considered secure for most use cases:
//!
//! * TLS 1.2 and TLS 1.3 draft 22
//! * ALPN and SNI support
//! * Forced hostname validation
//! * Safe and fast crypto implementations from Google's BoringSSL
//! * ECDHE key exchange with forward secrecy
//! * AES-256-GCM and Chacha20-Poly1305 bulk encryption
//! * Built-in Mozilla's CA root certificates
//!
//! ## Dodged bullets
//!
//! This section lists a few vulnerabilities that affected other TLS libraries in
//! 2017 but will not be possible in MesaLink.
//!
//! * [CVE-2017-3730](https://www.cvedetails.com/cve/CVE-2017-3730/): In OpenSSL
//!   1.1.0 before 1.1.0d, if a malicious server supplies bad parameters for a DHE
//!   or ECDHE key exchange then this can result in the client attempting to
//!   dereference a NULL pointer leading to a client crash. This could be exploited
//!   in a Denial of Service attack.
//! * [CVE-2017-3735](https://www.cvedetails.com/cve/CVE-2017-3735/): While OpenSSL
//!   parses an IPAddressFamily extension in an X.509 certificate, it is possible to
//!   do a one-byte overread.
//! * [CVE-2017-2784](https://www.cvedetails.com/cve/CVE-2017-2784/): An exploitable
//!   free of a stack pointer vulnerability exists in the x509 certificate parsing
//!   code of ARM mbed TLS before 1.3.19, 2.x before 2.1.7, and 2.4.x before 2.4.2.
//! * [CVE-2017-2800](https://www.cvedetails.com/cve/CVE-2017-2800/): A specially
//!   crafted x509 certificate can cause a single out of bounds byte overwrite in
//!   wolfSSL through 3.10.2 resulting in potential certificate validation
//!   vulnerabilities, denial of service and possible remote code execution.
//! * [CVE-2017-8854](https://www.cvedetails.com/cve/CVE-2017-8854/): wolfSSL before
//!   3.10.2 has an out-of-bounds memory access with loading crafted DH parameters,
//!   aka a buffer overflow triggered by a malformed temporary DH file.
//!
//! ## Building the MesaLink library from source
//!
//! MesaLink is currently only available on Linux, Android and macOS. We will
//! introduce support for other platforms in future releases.
//!
//! To build MesaLink from source, the following tools are needed:
//!
//!   * m4
//!   * autoconf
//!   * automake
//!   * libtool
//!   * curl
//!   * make
//!   * gcc
//!   * rustc
//!   * cargo
//!
//! On Ubuntu, you can install them with:
//!
//! ```text
//! $ sudo apt-get install m4 autoconf automake libtool make gcc curl
//! $ curl https://sh.rustup.rs -sSf | sh
//! ```text
//!
//! On other platforms, please use the corresponding package managing tool to
//! install them before proceeding. Note that MesaLink always targets the
//! **current** stable and nightly release of Rust. We do not guarantee backward
//! compatibility with older releases.
//!
//! The source code can be downloaded from Github:
//!
//! ```text
//! $ git clone https://github.com/mesalock-linux/mesalink.git
//! ```text
//!
//! To configure MesaLink, execute the following:
//!
//! ```text
//! $ ./autogen.sh [OPTIONS]
//! ```text
//!
//! By default, `autogen.sh` generates the `configure` script and runs it with the
//! default configuration. A non-exhaustive list of options that can be passed to
//! either of these scripts are shown as follows:
//!
//! ```text
//!   --prefix=PREFIX         install architecture-independent files in PREFIX
//!                           [/usr/local]
//!   --includedir=DIR        C header files [PREFIX/include]
//!   --build=BUILD           configure for building on BUILD [guessed]
//!   --host=HOST             cross-compile to build programs to run on HOST [BUILD]
//!   --enable-debug          Add debug code/turns off optimizations (yes|no)
//!                           [default=no]
//!   --enable-rusthost       Set the Rust host for cross compilation (default:
//!                           disabled)
//!   --enable-client         Enable TLS client-side APIs (default: enabled)
//!   --enable-server         Enable TLS server-side APIs (default: enabled)
//!   --enable-errorstrings   Enable error string table (default: enabled)
//!   --enable-aesgcm         Enable AES-GCM bulk encryption (default: enabled)
//!   --enable-chachapoly     Enable Chacha20Poly1305 bulk encryption (default:
//!                           enabled)
//!   --enable-tls13          Enable TLS 1.3 draft (default: enabled)
//!   --enable-x25519         Enable Curve25519 for key exchange (default:
//!                           enabled)
//!   --enable-ecdh           Enable curve secp256r1 and secp384r1 for key
//!                           exchange (default: enabled)
//!   --enable-ecdsa          Enable curve secp256r1 and secp384r1 for signature
//!                           verification (default: enabled)
//! ```text
//!
//! At the end of the configuration, a configuration summary is shown. For example,
//!
//! ```text
//! Configuration summary for mesalink version 0.1.0
//!
//!    * Installation prefix:        /usr/local
//!    * Host:                       x86_64-apple-darwin17.4.0
//!    * Rust Host:
//!    * C Compiler:                 gcc
//!    * C Compiler vendor:          clang
//!    * C Flags:                    -Os -ffunction-sections -fdata-sections  -Werror
//!                                  -Wno-pragmas -Wall -Wno-strict-aliasing -Wextra -Wunknown-pragmas
//!                                  --param=ssp-buffer-size=1 -Waddress -Warray-bounds -Wbad-function-cast -Wchar-subscripts
//!                                  -Wcomment -Wfloat-equal -Wformat-security -Wformat=2 -Wmissing-field-initializers
//!                                  -Wmissing-noreturn -Wmissing-prototypes -Wnested-externs -Wpointer-arith -Wpointer-sign
//!                                  -Wredundant-decls -Wshadow -Wshorten-64-to-32 -Wsign-compare -Wstrict-overflow=1
//!                                  -Wstrict-prototypes -Wswitch-enum -Wundef -Wunused -Wunused-result -Wunused-variable
//!                                  -Wwrite-strings -fwrapv
//!    * Debug enabled:              no
//!
//!    Features
//!    * Logging and error strings:  yes
//!    * AES-GCM:                    yes
//!    * Chacha20-Poly1305:          yes
//!    * TLS 1.3 (draft):            yes
//!    * X25519 key exchange:        yes
//!    * EC key exchange:            yes
//!    * RSA signature verification: yes
//!    * EC signature verification:  yes
//! ```text
//!
//! Finally, simple run `make` to compile the MesaLink library.
//!
//! ```text
//! $ make
//! ```text
//!
//! ## Examples
//! MesaLink comes with two examples that demonstrate a TLS client and a TLS
//! server. Both of them are located at `examples/`.
//!
//! The client example connects to a remote HTTPS server and prints the server's
//! response.
//!
//! ```text
//! $ ./examples/client/client api.ipify.org
//! [+] Negotiated ciphersuite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, enc_length=16,
//! version=TLS1.2
//! [+] Sent 85 bytes
//!
//! GET / HTTP/1.0
//! Host: api.ipify.org
//! Connection: close
//! Accept-Encoding: identity
//!
//! HTTP/1.1 200 OK
//! Server: Cowboy
//! Connection: close
//! Content-Type: text/plain
//! Vary: Origin
//! Date: Thu, 15 Feb 2018 23:58:39 GMT
//! Content-Length: 10
//! Via: 1.1 vegur
//!
//! 1.2.3.4
//! [+] TLS protocol version: TLS1.2
//! [+] Received 177 bytes
//! ```text
//!
//! The server example comes with a pair of certificate and private key. The
//! certificate file is in the PEM format and contains a chain of certificates from
//! the server's certificate to the root CA certificate. The private key file
//! contains a PKCS8-encoded private key in the PEM format. Once the server is up
//! and running, open [https://127.0.0.1:8443](https://127.0.0.1:8443) and expect to
//! see the hello message.
//!
//! ```text
//! $ ./examples/server/server
//! Usage: ./examples/server/server <portnum> <cert_file> <private_key_file>
//! $ cd examples/server/server
//! $ ./server 8443 certificates private_key
//! [+] Listening at 0.0.0.0:8443
//! [+] Negotiated ciphersuite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, enc_length=16,
//! version=TLS1.2
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
//! ```text
//!
//! ## Unit tests
//! MesaLink uses cargo for unit tests. The test cases are designed for the the
//! default configuration of MesaLink, in which all the optional features are
//! enabled. So before running the test cases, please rebuild MesaLink with the
//! default configuration:
//!
//! ```text
//! $ ./configure
//! $ make
//! $ cargo test
//! ```text
//!
//! ## BoringSSL SSL tests
//! [BoGo](https://github.com/google/boringssl/tree/master/ssl/test) is BoringSSL's
//! protocol level test suite. We have ported BoGo for testing the functionality and
//! compatibility of MesaLink. To run BoGo test cases, run the following:
//!
//! ```text
//! $ cargo build --release --examples
//! $ (cd bogo && ./fetch-and-build && ./runme)
//! ```text
//!
//! ## Crypto benchmarks
//! MesaLink's underlying crypto library is
//! [**Ring**](https://github.com/briansmith/ring), a safe and fast crypto using
//! Rust. To evaluate the speed and throughput of MesaLink, we developed new
//! benchmarks for OpenSSL and wolfSSL based on the
//! [crypto-bench](https://github.com/briansmith/crypto-bench) project. A summary of
//! the available benchmarks is shown as follows:
//!
//! | Benchmark                           | Ring | OpenSSL/LibreSSL | wolfSSL |
//! | ----------------------------------- | :--: | :--------------: | :-----: |
//! | SHA-1 & SHA-256 & SHA-512           |  ✔️   |        ✔️         |    ✔️    |
//! | AES-128-GCM & AES-256-GCM           |  ✔️   |        ✔️         |    ✔️    |
//! | Chacha20-Poly1305                   |  ✔️   |        ✔️         |    ✔️    |
//! | ECDH (suite B) key exchange         |  ✔️   |                  |         |
//! | X25519 (Curve25519) key exchange    |  ✔️   |                  |         |
//!
//! To run the benchmarks, run the following command with nightly Rust. Note you
//! must have OpenSSL/LibreSSL or wolfSSL installed to run the corresponding
//! benchmarks.
//!
//! ```text
//! $ rustup default nightly
//! $ cd crypto-bench && ./cargo_all update && ./cargo_all bench
//! ```text
//!
//! ## Maintainer
//!
//!  * Yiming Jing <jingyiming@baidu.com>
//!
//! ## License
//! MesaLink is provided under the 3-Clause BSD license. For a copy, see the LICENSE
//! file.

#![deny(trivial_numeric_casts, unused_qualifications)]
#![forbid(anonymous_parameters, unused_extern_crates, unused_import_braces, unused_results,
          variant_size_differences, warnings)]

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
#[cfg(feature = "error_strings")]
#[macro_use]
extern crate enum_to_str_derive;

#[macro_use]
mod macros {
    #[cfg(feature = "error_strings")]
    #[macro_export]
    macro_rules! call_site {
        () => {{
            concat!(file!(), ":", line!())
        }};
    }

    #[cfg(not(feature = "error_strings"))]
    #[macro_export]
    macro_rules! call_site {
        () => {{
            "call_site information not enabled"
        }};
    }
}

/// The ssl module is the counterpart of the OpenSSL ssl library.
pub mod ssl;

/// The crypo module is the counterpart of the OpenSSL crypto library.
pub mod crypto;
