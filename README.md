<p align="center"><img src="logo.png" height="86" /></p>

<h1 align="center"> A memory-safe and OpenSSL-compatible TLS library </h1>

[![Build Status](https://travis-ci.com/mesalock-linux/mesalink.svg?branch=master)](https://travis-ci.com/mesalock-linux/mesalink)
[![Build Status](https://dev.azure.com/mesalink/MesaLink/_apis/build/status/mesalock-linux.mesalink?branchName=master)](https://dev.azure.com/mesalink/MesaLink/_build/latest?definitionId=1&branchName=master)
[![Coverage Status](https://codecov.io/gh/mesalock-linux/mesalink/branch/master/graph/badge.svg)](https://codecov.io/gh/mesalock-linux/mesalink)
[![Release](https://img.shields.io/github/release/mesalock-linux/mesalink.svg)](https://github.com/mesalock-linux/mesalink/releases)
[![License](https://img.shields.io/badge/license-BSD-blue.svg)](LICENSE)

MesaLink is a memory-safe and OpenSSL-compatible TLS library.
MesaLink has been in production at Baidu with >10 million monthly active users.

**This is a special version of MesaLink distributed as a `openssl-sys`-like
crate on crates.io. CMake/Autotools is not necessary to build this crate. This
version uses [rustls](https://crates.io/crates/rustls) and
[webpki](https://crates.io/crates/rustls) on crates.io instead of our forks.**

Visit us on our website: [https://mesalink.io](https://mesalink.io).

## Release history
* 1.0.0 (🎂 04-02-2019 🎂)
  - CMake support; see the updated [CROSS_COMPILE.md](https://github.com/mesalock-linux/mesalink/blob/master/CROSS_COMPILE.md) for cross-compilation instructions
  - Windows builds (MSVC and MinGW)
  - CI/CD migrated to Azure Pipelines
  - NSIS installer for Win64 available
  - Mutex/RwLock from [parking_lot](https://crates.io/crates/parking_lot)
  - Session caches with [hashbrown](https://crates.io/crates/hashbrown)
  - Optional jemalloc memory allocator with [jemallocator](https://crates.io/crates/jemallocator)
  - Renovated website
* 0.8.0 (01-25-2019)
  - 40 new OpenSSL APIs, covering BIO, EVP_PKEY, PEM and X509
  - SSL_CTX and SSL are thread-safe
  - Configurable session cache
  - SHA1 signatures discontinued
  - Tested with rust-san memory and leak sanitizers
  - Rust 2018 edition
  - Based on rustls 0.15, webpki 0.19, and \*ring\* 0.14
  - TLS backend for curl since 7.62.0
  - TLS backend for brpc, an industrial-grade RPC framework; see the `patches`
    directory
  - Experimental SGX Remote Attestation for Untrusted Enclaves (see
    [SGX_README.md](examples/sgx_uera_client/SGX_README.md))
* 0.7.2 (11-24-2018)
  - Client authentication
  - Use armv7-linux-androideabi for Android builds
* 0.7.1 (09-05-2018)
  - SSL_CTX_load_verify_location
  - Fix duplicate `floatdisf` symbols

See [OLD_CHANGES.md](OLD_CHANGES.md) for further change history.

## Feature highlights

 * **Memory safety**. MesaLink is impervious to bugs like Heartbleed and buffer
   overflows becuse it is written in Rust.
 * **Cross Platform**. Linux, macOS, Android, Windows; x86, x86_64, armv7,
   aarch64... you name it. MesaLink probably compiles for it.
 * **Modern Ciphersuites**. MesaLink uses the best ciphersuites including
   AES-GCM, Chacha20Poly1305, and elliptic-curve key exchange with perfect
   forward secrecy.
 * **TLS 1.3**. Eight years since TLS 1.2, the faster and more secure TLS standard, is now in Rustls and MesaLink.
 * **Blazing Fast**. X25519 key exchange, AES-NI support, no language runtime
   like Java/Go. MesaLink runs at full speed on your metal.
 * **Flexible Configuration**: MesaLink offers flexible configurations tailored
   to your needs. You can customize which ciphers and TLS versions are built-in.
 * **Transparent Replacement**. MesaLink provides OpenSSL-compatible C APIs.
   Want to use MesaLink in curl or Android? No problem.
 * **Production Ready**. Baidu uses MesaLink in production with 10M monthly
   active users as of 12/2018

MesaLink depends on two Rust crates: [rustls](https://github.com/ctz/rustls) and
[sct](https://github.com/ctz/sct.rs). With them, MesaLink provides the following
features that are considered secure for most use cases:

* TLS 1.2 and TLS 1.3
* ECDSA and RSA server authentication
* Forced hostname validation
* Forward secrecy using ECDHE; with curve25519, nistp256 or nistp384 curves.
* Safe and fast crypto primitives from BoringSSL
* AES-128-GCM, AES-256-GCM and Chacha20-Poly1305 bulk encryption
* Built-in Mozilla's CA root certificates

## Supported ciphersuites

* TLS13-CHACHA20-POLY1305-SHA256
* TLS13-AES-256-GCM-SHA384
* TLS13-AES-128-GCM_SHA256
* TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256
* TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256
* TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384
* TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256
* TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384
* TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256

## Unit tests
MesaLink uses cargo for unit tests. Simply run `cargo test`.

```
$ cargo test
```

## BoringSSL SSL tests
[BoGo](https://github.com/google/boringssl/tree/master/ssl/test) is BoringSSL's
protocol level test suite. We have ported BoGo for testing the functionality and
compatibility of MesaLink. To run BoGo test cases, run the following:

```
$ cd bogo && ./runme
```

## Acknowledgments
The MesaLink project would not have been possible without the following
high-quality open source projects in the Rust community. Thanks for code and
inspiration!

  * `rustls`: A modern TLS library in Rust, maintained by Joseph Birr-Pixton
    [@ctz](https://github.com/ctz)
  * `sct.rs`: Certificate transparency SCT verification library in rust,
    maintained by Joseph Birr-Pixton [@ctz](https://github.com/ctz)
  * `ring`: Safe, fast, small crypto using Rust, by Brian Smith
    [@briansmith](https://github.com/briansmith)
  * `webpki`: WebPKI X.509 Certificate Validation in Rust, maintained by Brian
    Smith [@briansmith](https://github.com/briansmith)
  * `crypto-bench`: Benchmarks for crypto libraries, maintained by Brian Smith
    [@briansmith](https://github.com/briansmith)
  * Special thanks to Brian Smith for insights and valuable discussion

## Maintainer

 * Yiming Jing `<jingyiming@baidu.com>` [@kevinis](https://github.com/kevinis)

## License
MesaLink is provided under the 3-Clause BSD license. For a copy, see the LICENSE
file.
