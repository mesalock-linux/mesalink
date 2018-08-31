<p align="center"><img src="logo.png" height="86" /></p>

<h1 align="center"> A memory-safe and OpenSSL-compatible TLS library </h1>

[![Build Status](https://travis-ci.com/mesalock-linux/mesalink.svg?branch=master)](https://travis-ci.com/mesalock-linux/mesalink)
[![Coverage Status](https://coveralls.io/repos/github/mesalock-linux/mesalink/badge.svg?branch=master)](https://coveralls.io/github/mesalock-linux/mesalink?branch=master)
[![Documentation Status](https://img.shields.io/badge/docs-latest-brightgreen.svg?style=flat)](https://mesalock-linux.github.io/mesalink-doc/doc/mesalink/index.html)
[![Release](https://img.shields.io/github/release/mesalock-linux/mesalink.svg)](https://github.com/mesalock-linux/mesalink/releases)
[![License](https://img.shields.io/badge/license-BSD-blue.svg)](LICENSE)

MesaLink is a memory-safe and OpenSSL-compatible TLS library. To achieve better
security, we apply [Non-bypassable Security Paradigm
(NbSP)](https://github.com/baidu/rust-sgx-sdk/blob/master/documents/nbsp.pdf) to
the system design and implementation.

MesaLink is part of [Open AI System Security Alliance](https://oases.io/) and
[Baidu AIoT Security Solutions](https://aiotsec.baidu.com/). Integration of
MesaLink into Android apps and Android-based smart TVs is now in progress.

Also visit us on our new website: [https://mesalink.io](https://mesalink.io).

## Release history

* 0.7.0 (08-14-2018)
  - TLS 1.3 draft 28
  - Client-side support for TLS 1.3 0-RTT ([rustls PR
    #185](https://github.com/ctz/rustls/pull/185))
  - SSL_connect and SSL_do_handshake
  - Experimental X509 and STACK APIs for Android HostnameVerifier
  - Non-blocking socket support
  - Refactored thread-local error queue, now includes error line numbers for
    debugging
  - `catch_unwind` at FFI boundaries to prevent undefined behavior
  - Link time optimization if built with nightly Rust or stable Rust >1.28
  - Curl support tested with official CI scripts and git 2.18; see the `patches`
    directory
  - `cargo-fmt` and `cargo-clippy` lint checks

* 0.6.1 (04-09-2018)
  - TLS 1.3 Draft 23
  - Coverage tests with `cargo tarpaulin`

* 0.6.0 (04-02-2018)
  - First public release
  - TLS 1.2 and TLS 1.3 Draft 22
  - SSL_CTX and METHOD APIs
  - SSL APIs
  - Dynamic pointer sanity checks for opaque pointer types
  - Autotools
  - Configurable ciphersuites, curves, and TLS versions
  - Linux, macOS, and Android builds on x86_64/arm/arm64
  - Unit tests and BoringSSL BoGo tests
  - Crypto benchmarks

## Feature highlights

 * **Memory safety**. MesaLink and its dependencies are written in
   [Rust](https://www.rust-lang.org), a programming language that guarantees
   memory safety. This extremely reduces the attack surfaces of an exposed TLS
   stack, leaving the remaining attack surfaces auditable and restricted.
 * **Flexibility**. MesaLink offers flexible configurations tailored to various
   needs, such as IoT, connected home, automobiles, the cloud and more.
 * **Simplicity**. MesaLink does not support obsolete or legacy TLS features to
   prevent misconfigurations that can introduce vulnerabilities.
 * **Compatibility**. MesaLink provides OpenSSL-compatible APIs. This makes it a
   breeze to port an existing OpenSSL project.

MesaLink depends on two Rust crates: [rustls](https://github.com/ctz/rustls) and
[sct](https://github.com/ctz/sct.rs). With them, MesaLink provides the following
features that are considered secure for most use cases:

* TLS 1.2 and TLS 1.3 draft 23
* ECDSA or RSA server authentication
* Forced hostname validation
* Forward secrecy using ECDHE; with curve25519, nistp256 or nistp384 curves.
* Safe and fast crypto primitives from BoringSSL
* AES-128-GCM, AES-256-GCM and Chacha20-Poly1305 bulk encryption
* Built-in Mozilla's CA root certificates

## Building instructions

MesaLink currently supports Linux, Android and macOS. We will introduce support
for other platforms in future releases.

First, install the build dependencies:

```
$ sudo apt-get install m4 autoconf automake libtool make gcc curl
```

Then install the Rust tool chain. Note that MesaLink always targets the
**current** stable and nightly release of Rust.

```
$ curl https://sh.rustup.rs -sSf | sh
```

The source code can be downloaded from Github:

```
$ git clone https://github.com/mesalock-linux/mesalink.git
```

To configure MesaLink, execute the following:

```
$ ./autogen.sh --enable-examples
```

By default, `autogen.sh` generates the `configure` script and runs it with the
default configuration. A non-exhaustive list of options that can be passed to
either of these scripts are shown as follows:

```
  --prefix=PREFIX         install architecture-independent files in PREFIX
                          [/usr/local]
  --includedir=DIR        C header files [PREFIX/include]
  --build=BUILD           configure for building on BUILD [guessed]
  --host=HOST             cross-compile to build programs to run on HOST [BUILD]
  --enable-debug          Add debug code/turns off optimizations (yes|no)
                          [default=no]
  --enable-rusthost       Set the Rust host for cross compilation (default:
                          disabled)
  --enable-client         Enable TLS client-side APIs (default: enabled)
  --enable-server         Enable TLS server-side APIs (default: enabled)
  --enable-errorstrings   Enable error string table (default: enabled)
  --enable-aesgcm         Enable AES-GCM bulk encryption (default: enabled)
  --enable-chachapoly     Enable Chacha20Poly1305 bulk encryption (default:
                          enabled)
  --enable-tls13          Enable TLS 1.3 draft (default: enabled)
  --enable-x25519         Enable Curve25519 for key exchange (default:
                          enabled)
  --enable-ecdh           Enable curve secp256r1 and secp384r1 for key
                          exchange (default: enabled)
  --enable-ecdsa          Enable curve secp256r1 and secp384r1 for signature
                          verification (default: enabled)
  --enable-examples       Enable examples (default: disabled)
```

At the end of the configuration, a configuration summary is shown. For example,

```
---
Configuration summary for mesalink version 0.7.0

   * Installation prefix:        /usr/local
   * Host:                       x86_64-apple-darwin17.7.0
   * Rust Host:
   * C Compiler:                 gcc
   * C Compiler vendor:          clang
   * C Flags:                    -Os -fvisibility=hidden -ffunction-sections -fdata-sections
   * Debug enabled:              no
   * Nightly Rust:               no
   * Examples:                   no

   Features
   * Logging and error strings:  yes
   * AES-GCM:                    yes
   * Chacha20-Poly1305:          yes
   * TLS 1.3 (draft):            yes
   * X25519 key exchange:        yes
   * EC key exchange:            yes
   * RSA signature verification: yes
   * EC signature verification:  yes

---
```

Finally, simple run `make` to compile the MesaLink library and examples

```
$ make
```

## Examples
MesaLink comes with two examples that demonstrate a TLS client and a TLS
server. Both of them are located at `examples/`.

The client example connects to a remote HTTPS server and prints the server's
response.

```
$ ./examples/client/client api.ipify.org
[+] Negotiated ciphersuite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, enc_length=16, version=TLS1.2
[+] Subject name: /OU=Domain Control Validated/OU=PositiveSSL Wildcard/CN=*.ipify.org
[+] Subject alternative names:*.ipify.org ipify.org
[+] Sent 85 bytes

GET / HTTP/1.0
Host: api.ipify.org
Connection: close
Accept-Encoding: identity


HTTP/1.1 200 OK
Server: Cowboy
Connection: close
Content-Type: text/plain
Vary: Origin
Date: Thu, 09 Aug 2018 21:44:35 GMT
Content-Length: 10
Via: 1.1 vegur

1.2.3.4
[+] TLS protocol version: TLS1.2

[+] Received 177 bytes
```

The server example comes with a pair of certificate and private key. The
certificate file is in the PEM format and contains a chain of certificates from
the server's certificate to the root CA certificate. The private key file
contains a PKCS8-encoded private key in the PEM format. Once the server is up
and running, open [https://127.0.0.1:8443](https://127.0.0.1:8443) and expect to
see the hello message.

```
$ ./examples/server/server
Usage: ./examples/server/server <portnum> <cert_file> <private_key_file>
$ cd examples/server/server
$ ./server 8443 certificates private_key
[+] Listening at 0.0.0.0:8443
[+] Negotiated ciphersuite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, enc_length=16, version=TLS1.2
[+] Received:
GET / HTTP/1.1
Host: 127.0.0.1:8443
Connection: keep-alive
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_2) AppleWebKit/537.36
(KHTML, like Gecko) Chrome/63.0.3239.84 Safari/537.36
Upgrade-Insecure-Requests: 1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
```

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

## Crypto benchmarks
MesaLink's underlying crypto library is
[**Ring**](https://github.com/briansmith/ring), a safe and fast crypto using
Rust. To evaluate the speed and throughput of MesaLink, we developed new
benchmarks for OpenSSL and wolfSSL based on the
[crypto-bench](https://github.com/briansmith/crypto-bench) project. A summary of
the available benchmarks is shown as follows:

| Benchmark                           | Ring | OpenSSL/LibreSSL | wolfSSL |
| ----------------------------------- | :--: | :--------------: | :-----: |
| SHA-1 & SHA-256 & SHA-512           |  ✔️   |        ✔️         |    ✔️    |
| AES-128-GCM & AES-256-GCM           |  ✔️   |        ✔️         |    ✔️    |
| Chacha20-Poly1305                   |  ✔️   |        ✔️         |    ✔️    |
| ECDH (suite B) key exchange         |  ✔️   |                  |         |
| X25519 (Curve25519) key exchange    |  ✔️   |                  |         |

To run the benchmarks, run the following command with *nightly* Rust. Note you
would need OpenSSL/LibreSSL and/or wolfSSL installed to run the corresponding
benchmarks.

```
$ rustup install nightly-2017-12-24
$ rustup default nightly-2017-12-24
$ cd crypto-bench && ./bench_all
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

## Steering Committee

  - Tao Wei
  - Yulong Zhang

## License
MesaLink is provided under the 3-Clause BSD license. For a copy, see the LICENSE
file.
