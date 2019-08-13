<p align="center"><img src="logo.png" height="86" /></p>

<h1 align="center"> A memory-safe and OpenSSL-compatible TLS library </h1>

[![Build Status](https://travis-ci.com/mesalock-linux/mesalink.svg?branch=master)](https://travis-ci.com/mesalock-linux/mesalink)
[![Build Status](https://dev.azure.com/mesalink/MesaLink/_apis/build/status/mesalock-linux.mesalink?branchName=master)](https://dev.azure.com/mesalink/MesaLink/_build/latest?definitionId=1&branchName=master)
[![Coverage Status](https://codecov.io/gh/mesalock-linux/mesalink/branch/master/graph/badge.svg)](https://codecov.io/gh/mesalock-linux/mesalink)
[![Documentation Status](https://img.shields.io/badge/docs-latest-brightgreen.svg?style=flat)](https://mesalock-linux.github.io/mesalink-doc/doc/mesalink/index.html)
[![Release](https://img.shields.io/github/release/mesalock-linux/mesalink.svg)](https://github.com/mesalock-linux/mesalink/releases)
[![License](https://img.shields.io/badge/license-BSD-blue.svg)](LICENSE)

MesaLink is a memory-safe and OpenSSL-compatible TLS library.
MesaLink has been in production at Baidu with >10 million monthly active users.

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

## Building instructions for Autotools

```
$ sudo apt-get install m4 autoconf automake libtool make gcc curl
$ curl https://sh.rustup.rs -sSf | sh

$ git clone https://github.com/mesalock-linux/mesalink.git
$ ./autogen.sh --enable-examples
$ make
```

## Building instructions for CMake

```
$ sudo apt-get install cmake make gcc curl
$ curl https://sh.rustup.rs -sSf | sh

$ git clone https://github.com/mesalock-linux/mesalink.git
$ mkdir build && cd build
$ cmake ..
$ cmake --build .
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
