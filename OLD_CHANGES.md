## Release history

* 0.7.2 (11-24-2018)
  - Client authentication
  - Use armv7-linux-androideabi for Android builds
* 0.7.1 (09-05-2018)
  - SSL_CTX_load_verify_location
  - Fix duplicate `floatdisf` symbols
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