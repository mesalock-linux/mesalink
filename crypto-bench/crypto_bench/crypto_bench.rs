// This crate only contains benchmarks, but we have to define a program with
// `main` to avoid things complaining.

pub mod aead {
    // All the AEADs we're testing use 96-bit nonces.
    pub const NONCE: [u8; 96 / 8] = [0u8; 96 / 8];

    // A TLS 1.2 finished message is always 12 bytes long.
    pub const TLS12_FINISHED_LEN: usize = 12;

    // A TLS 1.3 finished message is "[t]he size of the HMAC output for the
    // Hash used for the handshake," which is usually SHA-256.
    pub const TLS13_FINISHED_LEN: usize = 32;

    // In TLS 1.2, 13 bytes of additional data are used for AEAD cipher suites.
    pub const TLS12_AD: [u8; 13] = [
        23,         // Type: application_data
        3, 3,       // Version = TLS 1.2.
        0x12, 0x34, // Length = 0x1234.
        0, 0, 0, 0, 0, 0, 0, 1, // Record #1
    ];

    // In TLS 1.3, no additional data is used for AEAD cipher suites.
    pub const TLS13_AD: [u8; 0] = [ ];
}

pub const SHA1_BLOCK_LEN: usize = 512 / 8;
pub const SHA1_OUTPUT_LEN: usize = 160 / 8;
pub const SHA256_BLOCK_LEN: usize = 512 / 8;
pub const SHA256_OUTPUT_LEN: usize = 256 / 8;
pub const SHA384_BLOCK_LEN: usize = 1024 / 8;
pub const SHA384_OUTPUT_LEN: usize = 384 / 8;
pub const SHA512_BLOCK_LEN: usize = 1024 / 8;
pub const SHA512_OUTPUT_LEN: usize = 512 / 8;
pub const SHA512_256_OUTPUT_LEN: usize = 256 / 8;

#[macro_export]
macro_rules! digest_bench {
    ( $bench_fn_name:ident, $input_len:expr, $input:ident,
      $calculation:expr) => {
        #[bench]
        fn $bench_fn_name(b: &mut test::Bencher) {
            let $input = vec![0u8; $input_len];
            let $input = &$input[..];
            b.bytes = $input_len as u64;
            b.iter(|| $calculation);
        }
    }
}

#[macro_export]
macro_rules! digest_benches {
    ($block_len:expr, $input:ident, $calculation:expr) =>
    {
        use test;

        digest_bench!(block_len, $block_len, $input, $calculation); // PBKDF2
        digest_bench!(_16, 16, $input, $calculation); // BoringSSL
        digest_bench!(_256, 256, $input, $calculation); // BoringSSL
        digest_bench!(_1000, 1000, $input, $calculation); // X.509 TBSCertificate
        digest_bench!(_2000, 2000, $input, $calculation); // X.509 TBSCertificate
        digest_bench!(_8192, 8192, $input, $calculation); // BoringSSL
    }
}

pub mod pbkdf2 {
    // These values are copied from
    // https://github.com/ctz/rust-fastpbkdf2/tree/master/pbkdf2-bench, except
    // `ITERATIONS` was lowered from `1 << 20` because the benchmarks were
    // excruciatingly slow with 2^20 iterations, and that iteration count isn't
    // realistic for most applications anyway.
    pub const ITERATIONS: u32 = 100_000;
    pub const PASSWORD: &'static [u8] = b"password";
    pub const PASSWORD_STR: &'static str = "password";
    pub const SALT: &'static [u8] = b"salt";
}

#[macro_export]
macro_rules! pbkdf2_bench {
    ( $bench_fn_name:ident, $out_len:expr, $out:ident, $calculation:expr) => {
        #[bench]
        fn $bench_fn_name(b: &mut test::Bencher) {
            let mut $out = [0u8; $out_len];
            b.iter(|| $calculation)
        }
    }
}
