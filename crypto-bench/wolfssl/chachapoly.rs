use crypto_bench;
use ffi;
use test;
use std::mem;

fn generate_sealing_key() -> Result<[ffi::byte; ffi::CHACHA20_POLY1305_AEAD_KEYSIZE as usize], ()> {
    let mut rng: ffi::WC_RNG;
    let mut key_bytes: [ffi::byte; ffi::CHACHA20_POLY1305_AEAD_KEYSIZE as usize];
    unsafe {
        rng = mem::uninitialized();
        key_bytes = mem::uninitialized();

        if 0 != ffi::wc_InitRng(&mut rng) {
            return Err(());
        }

        if 0
            != ffi::wc_RNG_GenerateBlock(
                &mut rng,
                key_bytes.as_mut_ptr(),
                key_bytes.len() as ffi::word32,
            ) {
            return Err(());
        }

        if 0 != ffi::wc_FreeRng(&mut rng) {
            return Err(());
        }
    }
    Ok(key_bytes)
}

fn seal_bench(chunk_len: usize, ad: &[u8], b: &mut test::Bencher) {
    let mut tag = vec![0u8; ffi::CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE as usize];
    let data = vec![0u8; chunk_len];
    let mut out = vec![0u8; chunk_len + tag.len()];
    // XXX: This is a little misleading when `ad` isn't empty.
    b.bytes = chunk_len as u64;

    let key = generate_sealing_key().unwrap();

    b.iter(|| {
        unsafe {
            ffi::wc_ChaCha20Poly1305_Encrypt(
                key.as_ptr() as *const ffi::byte,                       // inKey
                crypto_bench::aead::NONCE.as_ptr() as *const ffi::byte, // inIV
                ad.as_ptr() as *const ffi::byte,                        // inAAD
                ad.len() as ffi::word32,                                // inAADLen
                data.as_ptr() as *const ffi::byte,                      // inPlaintext
                data.len() as ffi::word32,                              // inPlaintextLen
                out.as_mut_ptr() as *mut ffi::byte,                     // outCiphertext
                tag.as_mut_ptr() as *mut ffi::byte,                     // outAuthTag
            );
        }
    });
}

macro_rules! wolfssl_seal_bench {
 ( $benchmark_name:ident, $chunk_len:expr, $ad:expr ) => {
        #[bench]
        fn $benchmark_name(b: &mut test::Bencher) {
            use super::super::seal_bench;
            seal_bench($chunk_len, $ad, b);
        }
    }
}

macro_rules! wolfssl_seal_benches {
    ( $name:ident ) => {
        mod $name {
            use crypto_bench;
            use test;

            // A TLS 1.2 finished message.
            wolfssl_seal_bench!(tls12_finished,
                                      crypto_bench::aead::TLS12_FINISHED_LEN,
                                      &crypto_bench::aead::TLS12_AD);
            wolfssl_seal_bench!(tls13_finished,
                                      crypto_bench::aead::TLS13_FINISHED_LEN,
                                      &crypto_bench::aead::TLS13_AD);

            // ~1 packet of data in TLS.
            wolfssl_seal_bench!(tls12_1350, 1350, &crypto_bench::aead::TLS12_AD);
            wolfssl_seal_bench!(tls13_1350, 1350, &crypto_bench::aead::TLS13_AD);

            wolfssl_seal_bench!(tls12_4k, 4*1024, &crypto_bench::aead::TLS12_AD);
            wolfssl_seal_bench!(tls13_4k, 4*1024, &crypto_bench::aead::TLS13_AD);

            wolfssl_seal_bench!(tls12_1m, 1024*1024, &crypto_bench::aead::TLS12_AD);
            wolfssl_seal_bench!(tls13_1m, 1024*1024, &crypto_bench::aead::TLS13_AD);
        }
    }
}

mod bench_chacha20poly1305 {
    wolfssl_seal_benches!(chacha20_poly1305);
}
