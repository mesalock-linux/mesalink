use crypto_bench;
use ffi;
use test;
use std::{mem, ptr};

fn generate_sealing_key(key_len: usize) -> Result<ffi::Aes, ()> {
    let mut key: ffi::Aes;
    let mut rng: ffi::WC_RNG;
    let mut key_bytes: [ffi::byte; (ffi::AES_MAX_KEY_SIZE / 8) as usize];
    unsafe {
        key = mem::uninitialized();
        rng = mem::uninitialized();
        key_bytes = mem::uninitialized();

        if 0 != ffi::wc_InitRng(&mut rng) {
            return Err(());
        }

        if 0 != ffi::wc_RNG_GenerateBlock(&mut rng, key_bytes.as_mut_ptr(), key_len as ffi::word32)
        {
            return Err(());
        }

        if 0 != ffi::wc_AesInit(&mut key, ptr::null_mut(), ffi::INVALID_DEVID) {
            return Err(());
        }

        if 0
            != ffi::wc_AesGcmSetKey(
                &mut key,
                key_bytes.as_ptr() as *const ffi::byte,
                key_len as ffi::word32,
            ) {
            return Err(());
        }

        if 0 != ffi::wc_FreeRng(&mut rng) {
            return Err(());
        }
    }
    Ok(key)
}

fn seal_bench(key_len: usize, chunk_len: usize, ad: &[u8], b: &mut test::Bencher) {
    let mut tag = vec![0u8; 16]; // 128-bit authentication tags for all AEAD ciphers
    let data = vec![0u8; chunk_len];
    let mut out = vec![0u8; chunk_len + tag.len()];
    // XXX: This is a little misleading when `ad` isn't empty.
    b.bytes = chunk_len as u64;

    let mut key = generate_sealing_key(key_len).unwrap();

    b.iter(|| {
        unsafe {
            ffi::wc_AesGcmEncrypt(
                &mut key,                                               // aes
                out.as_mut_ptr() as *mut ffi::byte,                     // out
                data.as_ptr() as *const ffi::byte,                      // in_
                data.len() as ffi::word32,                              // sz,
                crypto_bench::aead::NONCE.as_ptr() as *const ffi::byte, // iv
                crypto_bench::aead::NONCE.len() as ffi::word32,         // ivSz
                tag.as_mut_ptr() as *mut ffi::byte,                     // authTag
                tag.len() as ffi::word32,                               // authTagSz
                ad.as_ptr() as *const ffi::byte,                        // authIn
                ad.len() as ffi::word32,                                // authInSz
            );
        }
    });
}

macro_rules! wolfssl_seal_bench {
 ( $benchmark_name:ident, $key_len:expr, $chunk_len:expr, $ad:expr ) => {
        #[bench]
        fn $benchmark_name(b: &mut test::Bencher) {
            use super::super::seal_bench;
            seal_bench($key_len, $chunk_len, $ad, b);
        }
    }
}

macro_rules! wolfssl_seal_benches {
    ( $name:ident, $key_len:expr ) => {
        mod $name {
            use crypto_bench;
            use test;

            // A TLS 1.2 finished message.
            wolfssl_seal_bench!(tls12_finished, $key_len,
                                      crypto_bench::aead::TLS12_FINISHED_LEN,
                                      &crypto_bench::aead::TLS12_AD);
            wolfssl_seal_bench!(tls13_finished, $key_len,
                                      crypto_bench::aead::TLS13_FINISHED_LEN,
                                      &crypto_bench::aead::TLS13_AD);

            // ~1 packet of data in TLS.
            wolfssl_seal_bench!(tls12_1350, $key_len, 1350,
                                      &crypto_bench::aead::TLS12_AD);
            wolfssl_seal_bench!(tls13_1350, $key_len, 1350,
                                      &crypto_bench::aead::TLS13_AD);
            wolfssl_seal_bench!(tls12_4k, $key_len, 4*1024,
                                      &crypto_bench::aead::TLS12_AD);
            wolfssl_seal_bench!(tls13_4k, $key_len, 4*1024,
                                      &crypto_bench::aead::TLS13_AD);
            wolfssl_seal_bench!(tls12_8k, $key_len, 8*1024,
                                      &crypto_bench::aead::TLS12_AD);
            wolfssl_seal_bench!(tls13_8k, $key_len, 8*1024,
                                      &crypto_bench::aead::TLS13_AD);
            wolfssl_seal_bench!(tls12_1m, $key_len, 1024*1024,
                                      &crypto_bench::aead::TLS12_AD);
            wolfssl_seal_bench!(tls13_1m, $key_len, 1024*1024,
                                      &crypto_bench::aead::TLS13_AD);
        }
    }
}

mod bench_aesgcm {
    wolfssl_seal_benches!(aes_128_gcm, 16); // AES-128-GCM
    wolfssl_seal_benches!(aes_256_gcm, 32); // AES-256-GCM
}
