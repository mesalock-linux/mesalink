use crypto_bench;
use openssl::{rand, symm};
use test;

fn generate_sealing_key(algorithm: symm::Cipher) -> Result<Vec<u8>, ()> {
    let mut key_bytes = vec![0u8; algorithm.key_len()];
    try!(rand::rand_bytes(&mut key_bytes).map_err(|_| ()));
    Ok(key_bytes)
}

fn seal_bench(algorithm: symm::Cipher, chunk_len: usize, ad: &[u8], b: &mut test::Bencher) {
    let mut tag = vec![0u8; 16]; // 128-bit authentication tags for all AEAD ciphers
    let data = vec![0u8; chunk_len];
    // XXX: This is a little misleading when `ad` isn't empty.
    b.bytes = chunk_len as u64;

    let key = generate_sealing_key(algorithm).unwrap();
    b.iter(|| {
        symm::encrypt_aead(
            algorithm,
            &key,
            Some(&crypto_bench::aead::NONCE),
            ad,
            &data,
            &mut tag,
        ).unwrap();
    });
}

macro_rules! openssl_seal_bench {
 ( $benchmark_name:ident, $algorithm:expr, $chunk_len:expr, $ad:expr ) => {
        #[bench]
        fn $benchmark_name(b: &mut test::Bencher) {
            use openssl::symm;
            use super::super::seal_bench;
            seal_bench($algorithm, $chunk_len, $ad, b);
        }
    }
}

macro_rules! openssl_seal_benches {
    ( $name:ident, $algorithm:expr ) => {
        mod $name {
            use crypto_bench;
            use test;

            // A TLS 1.2 finished message.
            openssl_seal_bench!(tls12_finished, $algorithm,
                                      crypto_bench::aead::TLS12_FINISHED_LEN,
                                      &crypto_bench::aead::TLS12_AD);
            openssl_seal_bench!(tls13_finished, $algorithm,
                                      crypto_bench::aead::TLS13_FINISHED_LEN,
                                      &crypto_bench::aead::TLS13_AD);

            // ~1 packet of data in TLS.
            openssl_seal_bench!(tls12_1350, $algorithm, 1350,
                                      &crypto_bench::aead::TLS12_AD);
            openssl_seal_bench!(tls13_1350, $algorithm, 1350,
                                      &crypto_bench::aead::TLS13_AD);

            openssl_seal_bench!(tls12_4k, $algorithm, 4*1024,
                                      &crypto_bench::aead::TLS12_AD);
            openssl_seal_bench!(tls13_4k, $algorithm, 4*1024,
                                      &crypto_bench::aead::TLS13_AD);

            openssl_seal_bench!(tls12_1m, $algorithm, 1024*1024,
                                      &crypto_bench::aead::TLS12_AD);
            openssl_seal_bench!(tls13_1m, $algorithm, 1024*1024,
                                      &crypto_bench::aead::TLS13_AD);
        }
    }
}

mod openssl_aead {
    openssl_seal_benches!(aes_128_gcm, symm::Cipher::aes_128_gcm());
    openssl_seal_benches!(aes_256_gcm, symm::Cipher::aes_256_gcm());

    #[cfg(feature = "openssl_110")]
    openssl_seal_benches!(chacha20_poly1305, symm::Cipher::chacha20_poly1305());
}
