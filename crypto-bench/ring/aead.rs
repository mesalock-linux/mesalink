// TODO: The BoringSSL benchmarks align the input/output buffers to 16-bytes
// boundaries. Should we?

use crypto_bench;
use ring::aead;
use ring::rand::SecureRandom;
use test;

fn generate_sealing_key(algorithm: &'static aead::Algorithm, rng: &SecureRandom)
                        -> Result<aead::SealingKey, ()> {
    let mut key_bytes = vec![0u8; algorithm.key_len()];
    try!(rng.fill(&mut key_bytes).map_err(|_| ()));
    aead::SealingKey::new(algorithm, &key_bytes).map_err(|_| ())
}

fn seal_in_place_bench(algorithm: &'static aead::Algorithm,
                       rng: &SecureRandom,
                       chunk_len: usize, ad: &[u8],
                       b: &mut test::Bencher) {
    let out_suffix_capacity = algorithm.tag_len();
    let mut in_out = vec![0u8; chunk_len + out_suffix_capacity];

    // XXX: This is a little misleading when `ad` isn't empty.
    b.bytes = chunk_len as u64;

    let key = generate_sealing_key(algorithm, rng).unwrap();
    b.iter(|| {
        aead::seal_in_place(&key, &crypto_bench::aead::NONCE, ad, &mut in_out,
                            out_suffix_capacity).unwrap();


    });
}

macro_rules! ring_seal_in_place_bench {
    ( $benchmark_name:ident, $algorithm:expr, $chunk_len:expr, $ad:expr ) => {
        #[bench]
        fn $benchmark_name(b: &mut test::Bencher) {
            use ring::aead;
            use ring::rand::SystemRandom;
            use super::super::seal_in_place_bench;
            let rng = SystemRandom::new();
            seal_in_place_bench($algorithm, &rng, $chunk_len, $ad, b);
        }
    }
}

macro_rules! ring_seal_in_place_benches {
    ( $name:ident, $algorithm:expr ) => {
        mod $name {
            use crypto_bench;
            use test;

            // A TLS 1.2 finished message.
            ring_seal_in_place_bench!(tls12_finished, $algorithm,
                                      crypto_bench::aead::TLS12_FINISHED_LEN,
                                      &crypto_bench::aead::TLS12_AD);
            ring_seal_in_place_bench!(tls13_finished, $algorithm,
                                      crypto_bench::aead::TLS13_FINISHED_LEN,
                                      &crypto_bench::aead::TLS13_AD);

            // ~1 packet of data in TLS.
            ring_seal_in_place_bench!(tls12_1350, $algorithm, 1350,
                                      &crypto_bench::aead::TLS12_AD);
            ring_seal_in_place_bench!(tls13_1350, $algorithm, 1350,
                                      &crypto_bench::aead::TLS13_AD);

            ring_seal_in_place_bench!(tls12_4k, $algorithm, 4*1024,
                                      &crypto_bench::aead::TLS12_AD);
            ring_seal_in_place_bench!(tls13_4k, $algorithm, 4*1024,
                                      &crypto_bench::aead::TLS13_AD);
            ring_seal_in_place_bench!(tls12_8k, $algorithm, 8*1024,
                                      &crypto_bench::aead::TLS12_AD);
            ring_seal_in_place_bench!(tls13_8k, $algorithm, 8*1024,
                                      &crypto_bench::aead::TLS13_AD);
            ring_seal_in_place_bench!(tls12_1m, $algorithm, 1024*1024,
                                      &crypto_bench::aead::TLS12_AD);
            ring_seal_in_place_bench!(tls13_1m, $algorithm, 1024*1024,
                                      &crypto_bench::aead::TLS13_AD);
        }
    }
}

mod seal_in_place {
    ring_seal_in_place_benches!(aes_128_gcm, &aead::AES_128_GCM);
    ring_seal_in_place_benches!(aes_256_gcm, &aead::AES_256_GCM);
    ring_seal_in_place_benches!(chacha20_poly1305,
                                &aead::CHACHA20_POLY1305);
}
