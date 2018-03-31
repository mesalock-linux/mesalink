#![feature(test)]

extern crate test;

#[macro_use]
extern crate crypto_bench;

extern crate ring;
extern crate untrusted;

mod aead;

mod agreement {
    macro_rules! ring_agreement_benches {
        ( $name:ident, $alg:expr) => {
            mod $name {
                use ring::{agreement, rand};
                use untrusted;
                use test;

                // Generate a new private key and compute the public key.
                // Although these are separate steps in *ring*, in other APIs
                // they are a single step.
                #[bench]
                fn generate_key_pair(b: &mut test::Bencher) {
                    let rng = rand::SystemRandom::new();
                    b.iter(|| {
                        let private_key = agreement::EphemeralPrivateKey::
                                            generate($alg, &rng).unwrap();
                        let mut pub_key = [0; agreement::PUBLIC_KEY_MAX_LEN];
                        let pub_key =
                            &mut pub_key[..private_key.public_key_len()];
                        private_key.compute_public_key(pub_key).unwrap();
                    });
                }

                #[bench]
                fn generate_private_key(b: &mut test::Bencher) {
                    let rng = rand::SystemRandom::new();
                    b.iter(|| {
                        let _ = agreement::EphemeralPrivateKey::
                                    generate($alg, &rng).unwrap();
                    });
                }

                // XXX: Because ring::agreement::agree_ephemeral moves its
                // private key argument, we cannot measure
                // `agreement::agree_ephemeral` on its own using the Rust
                // `Bencher` interface. To get an idea of its performance,
                // subtract the timing of `generate_private_key` from the
                // timing of this function.
                #[bench]
                fn generate_key_pair_and_agree_ephemeral(b: &mut test::Bencher) {
                    let rng = rand::SystemRandom::new();

                    // These operations are done by the peer.
                    let b_private =
                        agreement::EphemeralPrivateKey::generate($alg, &rng)
                            .unwrap();
                    let mut b_public = [0; agreement::PUBLIC_KEY_MAX_LEN];
                    let b_public =
                        &mut b_public[..b_private.public_key_len()];
                    b_private.compute_public_key(b_public).unwrap();

                    b.iter(|| {
                        // These operations are all done in the
                        // `generate_key_pair` step.
                        let a_private =
                            agreement::EphemeralPrivateKey::generate($alg, &rng)
                                .unwrap();
                        let mut a_public = [0; agreement::PUBLIC_KEY_MAX_LEN];
                        let a_public =
                            &mut a_public[..a_private.public_key_len()];
                        a_private.compute_public_key(a_public).unwrap();

                        let b_public = untrusted::Input::from(b_public);
                        agreement::agree_ephemeral(a_private, $alg, b_public,
                                                   (), |_| {
                            Ok(())
                        }).unwrap();
                    });
                }
            }
        }
    }

    ring_agreement_benches!(p256, &agreement::ECDH_P256);
    ring_agreement_benches!(p384, &agreement::ECDH_P384);
    ring_agreement_benches!(x25519, &agreement::X25519);
}


mod digest {
    macro_rules! ring_digest_benches {
        ( $name:ident, $algorithm:expr) => {
            mod $name {
                use ring::digest;
                digest_benches!($algorithm.block_len, input, {
                    let _ = digest::digest($algorithm, &input);
                });
            }
        }
    }

    ring_digest_benches!(sha1, &digest::SHA1);
    ring_digest_benches!(sha256, &digest::SHA256);
    ring_digest_benches!(sha384, &digest::SHA384);
    ring_digest_benches!(sha512, &digest::SHA512);
}

mod pbkdf2 {
    use crypto_bench;
    use ring::{digest, pbkdf2};
    use test;

    pbkdf2_bench!(hmac_sha256, crypto_bench::SHA256_OUTPUT_LEN, out,
                  pbkdf2::derive(&digest::SHA256,
                                 crypto_bench::pbkdf2::ITERATIONS,
                                 &crypto_bench::pbkdf2::SALT,
                                 crypto_bench::pbkdf2::PASSWORD, &mut out));

    pbkdf2_bench!(hmac_sha384, crypto_bench::SHA384_OUTPUT_LEN, out,
                  pbkdf2::derive(&digest::SHA384,
                                 crypto_bench::pbkdf2::ITERATIONS,
                                 crypto_bench::pbkdf2::SALT,
                                 crypto_bench::pbkdf2::PASSWORD, &mut out));

    pbkdf2_bench!(hmac_sha512, crypto_bench::SHA512_OUTPUT_LEN, out,
                  pbkdf2::derive(&digest::SHA256,
                                 crypto_bench::pbkdf2::ITERATIONS,
                                 crypto_bench::pbkdf2::SALT,
                                 crypto_bench::pbkdf2::PASSWORD, &mut out));

    pbkdf2_bench!(hmac_sha512_256, crypto_bench::SHA512_256_OUTPUT_LEN, out,
                  pbkdf2::derive(&digest::SHA512_256,
                                 crypto_bench::pbkdf2::ITERATIONS,
                                 crypto_bench::pbkdf2::SALT,
                                 crypto_bench::pbkdf2::PASSWORD, &mut out));

}

mod signature {
    mod ed25519 {
        use ring::{rand, signature};
        use test;
        use untrusted;

        #[bench]
        fn generate_key_pair(b: &mut test::Bencher) {
            let rng = rand::SystemRandom::new();
            b.iter(|| {
                signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
            });
        }

        // We're interested in the timing of the Ed25519 operation, not the
        // timing of the hashing, so sign an empty message to minimize the time
        // spent hashing.
        #[bench]
        fn sign_empty(b: &mut test::Bencher) {
            let rng = rand::SystemRandom::new();
            let key_pair = signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
            let key_pair = signature::Ed25519KeyPair::from_pkcs8(
                untrusted::Input::from(&key_pair)).unwrap();
            b.iter(|| {
                let signature = key_pair.sign(b"");
                let _ = signature.as_ref();
            });
        }
    }
}
