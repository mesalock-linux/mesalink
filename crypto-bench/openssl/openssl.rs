#![feature(test)]

extern crate test;

#[macro_use]
extern crate crypto_bench;

extern crate openssl;

mod aead;

macro_rules! openssl_digest_benches {
    ( $name:ident, $block_len:expr, $alg:expr) => {
        mod $name {
            use crypto_bench;
            use openssl::hash;

            digest_benches!($block_len, input, {
                let _ = hash::hash($alg, input);
            });
        }
    }
}

mod digest {
    openssl_digest_benches!(
        sha1,
        crypto_bench::SHA1_BLOCK_LEN,
        hash::MessageDigest::sha1()
    );
    openssl_digest_benches!(
        sha256,
        crypto_bench::SHA256_BLOCK_LEN,
        hash::MessageDigest::sha256()
    );
    openssl_digest_benches!(
        sha384,
        crypto_bench::SHA384_BLOCK_LEN,
        hash::MessageDigest::sha384()
    );
    openssl_digest_benches!(
        sha512,
        crypto_bench::SHA512_BLOCK_LEN,
        hash::MessageDigest::sha512()
    );
}

mod pbkdf2 {
    use crypto_bench;
    use openssl;
    use test;

    pbkdf2_bench!(hmac_sha1, 20, out, {
        let mut vec = Vec::new();
        let _ = openssl::pkcs5::pbkdf2_hmac(
            crypto_bench::pbkdf2::PASSWORD_STR.as_bytes(),
            crypto_bench::pbkdf2::SALT,
            crypto_bench::pbkdf2::ITERATIONS as usize,
            openssl::hash::MessageDigest::sha1(),
            &mut vec,
        );
        for i in 0..vec.len() {
            out[i] = vec[i];
        }
    });
    pbkdf2_bench!(hmac_sha256, 20, out, {
        let mut vec = Vec::new();
        let _ = openssl::pkcs5::pbkdf2_hmac(
            crypto_bench::pbkdf2::PASSWORD_STR.as_bytes(),
            crypto_bench::pbkdf2::SALT,
            crypto_bench::pbkdf2::ITERATIONS as usize,
            openssl::hash::MessageDigest::sha256(),
            &mut vec,
        );
        for i in 0..vec.len() {
            out[i] = vec[i];
        }
    });
    pbkdf2_bench!(hmac_sha384, 20, out, {
        let mut vec = Vec::new();
        let _ = openssl::pkcs5::pbkdf2_hmac(
            crypto_bench::pbkdf2::PASSWORD_STR.as_bytes(),
            crypto_bench::pbkdf2::SALT,
            crypto_bench::pbkdf2::ITERATIONS as usize,
            openssl::hash::MessageDigest::sha384(),
            &mut vec,
        );
        for i in 0..vec.len() {
            out[i] = vec[i];
        }
    });
    pbkdf2_bench!(hmac_sha512, 20, out, {
        let mut vec = Vec::new();
        let _ = openssl::pkcs5::pbkdf2_hmac(
            crypto_bench::pbkdf2::PASSWORD_STR.as_bytes(),
            crypto_bench::pbkdf2::SALT,
            crypto_bench::pbkdf2::ITERATIONS as usize,
            openssl::hash::MessageDigest::sha512(),
            &mut vec,
        );
        for i in 0..vec.len() {
            out[i] = vec[i];
        }
    });
}
