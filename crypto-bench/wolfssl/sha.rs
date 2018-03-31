macro_rules! wolfssl_digest_benches {
    ( $name:ident, $block_len:expr, $digest_len:expr, $t:ty, $init:expr, $update:expr, $final:expr) => {
        mod $name {
            use ffi;
            use std::mem;

            digest_benches!($block_len as usize, input, {
                unsafe {
                    let mut sha: $t = mem::uninitialized();
                    let mut hash: [ffi::byte; $digest_len as usize];
                    hash = mem::uninitialized();
                    let _ = $init(&mut sha);
                    let _ = $update(&mut sha,
                                input.as_ptr() as *const ffi::byte,
                                input.len() as ffi::word32);
                    let _ = $final(&mut sha, hash.as_mut_ptr() as *mut ffi::byte);
                }
            });
        }
    }
}

#[cfg(target_os = "linux")]
mod bench_sha {
    wolfssl_digest_benches!(
        sha1,
        ffi::WC_SHA_BLOCK_SIZE,
        ffi::WC_SHA_DIGEST_SIZE,
        ffi::wc_Sha,
        ffi::wc_InitSha,
        ffi::wc_ShaUpdate,
        ffi::wc_ShaFinal
    );
    wolfssl_digest_benches!(
        sha256,
        ffi::WC_SHA256_BLOCK_SIZE,
        ffi::WC_SHA256_DIGEST_SIZE,
        ffi::wc_Sha256,
        ffi::wc_InitSha256,
        ffi::wc_Sha256Update,
        ffi::wc_Sha256Final
    );
    /*wolfssl_digest_benches!(
        sha384,
        ffi::WC_SHA384_BLOCK_SIZE,
        ffi::WC_SHA384_DIGEST_SIZE,
        ffi::wc_Sha384,
        ffi::wc_InitSha384,
        ffi::wc_Sha384Update,
        ffi::wc_Sha384Final
    );
    wolfssl_digest_benches!(
        sha512,
        ffi::WC_SHA512_BLOCK_SIZE,
        ffi::WC_SHA512_DIGEST_SIZE,
        ffi::wc_Sha512,
        ffi::wc_InitSha512,
        ffi::wc_Sha512Update,
        ffi::wc_Sha512Final
    );*/ // disabled for wolfSSL 3.14
}

#[cfg(target_os = "macos")]
mod bench_sha {
    wolfssl_digest_benches!(
        sha1,
        ffi::SHA_BLOCK_SIZE,
        ffi::SHA_DIGEST_SIZE,
        ffi::Sha,
        ffi::wc_InitSha,
        ffi::wc_ShaUpdate,
        ffi::wc_ShaFinal
    );
    wolfssl_digest_benches!(
        sha256,
        ffi::SHA256_BLOCK_SIZE,
        ffi::SHA256_DIGEST_SIZE,
        ffi::Sha256,
        ffi::wc_InitSha256,
        ffi::wc_Sha256Update,
        ffi::wc_Sha256Final
    );
    /*wolfssl_digest_benches!(
        sha384,
        ffi::SHA384_BLOCK_SIZE,
        ffi::SHA384_DIGEST_SIZE,
        ffi::Sha384,
        ffi::wc_InitSha384,
        ffi::wc_Sha384Update,
        ffi::wc_Sha384Final
    );
    wolfssl_digest_benches!(
        sha512,
        ffi::SHA512_BLOCK_SIZE,
        ffi::SHA512_DIGEST_SIZE,
        ffi::Sha512,
        ffi::wc_InitSha512,
        ffi::wc_Sha512Update,
        ffi::wc_Sha512Final
    );*/ // disabled for wolfSSL 3.14
}
