# apt-get install gcc-aarch64-linux-gnu libc6-arm64-cross libc6-dev-arm64-cross
# rustup target add aarch64-unknown-linux-gnu

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR aarch64)
set(CMAKE_C_COMPILER aarch64-linux-gnu-gcc)
set(RUST_TARGET aarch64-unknown-linux-gnu)