# apt-get install gcc-arm-linux-gnueabi gcc-arm-linux-gnueabihf libc6-armel-cross libc6-dev-armel-cross
# rustup target add arm-unknown-linux-gnueabi

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR arm)
set(CMAKE_C_COMPILER arm-linux-gnueabi-gcc)
set(RUST_TARGET arm-unknown-linux-gnueabi)