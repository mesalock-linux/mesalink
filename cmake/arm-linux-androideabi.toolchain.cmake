# ./android-ndk-r17b/build/tools/make_standalone_toolchain.py --arch arm --api 19
# rustup target add armv7-linux-androideabi

set(CMAKE_SYSTEM_NAME Android)
set(CMAKE_SYSTEM_PROCESSOR arm)
set(CMAKE_C_COMPILER arm-linux-androideabi-gcc)
set(RUST_TARGET armv7-linux-androideabi)