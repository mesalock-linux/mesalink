# ./android-ndk-r17b/build/tools/make_standalone_toolchain.py --arch arm64 --api 21
# rustup target add aarch64-linux-android

set(CMAKE_SYSTEM_NAME Android)
set(CMAKE_SYSTEM_PROCESSOR aarch64)
set(CMAKE_C_COMPILER aarch64-linux-android-gcc)
set(CMAKE_CXX_COMPILER aarch64-linux-android-g++)
set(RUST_TARGET aarch64-linux-android)