# ./android-ndk-r17b/build/tools/make_standalone_toolchain.py --arch x86_64 --api 21
# rustup target add x86_64-linux-android

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR x86_64)
set(CMAKE_C_COMPILER x86_64-linux-android-gcc)
set(CMAKE_CXX_COMPILER x86_64-linux-android-g++)
set(RUST_TARGET x86_64-linux-android)