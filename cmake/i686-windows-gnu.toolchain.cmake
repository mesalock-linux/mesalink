# apt-get install mingw-w64
# rustup target add i686-pc-windows-gnu

set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR x86)
set(CMAKE_C_COMPILER i686-w64-mingw32-gcc)
set(CMAKE_CXX_COMPILER i686-w64-mingw32-g++)
set(RUST_TARGET i686-pc-windows-gnu)