# Cross compiling MesaLink

MesaLink added CMake support since 1.0.0. It is recommended to use CMake to cross compile MesaLink.
For example:

```shell
$ sudo apt-get install gcc-arm-linux-gnueabi g++-arm-linux-gnueabi
$ sudo apt-get install gcc-arm-linux-gnueabihf g++-arm-linux-gnueabihf
$ sudo apt-get install libc6-armel-cross libc6-dev-armel-cross

$ rustup target add arm-unknown-linux-gnueabi

$ mkdir build && cd build
$ cmake -DCMAKE_TOOLCHAIN_FILE=../cmake/arm-linux-gnueabi.toolchain.cmake ..
$ make
```