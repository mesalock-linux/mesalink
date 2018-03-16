# Cross compiling MesaLink

Despite that MesaLink is written in Rust, we have crafted the build script to
help you cross compile MesaLink in a way that is similar to cross-compiling
OpenSSL.

## Know your target triple
In general, cross compiling involves two different systems/devices/environments:
a **build** environment where your compiler runs and your code resides; and a
**target** or **host** environment where the compiled binary would run. Note
that some literature may use a different definition for **host**. In this
article we follow the
[autotool](https://www.gnu.org/software/autoconf/manual/autoconf-2.65/html_node/Specifying-Target-Triplets.html)
definition and use target and host interchangeably. 

Knowing the target is the first step in cross compiling MesaLink. Typically, a
target is represented as a **triple** of a system's `architecture`, `vendor`,
`operating system`, and `abi`. For example, the triple
`arm-unknown-linux-gnueabi` is a commonly used target for 32-bit ARM devices
that run Linux; `x86_64-apple-darwin` is the target for a 2017 Macbook running
macOS. Sometimes the C/C++ and Rust community do not strictly follow the
convention of target triple names. For example, `x86_64-apple-darwin` does not
have the `abi` part (and thus is an actual "triple"). Here we list a few
commonly used target triples for C/C++ and Rust, respectively.

| C/C++         | Rust          | Notes |
|:-------------:|:-------------:|------:|
| arm-linux-gnueabi | arm-unknown-linux-gnueabi | ARM Linux|
| arm-linux-gnueabihf | arm-unknown-linux-gnueabihf | ARM Linux, hardfloat |
| armv7-none-linux-androideabi (Android NDK) | arm-linux-androideabi | ARM Android |
| aarch64-linux-android (Android NDK) | aarch64-linux-android | ARM64 Android |
| i686-linux-android | i686-linux-android | 32bit x86 Android |
| x86_64-linux-android | x86_64-linux-android | 64bit x86_64 Android |

A list of target tuples supported by Rust can be found from [Rust Platform
Support](https://forge.rust-lang.org/platform-support.html), or by executing the
following command:
```
$ rustc --print target-list
```

## Install a C/C++ toolchain
Where to acquire the C/C++ toolchain depends on the build system and your
choice. Some Linux distributions provide prebuilt toolchain packages. For
example, on Ubuntu 16.04, you may install a toolchain for
`arm-unknown-linux-gnueabi` with the following command:

```
$ sudo apt-get install gcc-arm-linux-gnueabi g++-arm-linux-gnueabi
```

To test if the toolchain is installed, add `gcc` after the target triple and run:
```
$ arm-linux-gnueabi-gcc
arm-linux-gnueabi-gcc: fatal error: no input files
compilation terminated.
```

Alternatively, you can download and install toolchains from third-parties such
as [Linaro](https://www.linaro.org/downloads/). A special case is Android, where
the Android NDK provides the toolchain. Please refer to [Standalone
Toolchains](https://developer.android.com/ndk/guides/standalone_toolchain.html)
to setup the toolchain if you are cross-compiling for Android.

## Add a Rust target
To cross compile Rust code, you would need to add a `target` with rustup. For
example,

```
$ rustup target add arm-unknown-linux-gnueabi
info: downloading component 'rust-std' for 'arm-unknown-linux-gnueabi'
info: installing component 'rust-std' for 'arm-unknown-linux-gnueabi'
$
```

Just replace `arm-unknown-linux-gnueabi` with your target triple. You may check
a list of installed Rust targets with the following command:
```
$ rustup show
Default host: x86_64-apple-darwin

installed toolchains
--------------------

stable-x86_64-apple-darwin
nightly-x86_64-apple-darwin (default)

installed targets for active toolchain
--------------------------------------

arm-unknown-linux-gnueabihf
i686-unknown-linux-gnu
x86_64-apple-darwin

active toolchain
----------------

nightly-x86_64-apple-darwin (default)
rustc 1.25.0-nightly (3ec5a99aa 2018-02-14)
$
```

## Cross compiling MesaLink
Once the toolchains are ready, cross compiling MesaLink is as easy as just two
extra arguments for the `configure` script. Pass the C/C++ and Rust target
triples with `--host` and `--enable-rusthost`. For example:

```
$ ./configure --host=arm-linux-gnueabi --enable-rusthost=arm-unknown-linux-gnueabi
...

---
Configuration summary for mesalink version 0.1.0

   * Installation prefix:        /usr/local              
   * Host:                       arm-unknown-linux-gnueabi
   * Rust Host:                  arm-unknown-linux-gnueabi
   * C Compiler:                 arm-linux-gnueabi-gcc
   * C Compiler vendor:          gnu
   * C Flags:                    -Os -ffunction-sections -fdata-sections -Wl,--gc-sections  -Werror -Wno-pragmas -Wall -Wno-strict-aliasing -Wextra -Wunknown-pragmas --param=ssp-buffer-size=1 -Waddress -Warray-bounds -Wbad-function-cast -Wchar-subscripts -Wcomment -Wfloat-equal -Wformat-security -Wformat=2 -Wmaybe-uninitialized -Wmissing-field-initializers -Wmissing-noreturn -Wmissing-prototypes -Wnested-externs -Wnormalized=id -Woverride-init -Wpointer-arith -Wpointer-sign -Wredundant-decls -Wshadow -Wsign-compare -Wstrict-overflow=1 -Wswitch-enum -Wundef -Wunused -Wunused-result -Wunused-variable -Wwrite-strings -fwrapv
   * Debug enabled:              no

   Features
   * Logging and error strings:  yes
   * AES-GCM:                    yes
   * Chacha20-Poly1305:          yes
   * TLS 1.3 (draft):            yes
   * X25519 key exchange:        yes
   * EC key exchange:            yes
   * RSA signature verification: yes
   * EC signature verification:  yes
___
```
