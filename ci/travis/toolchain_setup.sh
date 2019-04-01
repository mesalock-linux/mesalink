#!/bin/bash

set -xev

if [[ "$TARGET" == "arm-linux-gnueabi" ]]
then
    sudo apt-get install -qq gcc-arm-linux-gnueabi g++-arm-linux-gnueabi gcc-arm-linux-gnueabihf g++-arm-linux-gnueabihf libc6-armel-cross libc6-dev-armel-cross
elif [[ "$TARGET" == "aarch64-linux-gnu" ]]
then
    sudo apt-get install -qq gcc-aarch64-linux-gnu g++-aarch64-linux-gnu libc6-arm64-cross libc6-dev-arm64-cross
elif [[ "$TARGET" == *"windows-gnu"* ]]
then
    sudo apt-get install -qq mingw-w64
fi

if [[ "$TARGET" = *"android"* ]]
then
    wget -nv -4 https://dl.google.com/android/repository/android-ndk-r17b-linux-x86_64.zip
    unzip -o android-ndk-r17b-linux-x86_64.zip 2>&1 >/dev/null
    ./android-ndk-r17b/build/tools/make_standalone_toolchain.py --arch $NDK_ARCH --api $NDK_API --install-dir $PWD/cross
fi

if [[ "$COVERAGE" == "yes" ]]
then
    sudo apt-get install -qq libssl-dev
fi
