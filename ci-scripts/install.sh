#!/bin/bash

set -ev

if [[ "$TARGET" == "arm-linux-gnueabi" ]]
then
    sudo apt-get install -qq gcc-arm-linux-gnueabi libc6-armel-cross libc6-dev-armel-cross
elif [[ "$TARGET" == "aarch64-linux-gnu" ]]
then
    sudo apt-get install -qq gcc-aarch64-linux-gnu libc6-arm64-cross libc6-dev-arm64-cross
elif [[ "$TARGET" = *"android"* ]]
then
    wget -nv -4 https://dl.google.com/android/repository/android-ndk-r17b-linux-x86_64.zip
    unzip android-ndk-r17b-linux-x86_64.zip  2>&1 >/dev/null
    ./android-ndk-r17b/build/tools/make_standalone_toolchain.py --arch $NDK_ARCH --api $NDK_API --install-dir $PWD/cross
    export PATH="$PATH:$PWD/cross/bin"
fi

if [[ "$COVERAGE" == "yes" ]]
then
    sudo apt-get install -qq libssl-dev
fi
