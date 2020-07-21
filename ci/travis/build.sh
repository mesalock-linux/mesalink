#!/bin/bash

set -xev

if [[ x"$TARGET" == "x" ]]
then
    #./autogen.sh --enable-examples
    mkdir -p build && cd build && cmake -DCMAKE_INSTALL_PREFIX=../inst ..
else
    rustup target add $RUST_TARGET
    #./autogen.sh --host=$TARGET --enable-rusthost=$RUST_TARGET
    mkdir -p build && cd build && cmake -DCMAKE_INSTALL_PREFIX=../inst -DCMAKE_TOOLCHAIN_FILE=${TRAVIS_BUILD_DIR}/cmake/${TARGET}.toolchain.cmake ..
fi

make
make install
if [[ -d "$TRAVIS_BUILD_DIR/inst/lib/" ]]
then
    du -sh $TRAVIS_BUILD_DIR/inst/lib/*
fi
