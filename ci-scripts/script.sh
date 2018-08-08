#!/bin/bash

set -xev

# Skip building MesaLink if testing for coverage only
if [[ "$COVERAGE" == "yes" ]]
then
    exit 0
fi

if [[ x"$TARGET" == "x" ]]
then
    ./autogen.sh --enable-examples
else
    rustup target add $RUST_TARGET
    ./autogen.sh --host=$TARGET --enable-rusthost=$RUST_TARGET
fi

make
make DESTDIR=$TRAVIS_BUILD_DIR/inst install-strip
du -sh $TRAVIS_BUILD_DIR/inst/usr/local/lib/libmesalink.*

# Only stable x86_64_macos and x86_64_linux builds run tests
if [[ x"$TARGET" == "x" ]]
then
    ./examples/client/client google.com
    RUST_BACKTRACE=1 cargo test
    ( cd bogo && ./runme )
fi
