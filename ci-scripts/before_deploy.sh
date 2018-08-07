#!/bin/bash

set -ev

if [[ x"$ARCH" != "x" ] && [ $"TRAVIS_RUST_VERSION" == "stable" ]]
then
    mkdir -p $TRAVIS_BUILD_DIR/releases
    cd $TRAVIS_BUILD_DIR/inst
    tar -zcvf $TRAVIS_BUILD_DIR/releases/mesalink-$TRAVIS_BRANCH-$ARCH.tar.gz *
    cd $TRAVIS_BUILD_DIR
fi
