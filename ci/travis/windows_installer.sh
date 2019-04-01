#!/bin/bash

set -xev


mkdir -p $TRAVIS_BUILD_DIR/releases

mkdir build && cd build && cmake -G "Visual Studio 15 2017 Win64" .. && cmake --build .
cpack -D CPACK_GENERATOR="NSIS64"
cp *.exe $TRAVIS_BUILD_DIR/releases/
