#!/bin/bash

set -xev

if [[ x"$TARGET" == "x" ]]
then
    cargo build --release
else
    rustup target add $RUST_TARGET
    cargo build --release --target="$RUST_TARGET"
fi
