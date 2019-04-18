#!/usr/bin/env bash

set -e

SOURCE_DIR=${SOURCE_DIR:-$( cd "$( dirname "${BASH_SOURCE[0]}" )" && dirname $( pwd ) )}
BUILD_DIR=$SOURCE_DIR/build

mkdir -p "$BUILD_DIR" && cd "$BUILD_DIR"

cmake $CMAKE_FLAGS \
    -DCRYPTO_BACKEND=$CRYPTO_BACKEND \
    -DBUILD_SHARED_LIBS=$BUILD_SHARED_LIBS \
    -DENABLE_DEBUG_LOGGING=ON \
    -DENABLE_ZLIB_COMPRESSION=$ENABLE_ZLIB_COMPRESSION ..

cmake --build .

# FIXME: disabled
# cmake --build . --target package
