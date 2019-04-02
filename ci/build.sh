#!/usr/bin/env bash

set -e

if [ "$B" = "configure" ]; then
    ./buildconf
    ./configure --enable-debug --enable-werror
    make
    make check
fi
if [ "$B" = "cmake" ]; then
    mkdir bin
    cd bin
    cmake $CMAKE_FLAGS \
        -DCRYPTO_BACKEND=$CRYPTO_BACKEND \
        -DBUILD_SHARED_LIBS=$BUILD_SHARED_LIBS \
        -DENABLE_ZLIB_COMPRESSION=$ENABLE_ZLIB_COMPRESSION ..
    cmake --build .
    CTEST_OUTPUT_ON_FAILURE=1 cmake --build . --target test
    cmake --build . --target package
fi
