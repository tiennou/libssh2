#!/usr/bin/env bash

set -e

SOURCE_DIR=${SOURCE_DIR:-$( cd "$( dirname "${BASH_SOURCE[0]}" )" && dirname $( pwd ) )}
BUILD_DIR=$SOURCE_DIR/build

mkdir -p "$BUILD_DIR" && cd "$BUILD_DIR"

if [ $ADDRESS = '32' ]; then
    export CMAKE_FLAGS="-DCMAKE_TOOLCHAIN_FILE=../cmake/Toolchain-Linux-32.cmake"
fi

if [ $CRYPTO_BACKEND = 'OpenSSL' ]; then
    export CMAKE_FLAGS="$CMAKE_FLAGS -DOPENSSL_ROOT_DIR=$OPENSSL_PREFIX/include -DOPENSSL_CRYPTO_LIBRARY=$OPENSSL_PREFIX/lib/libcrypto.so -DOPENSSL_SSL_LIBRARY=$OPENSSL_PREFIX/lib/libssl.so"
elif [ $CRYPTO_BACKEND = 'mbedTLS' ]; then
    export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$PWD/usr/lib;
    export CMAKE_FLAGS="$CMAKE_FLAGS -DCMAKE_PREFIX_PATH=$PWD/usr";
fi

echo "Configuring…"
echo cmake $CMAKE_FLAGS \
    -DCRYPTO_BACKEND=$CRYPTO_BACKEND \
    -DBUILD_SHARED_LIBS=ON \
    -DENABLE_DEBUG_LOGGING=ON \
    -DENABLE_ZLIB_COMPRESSION=$ENABLE_ZLIB_COMPRESSION .. $@
cmake $CMAKE_FLAGS \
    -DCRYPTO_BACKEND=$CRYPTO_BACKEND \
    -DBUILD_SHARED_LIBS=ON \
    -DENABLE_DEBUG_LOGGING=ON \
    -DENABLE_ZLIB_COMPRESSION=$ENABLE_ZLIB_COMPRESSION .. $@

echo "Building…"
cmake --build .
