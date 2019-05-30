
set -ev

SOURCE_DIR=${SOURCE_DIR:-$( cd "$( dirname "${BASH_SOURCE[0]}" )" && dirname $( pwd ) )}
BUILD_DIR=$SOURCE_DIR/build

mkdir -p $BUILD_DIR/deps

BUILD_ROOT=$(realpath "$BUILD_DIR/deps")
echo "Dependencies will be installed to $BUILD_ROOT"

if [ x$ADDRESS_SIZE = 'x32' ]; then
    export CMAKE_FLAGS="-DCMAKE_TOOLCHAIN_FILE=../cmake/Toolchain-Linux-32.cmake"
fi

if [ $CRYPTO_BACKEND = 'OpenSSL' ]; then
    export CMAKE_FLAGS="$CMAKE_FLAGS -DOPENSSL_ROOT_DIR=$BUILD_ROOT/include -DOPENSSL_CRYPTO_LIBRARY=$BUILD_ROOT/lib/libcrypto.so -DOPENSSL_SSL_LIBRARY=$BUILD_ROOT/lib/libssl.so"
elif [ $CRYPTO_BACKEND = 'mbedTLS' ]; then
    export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:$BUILD_ROOT/lib"
    export CMAKE_FLAGS="$CMAKE_FLAGS -DCMAKE_PREFIX_PATH=$BUILD_ROOT"
fi
