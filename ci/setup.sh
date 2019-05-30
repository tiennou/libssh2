#!/usr/bin/env bash

set -e

SOURCE_DIR=${SOURCE_DIR:-$( cd "$( dirname "${BASH_SOURCE[0]}" )" && dirname $( pwd ) )}

. $SOURCE_DIR/ci/conf.sh

# Fix issue with chrome and 32-bit multilib
# See http://www.omgubuntu.co.uk/2016/03/fix-failed-to-fetch-google-chrome-apt-error-ubuntu
# sudo sed -i -e 's/deb http/deb [arch=amd64] http/' "/etc/apt/sources.list.d/google-chrome.list"
# sudo sed -i -e 's/deb http/deb [arch=amd64] http/' "/opt/google/chrome/cron/google-chrome"

if [ $ADDRESS_SIZE = '32' ]; then
    sudo dpkg --add-architecture i386
    sudo apt-get update -qq
    sudo apt-get install -y gcc-multilib
    sudo apt-get install -y libssl-dev:i386 libgcrypt-dev:i386 build-essential gcc-multilib
    sudo dpkg --purge --force-depends gcc-multilib && sudo dpkg --purge --force-depends libssl-dev

    OPENSSL_CONFIG="setarch i386 ./config -m32"
elif [ $ADDRESS_SIZE = '64' ]; then
    sudo apt-get update -qq
    sudo apt-get install -y libssl-dev
    sudo apt-get install -y libgcrypt-dev
    OPENSSL_CONFIG="./config"
fi

if [ $LEAK_CHECK = 'valgrind' ]; then
    sudo apt-get install -y valgrind
fi

MBEDTLS_VERSION=mbedtls-2.4.0
OPENSSL_VERSION=openssl-1.1.1b

echo "Installing $CRYPTO_BACKEND"
if [ $CRYPTO_BACKEND = 'OpenSSL' ]; then
    curl -L https://www.openssl.org/source/$OPENSSL_VERSION.tar.gz | tar -xzf -
    cd $OPENSSL_VERSION

    $OPENSSL_CONFIG --prefix=$BUILD_ROOT --openssldir=$BUILD_ROOT
    make -j3 > /dev/null && make install > /dev/null
    cd ..
elif [ $CRYPTO_BACKEND = 'mbedTLS' ]; then
    curl -L https://github.com/ARMmbed/mbedtls/archive/$MBEDTLS_VERSION.tar.gz | tar -xzf -
    cd mbedtls-$MBEDTLS_VERSION

    cmake $CMAKE_FLAGS -DUSE_SHARED_MBEDTLS_LIBRARY=ON -DCMAKE_INSTALL_PREFIX:PATH=$BUILD_ROOT .
    make -j3 install
    cd ..
fi
