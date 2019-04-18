#!/usr/bin/env bash

set -e

# Fix issue with chrome and 32-bit multilib
# See http://www.omgubuntu.co.uk/2016/03/fix-failed-to-fetch-google-chrome-apt-error-ubuntu
sudo sed -i -e 's/deb http/deb [arch=amd64] http/' "/etc/apt/sources.list.d/google-chrome.list"
sudo sed -i -e 's/deb http/deb [arch=amd64] http/' "/opt/google/chrome/cron/google-chrome"

if [ $ADDRESS_SIZE = '32' ]; then
    sudo dpkg --add-architecture i386
    sudo apt-get update -qq
    sudo apt-get install -y gcc-multilib
    sudo apt-get install -y libssl-dev:i386 libgcrypt11-dev:i386 build-essential gcc-multilib
    sudo dpkg --purge --force-depends gcc-multilib && sudo dpkg --purge --force-depends libssl-dev

    export CMAKE_FLAGS="-DCMAKE_TOOLCHAIN_FILE=../cmake/Toolchain-Linux-32.cmake"
elif [ $ADDRESS_SIZE = '64' ]; then
    sudo apt-get update -qq
    sudo apt-get install -y libssl-dev
    sudo apt-get install -y libgcrypt11-dev
fi

if [ $LEAK_CHECK = 'valgrind' ]; then
    sudo apt-get install -y valgrind
fi

if [ $CRYPTO_BACKEND = 'mbedTLS' ]; then
    MBEDTLSVER=mbedtls-2.4.0

    curl -L https://github.com/ARMmbed/mbedtls/archive/$MBEDTLSVER.tar.gz | tar -xzf -
    cd mbedtls-$MBEDTLSVER
    cmake $CMAKE_FLAGS -DUSE_SHARED_MBEDTLS_LIBRARY=ON -DCMAKE_INSTALL_PREFIX:PATH=../usr .
    make -j3 install
    cd ..

    export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$PWD/usr/lib;
    export CMAKE_FLAGS="$CMAKE_FLAGS -DCMAKE_PREFIX_PATH=$PWD/usr";
fi
