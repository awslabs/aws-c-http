#!/bin/bash

set -e

BUILD_32BIT=false
if [ $1 = '32bit' ]; then
    BUILD_32BIT=true
    shift
fi

CMAKE_ARGS="$@"

function install_library {
    git clone https://github.com/awslabs/$1.git
    cd $1
    mkdir build
    cd build

    cmake -DCMAKE_INSTALL_PREFIX=../../install -DENABLE_SANITIZERS=ON $CMAKE_ARGS ../
    make install
    
    cd ../..
}


cd ../

mkdir install

# Special instructions for 32bit s2n.
# As per: https://github.com/awslabs/s2n/blob/master/docs/USAGE-GUIDE.md
if [ "$BUILD_32BIT" = true ]; then
    curl -LO https://www.openssl.org/source/openssl-1.1.0-latest.tar.gz
    tar -xzvf openssl-1.1.0-latest.tar.gz
    cd openssl-1.1.0i
    setarch i386 ./config -fPIC no-shared \
            -m32 no-md2 no-rc5 no-rfc3779 no-sctp no-ssl-trace no-zlib \
            no-hw no-mdc2 no-seed no-idea no-camellia \
            no-bf no-ripemd no-dsa no-ssl2 no-ssl3 no-capieng \
            -DSSL_FORBID_ENULL -DOPENSSL_NO_DTLS1 -DOPENSSL_NO_HEARTBEATS \
            --prefix=`pwd`/../install
    make
    make install
    cd ..

    # Install s2n with specific lib crypto root
    git clone https://github.com/awslabs/s2n.git
    cd s2n
    mkdir build
    cd build

    cmake -DLibCrypto_ROOT_DIR=../../install -DCMAKE_INSTALL_PREFIX=../../install -DENABLE_SANITIZERS=ON $CMAKE_ARGS ../
    make install

    cd ../..
else
    install_library s2n
fi

install_library aws-c-common

cd aws-c-http
mkdir build
cd build
cmake -DCMAKE_INSTALL_PREFIX=../../install -DENABLE_SANITIZERS=ON $CMAKE_ARGS ../

make

LSAN_OPTIONS=verbosity=1:log_threads=1 ctest --output-on-failure

cd ..

# ./cppcheck.sh ../install/include
