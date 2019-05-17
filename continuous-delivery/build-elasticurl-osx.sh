#!/bin/bash
#before running this, you'll need cmake3 and a compiler.
set -e
export MACOSX_DEPLOYMENT_TARGET="10.9"
mkdir install
mkdir aws-c-common-build
mkdir aws-c-io-build
mkdir aws-c-compression-build
mkdir aws-c-http-build
cd aws-c-common-build
cmake -DCMAKE_INSTALL_PREFIX=`pwd`/../install -DBUILD_TESTING=OFF ../aws-c-common
make -j
make install
cd ..
cd aws-c-compression-build
cmake -DCMAKE_PREFIX_PATH=`pwd`/../install -DCMAKE_INSTALL_PREFIX=`pwd`/../install -DBUILD_TESTING=OFF ../aws-c-compression
make -j
make install
cd ..
cd aws-c-io-build
cmake -DCMAKE_PREFIX_PATH=`pwd`/../install -DCMAKE_INSTALL_PREFIX=`pwd`/../install -DBUILD_TESTING=OFF ../aws-c-io
make -j
make install
cd ..
cd aws-c-http-build
cmake -DCMAKE_PREFIX_PATH=`pwd`/../install -DCMAKE_INSTALL_PREFIX=`pwd`/../install -DBUILD_TESTING=OFF ../aws-c-http
make -j
make install
cd ..

install/bin/elasticurl --version 
install/bin/elasticurl -v TRACE https://example.com 

