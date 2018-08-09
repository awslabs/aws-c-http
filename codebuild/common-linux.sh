#!/bin/bash

cd ../

mkdir install

git clone https://github.com/awslabs/aws-c-common.git
cd aws-c-common
mkdir build
cd build

cmake -DCMAKE_INSTALL_PREFIX=../../install -DENABLE_SANITIZERS=ON $@ ../
make install

cd ../..

cd aws-c-http
mkdir build
cd build
cmake -DCMAKE_INSTALL_PREFIX=../../install -DENABLE_SANITIZERS=ON $@ ../

make

LSAN_OPTIONS=verbosity=1:log_threads=1 ctest --output-on-failure

cd ..

./cppcheck.sh ../install/include
