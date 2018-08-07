#!/bin/bash

# Until CodeBuild supports macOS, this script is just used by Travis.

set -e

cd ../

mkdir install

git clone https://github.com/awslabs/aws-c-common.git
cd aws-c-common
mkdir build
cd build

cmake -DCMAKE_INSTALL_PREFIX=../../install -DENABLE_SANITIZERS=ON $@ ../
make install

cd ../..

cd aws-c-compression
mkdir build
cd build
cmake -DCMAKE_INSTALL_PREFIX=../../install -DENABLE_SANITIZERS=ON $@ ../

make

LSAN_OPTIONS=verbosity=1:log_threads=1 ctest --output-on-failure
