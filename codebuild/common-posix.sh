#!/bin/bash

set -e

echo "Using CC=$CC CXX=$CXX"

CMAKE_ARGS="$@"

# install_library <git_repo> [<commit>]
function install_library {
    git clone https://github.com/awslabs/$1.git
    cd $1

    if [ -n "$2" ]; then
        git checkout $2
    fi

    mkdir build
    cd build

    cmake -DCMAKE_INSTALL_PREFIX=../../install -DENABLE_SANITIZERS=ON $CMAKE_ARGS ../
    make install

    cd ../..
}

cd ../

mkdir -p install

# If TRAVIS_OS_NAME is OSX, skip this step (will resolve to empty string on CodeBuild)
if [ "$TRAVIS_OS_NAME" != "osx" ]; then
    sudo apt-get install libssl-dev -y
    install_library s2n 7c9069618e68214802ac7fbf45705d5f8b53135f
fi
install_library aws-c-common
install_library aws-c-io

cd aws-c-http
mkdir build
cd build
cmake -DCMAKE_INSTALL_PREFIX=../../install -DENABLE_SANITIZERS=ON $CMAKE_ARGS ../

make

LSAN_OPTIONS=verbosity=1:log_threads=1 ctest --output-on-failure

cd ..
