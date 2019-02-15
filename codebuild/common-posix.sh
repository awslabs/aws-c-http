#!/bin/bash

set -e

echo "Using CC=$CC CXX=$CXX"

BUILD_PATH=/tmp/builds
mkdir -p $BUILD_PATH
INSTALL_PATH=$BUILD_PATH/install
mkdir -p $INSTALL_PATH
CMAKE_ARGS="-DCMAKE_PREFIX_PATH=$INSTALL_PATH -DCMAKE_INSTALL_PREFIX=$INSTALL_PATH -DENABLE_SANITIZERS=ON $@"

# install_library <git_repo> [<commit>]
function install_library {
    pushd $BUILD_PATH
    git clone https://github.com/awslabs/$1.git

    cd $1
    if [ -n "$2" ]; then
        git checkout $2
    fi

    cmake $CMAKE_ARGS ./
    cmake --build . --target install

    popd
}

# If TRAVIS_OS_NAME is OSX, skip this step (will resolve to empty string on CodeBuild)
if [ "$TRAVIS_OS_NAME" != "osx" ]; then
    sudo apt-get install libssl-dev -y
    install_library s2n 7c9069618e68214802ac7fbf45705d5f8b53135f
fi
install_library aws-c-common
install_library aws-c-io

mkdir -p build
pushd build
cmake $CMAKE_ARGS ../
cmake --build . --target install

LSAN_OPTIONS=verbosity=1:log_threads=1 ctest --output-on-failure

popd
