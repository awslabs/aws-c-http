#!/bin/bash

set -e

echo "Using CC=$CC CXX=$CXX"

PROJECT_PATH="$PWD"
pushd ../
BASE_PATH="$PWD"
INSTALL_PATH="$BASE_PATH/install"
CMAKE_ARGS="-DCMAKE_PREFIX_PATH=$INSTALL_PATH -DCMAKE_INSTALL_PREFIX=$INSTALL_PATH -DENABLE_SANITIZERS=ON $@"

# install_library <git_repo> [<commit>]
function install_library {
    git clone https://github.com/awslabs/$1.git
    pushd $1

    if [ -n "$2" ]; then
        git checkout $2
    fi

    mkdir build
    cd build

    cmake $CMAKE_ARGS ../
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

cd $PROJECT_PATH
mkdir build
cd build
cmake $CMAKE_ARGS ../
cmake --build . --target install

LSAN_OPTIONS=verbosity=1:log_threads=1 ctest --output-on-failure

popd
