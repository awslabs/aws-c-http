#!/bin/bash

set -e
set -x

echo "Using CC=$CC CXX=$CXX"

sudo apt-get -y install squid
squid3 -v
netstat -plant
service squid restart

BUILD_PATH=/tmp/builds
mkdir -p $BUILD_PATH
INSTALL_PATH=$BUILD_PATH/install
mkdir -p $INSTALL_PATH
CMAKE_ARGS="-DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_PREFIX_PATH=$INSTALL_PATH -DCMAKE_INSTALL_PREFIX=$INSTALL_PATH -DENABLE_SANITIZERS=ON $@"

# pushd $BUILD_PATH
# curl -LO https://sourceware.org/pub/valgrind/valgrind-3.15.0.tar.bz2
# tar xvjf valgrind-*.tar.bz2
# cd valgrind-3.15.0
# ./configure
# make -j && sudo make install
# sudo apt-get install -y libc6-dbg
# popd

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
install_library aws-c-compression

mkdir -p build
pushd build
cmake $CMAKE_ARGS ../
cmake --build . --target install

#valgrind --leak-check=full --track-origins=yes --show-leak-kinds=all `pwd`/tests/aws-c-http-tests tls_negotiation_timeout
LSAN_OPTIONS=verbosity=1:log_threads=1 ctest --output-on-failure
popd
python3 integration-testing/http_client_test.py $INSTALL_PATH/bin/elasticurl

