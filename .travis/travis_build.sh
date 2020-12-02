# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0.
#
set -e

PROJECT_DIR=`pwd`
cd ..

#build aws-c-common
git clone https://github.com/awslabs/aws-c-common.git
mkdir common-build && cd common-build
cmake ../aws-c-common
make && make test
cd ..

#build s2n
git clone https://github.com/awslabs/s2n.git
mkdir s2n-build && cd s2n-build
cmake ../s2n
make && make test
cd ..

#build aws-c-io
cd $PROJECT_DIR
cppcheck --enable=all --std=c99 --language=c --suppress=unusedFunction -I include ../aws-c-common/include --force --error-exitcode=-1 ./
cd ..
mkdir build && cd build
cmake -Ds2n_DIR="../s2n-build" -Daws-c-common_DIR="../common-build" $PROJECT_DIR
make && make test

