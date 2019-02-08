#!/bin/bash

set -e

echo "Using CC=$CC CXX=$CXX"

CMAKE_ARGS="$@"
cd ..
mkdir -p install
INSTALL_DIR=`pwd`/install
echo $INSTALL_DIR
# install_library <git_repo> [<commit>]
function install_library {
    git clone https://github.com/awslabs/$1.git
    cd $1

    if [ -n "$2" ]; then
        git checkout $2
    fi

    mkdir build
    cd build

    cmake -DCMAKE_PREFIX_PATH=$INSTALL_DIR -DCMAKE_INSTALL_PREFIX=$INSTALL_DIR -DENABLE_SANITIZERS=ON $CMAKE_ARGS ../
    make install

    cd ../..
}

if [ "$TRAVIS_OS_NAME" != "osx" ]; then
    sudo apt-get install libssl-dev -y
fi
install_library aws-c-common

mkdir aws-c-cal-build
cd aws-c-cal-build

cmake -DCMAKE_PREFIX_PATH=$INSTALL_DIR -DCMAKE_INSTALL_PREFIX=$INSTALL_DIR -DENABLE_SANITIZERS=ON $CMAKE_ARGS ../aws-c-cal

make

LSAN_OPTIONS=verbosity=1:log_threads=1 ctest --output-on-failure

cd ..
