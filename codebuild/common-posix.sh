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

    cmake -DCMAKE_PREFIX_PATH=../../install -DCMAKE_INSTALL_PREFIX=../../install -DENABLE_SANITIZERS=ON $CMAKE_ARGS ../
    make install

    cd ../..
}

cd ../

mkdir -p install

if [ "$TRAVIS_OS_NAME" != "osx" ]; then
    sudo apt-get install libssl-dev -y
fi
install_library aws-c-common
ls -la
pwd
cd aws-c-cal
mkdir build
cd build
cmake -DCMAKE_PREFIX_PATH=../../install -DCMAKE_INSTALL_PREFIX=../../install -DENABLE_SANITIZERS=ON $CMAKE_ARGS ../

make

LSAN_OPTIONS=verbosity=1:log_threads=1 ctest --output-on-failure

cd ..
