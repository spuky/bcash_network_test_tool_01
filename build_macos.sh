#!/bin/bash

set -e 

date
ps axj

echo $1

#################################################################
# Build from source                                           #
#################################################################
cores=$(sysctl -n hw.physicalcpu)
echo "cores: $cores"
COIN_ROOT=$(pwd)

mkdir -p deps/openssl/
cd deps/openssl/
curl -L -O --insecure "https://openssl.org/source/openssl-1.0.1q.tar.gz"
tar -xzf openssl-*.tar.gz
rm -rf openssl-*.tar.gz
cd openssl-*
./Configure darwin64-x86_64-cc --prefix=$COIN_ROOT/deps/openssl/
make && make install
cd $COIN_ROOT

mkdir -p deps/db/
cd deps/db/
curl -L -O --insecure "https://download.oracle.com/berkeley-db/db-6.1.29.NC.tar.gz"
tar -xzf db-6.1.29.NC.tar.gz
rm -rf db-6.1.29.NC.tar.gz
cd db-6.1.29.NC/build_unix/
../dist/configure --enable-cxx --prefix=$COIN_ROOT/deps/db/
make && make install
cd $COIN_ROOT

cd deps
curl -L -O "https://sourceforge.net/projects/boost/files/boost/1.53.0/boost_1_53_0.tar.gz"
tar -xzf boost_1_53_0.tar.gz
rm -rf boost_1_53_0.tar.gz
mv boost_1_53_0 boost
cd boost
./bootstrap.sh
./bjam link=static toolset=clang cxxflags="-std=c++11 -stdlib=libc++" --with-system release
cd $COIN_ROOT

cd test
../deps/boost/bjam toolset=clang cxxflags="-std=c++11 -stdlib=libc++" release
cd $COIN_ROOT

#mkdir $COIN_ROOT/bin/
cp test/bin/clang-darwin-*/release/link-static/stack $COIN_ROOT/bin/coind

echo "coin daemon is starting..."

$COIN_ROOT/bin/coind

exit 0

