#!/bin/bash

set -e 

date
ps axjf

echo $1

#################################################################
# Raspberry Pi notes                                          #
#################################################################
# Increase swap file size.
#sudo nano /etc/dphys-swapfile
#Set CONF_SWAPSIZE=1024 and save /etc/dphys-swapfile
#sudo dphys-swapfile setup
#sudo dphys-swapfile swapon

#################################################################
# Update Ubuntu and install prerequisites                     #
#################################################################
#sudo apt-get update

#################################################################
# Build from source                                           #
#################################################################
NPROC=$(nproc)
echo "nproc: $NPROC"
COIN_ROOT=$(pwd)

#################################################################
# Install all necessary packages for building                 #
#################################################################
#sudo apt-get -y install build-essential
#sudo apt-get update

# Use core count -1 threads.
nproc=$(nproc)
if [ $nproc -eq 1 ]
then
	((job=nproc))
elif [ $nproc -gt 1 ]
then
	((job=nproc-1))
fi

echo "Using $job thread(s)"

mkdir -p deps/openssl/
cd deps/openssl/
wget --no-check-certificate "https://openssl.org/source/openssl-1.0.1q.tar.gz"
tar -xzf openssl-*.tar.gz
rm -rf openssl-*.tar.gz
cd openssl-*
./config threads no-comp --prefix=$COIN_ROOT/deps/openssl/
make -j$job depend && make -j$job && make install
cd $COIN_ROOT

mkdir -p deps/db/
cd deps/db/
wget --no-check-certificate "https://download.oracle.com/berkeley-db/db-6.1.29.NC.tar.gz"
tar -xzf db-6.1.29.NC.tar.gz
rm -rf db-6.1.29.NC.tar.gz
cd db-6.1.29.NC/build_unix/
../dist/configure --enable-cxx --prefix=$COIN_ROOT/deps/db/
make -j$job && make install
cd $COIN_ROOT

cd deps
wget "https://sourceforge.net/projects/boost/files/boost/1.53.0/boost_1_53_0.tar.gz"
tar -xzf boost_1_53_0.tar.gz
rm -rf boost_1_53_0.tar.gz
mv boost_1_53_0 boost
cd boost
./bootstrap.sh
./bjam -j$job link=static toolset=gcc cxxflags=-std=gnu++0x --with-system release
cd $COIN_ROOT

cd test
../deps/boost/bjam -j$job toolset=gcc cxxflags="-std=gnu++0x -fpermissive -msse4" release
cd $COIN_ROOT

cp test/bin/gcc-*/release/link-static/stack $COIN_ROOT/bin/coind

echo "coin daemon is starting..."

nohup $COIN_ROOT/bin/coind >/dev/null 2>&1 &

exit 0

