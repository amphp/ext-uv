#!/bin/bash
set -e
set -o pipefail

# install 'libuv'
git clone --recursive --branch v1.0.0 --depth 1 https://github.com/joyent/libuv.git
pushd libuv
./autogen.sh && ./configure && make && sudo make install
popd

#install 'php-uv'
phpize && ./configure --with-uv --enable-httpparser && make && sudo make install
echo "extension=uv.so" >> `php --ini | grep "Loaded Configuration" | sed -e "s|.*:\s*||"`
