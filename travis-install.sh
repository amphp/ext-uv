#!/bin/bash
set -e
set -o pipefail

# install 'libuv'
mkdir libuv
curl -L https://github.com/libuv/libuv/archive/v1.6.1.tar.gz | tar xzf -
cd libuv-1.6.1 && ./autogen.sh && ./configure --prefix=$(readlink -f `pwd`/../libuv) && make && make install
cd ..

#install 'php-uv'
phpize && ./configure --with-uv=$(readlink -f `pwd`/libuv) && make && make install
echo "extension = uv.so" >> ~/.phpenv/versions/$(phpenv version-name)/etc/php.ini
