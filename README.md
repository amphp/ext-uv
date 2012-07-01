# php-uv

[![Build Status](https://secure.travis-ci.org/chobie/php-uv.png)](http://travis-ci.org/chobie/php-uv)

interface to libuv for php (experimental). also supports http-parser.

# Experimental

This extension is experimental, its functions may change their names 
or move to extension all together so do not rely to much on them you have been warned!

# Install

````
git clone https://github.com/chobie/php-uv.git --recursive
cd php-uv
(cd libuv && make)
phpize
./configure
make
make install
# add `extension=uv.so` to your php.ini
````

# Examples

see examples and tests directory.

````
<?php
$tcp = uv_tcp_init();

uv_tcp_bind($tcp, uv_ip4_addr('0.0.0.0',8888));

uv_listen($tcp,100, function($server){
    $client = uv_tcp_init();
    uv_accept($server, $client);
    var_dump(uv_tcp_getsockname($server));

    uv_read_start($client, function($socket, $nread, $buffer){
        var_dump($buffer);
        uv_close($socket);
    });
});

$c = uv_tcp_init();
uv_tcp_connect($c, uv_ip4_addr('0.0.0.0',8888), function($stream, $stat){
    if ($stat == 0) {
        uv_write($stream,"Hello",function($stream, $stat){
            uv_close($stream);
        });
    }
});

uv_run();
````

# Community

Check out #php-uv on irc.freenode.net.

# Author

* Shuhei Tanuma

# License

PHP License
