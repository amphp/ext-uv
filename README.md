# php-uv

[![Build Status](https://secure.travis-ci.org/bwoebi/php-uv.png)](http://travis-ci.org/bwoebi/php-uv)

Interface to libuv for php.

# Install

## \*nix

```bash
git clone https://github.com/bwoebi/php-uv.git
cd php-uv
phpize
./configure
make
make install
# add `extension=uv.so` to your php.ini
```

__Automated__

For **Debian** like distributions, Ubuntu...

```bash
apt-get install libuv1-dev php-pear -y
```

For **RedHat** like distributions, CentOS...

```bash
yum install libuv-devel php-pear -y
```

Now have **Pecl** auto compile, install, and setup.

```bash
pecl channel-update pecl.php.net
pecl install uv-beta
```

## Windows

Windows builds for stable PHP versions are available [from PECL](https://pecl.php.net/package/uv).

Direct download latest from https://windows.php.net/downloads/pecl/releases/uv/0.2.4/

Extract `libuv.dll` to same directory as `PHP` binary executable, and extract `php_uv.dll` to `ext\` directory.

Enable extension `php_sockets.dll` and `php_uv.dll` in php.ini

```powershell
cd C:\Php
Invoke-WebRequest "https://windows.php.net/downloads/pecl/releases/uv/0.2.4/php_uv-0.2.4-7.2-ts-vc15-x64.zip" -OutFile "php_uv-0.2.4.zip"
Invoke-WebRequest "https://windows.php.net/downloads/pecl/releases/uv/0.2.4/php_uv-0.2.4-7.3-nts-vc15-x64.zip" -OutFile "php_uv-0.2.4.zip"
Invoke-WebRequest "https://windows.php.net/downloads/pecl/releases/uv/0.2.4/php_uv-0.2.4-7.4-ts-vc15-x64.zip" -OutFile "php_uv-0.2.4.zip"
7z x -y php_uv-0.2.4.zip libuv.dll php_uv.dll
copy php_uv.dll ext\php_uv.dll
del php_uv.dll
del php_uv-0.2.4.zip
echo extension=php_sockets.dll >> php.ini
echo extension=php_uv.dll >> php.ini
```

# Examples

see examples and tests directory.

````php
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

# Original Author

* Shuhei Tanuma

# Current Maintainer

* Bob Weinand

# License

PHP License

# Documentation

Use your favorite `IDE` and pull in the provided `stubs`.

For deeper usage understanding, see the online [book](https://nikhilm.github.io/uvbook/index.html) for a full tutorial overview.
