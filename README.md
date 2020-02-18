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

Direct download latest from https://windows.php.net/downloads/pecl/releases/uv/

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

# Overview of __libuv__

## Design

**libuv** is cross-platform support library which was originally written for __*Node.js*__. It’s designed around the event-driven _asynchronous_ I/O model.

The library provides much more than a simple abstraction over different I/O polling mechanisms: `‘handles’` and `‘streams’` provide a high level abstraction for `sockets` and other entities; cross-platform **file I/O** and **threading** functionality is also provided, amongst other things.

## Handles and Requests

**libuv** provides users with 2 abstractions to work with, in combination with the event loop: handles and requests.

__*Handles*__ represent long-lived objects capable of performing certain operations while active. Some examples:

* A prepare handle gets its callback called once every loop iteration when active.
* A TCP server handle that gets its connection callback called every time there is a new connection.

__*Requests*__ represent (typically) short-lived operations. These operations can be performed over a handle: `uv_write` requests are used to write data on a handle; or standalone: `uv_getaddrinfo` requests don’t need a handle they run directly on the loop.

## The I/O loop

The I/O (or event) loop is the central part of **libuv**. It establishes the content for all I/O operations, and it’s meant to be tied to a **single thread**. One can run multiple event loops as long as each runs in a different thread. The **libuv** event loop (or any other API involving the loop or handles, for that matter) is not thread-safe except where stated otherwise.

The event loop follows the rather usual single threaded asynchronous I/O approach:

* all (network) I/O is performed on _non-blocking sockets_ which are polled using the best mechanism available on the given platform: _epoll_ on `Linux`, _kqueue_ on `OSX` and other BSDs, _event ports_ on `SunOS` and _IOCP_ on `Windows`.

* As part of a loop iteration the loop will block waiting for I/O activity on sockets which have been added to the poller and callbacks will be fired indicating socket conditions (_readable_, _writable_ hangup) so handles can _read_, _write_ or perform the desired I/O operation.

* Use a thread pool to make asynchronous file I/O operations possible, but network I/O is always performed in a single thread, each loop’s thread.

>Note: While the polling mechanism is different, **libuv** makes the execution model consistent across Unix systems and Windows.

![loop][iteration]

## File I/O

Unlike network I/O, there are no platform-specific file I/O primitives **libuv** could rely on, so the current approach is to run blocking file I/O operations in a thread pool.

For a thorough explanation of the cross-platform file I/O landscape, checkout this [post](https://blog.libtorrent.org/2012/10/asynchronous-disk-io/).

**libuv** currently uses a global thread pool on which all loops can queue work. 3 types of operations are currently run on this pool:

* File system operations
* DNS functions (`uv_getaddrinfo`)
* User specified code via `uv_queue_work()`

## Thread pool work scheduling

**libuv** provides a threadpool which can be used to run user code and get notified in the loop thread. This thread pool is internally used to run all file system operations, as well as `uv_getaddrinfo` requests.

Its default size is 4, but it can be changed at startup time (the absolute maximum is 1024).

The threadpool is global and shared across all event loops. When a particular function makes use of the threadpool (i.e. when using `uv_queue_work()`) **libuv** preallocates and initializes the maximum number of threads allowed. This causes a relatively minor memory overhead (~1MB for 128 threads) but increases the performance of threading at runtime.

>Note that even though a global thread pool which is shared across all events loops is used, the functions are not thread safe.

[iteration]: http://docs.libuv.org/en/v1.x/_images/loop_iteration.png
