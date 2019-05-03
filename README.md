# php-uv

[![Build Status](https://secure.travis-ci.org/bwoebi/php-uv.png)](http://travis-ci.org/bwoebi/php-uv)

Interface to libuv for php.

# Install

## \*nix

````
git clone https://github.com/bwoebi/php-uv.git
cd php-uv
phpize
./configure
make
make install
# add `extension=uv.so` to your php.ini
````

## Windows

Windows builds for stable PHP versions are available [from PECL](https://pecl.php.net/package/uv).

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


# Documents

### void uv_unref(resource $uv_t)

##### *Description*

decrement reference

##### *Parameters*

*resource $uv_t*: uv resource handle.

##### *Return Value*

*void *:

##### *Example*

````php
<?php
$tcp = uv_tcp_init();
uv_unref($tcp);

````



### long uv_last_error([resource $uv_loop])

##### *Description*

get last error code.

##### *Parameters*

*resource $uv_loop*: uv loop handle

##### *Return Value*

*long $error_code*: error code

##### *Example*

````php
<?php
$err = uv_last_error();
var_dump($err);
````


### string uv_err_name(long $error_code)

##### *Description*

get error code name.

##### *Parameters*

*long $error_code*: libuv error code

##### *Return Value*

*string $erorr_name*: error name

##### *Example*

````php
<?php
$err = uv_last_error();
var_dump(uv_err_name($err));
````


### string uv_strerror(long $error_code)

##### *Description*

get error message.

##### *Parameters*

*long $error_code*: libuv error code

##### *Return Value*

*string $erorr_message*: error message

##### *Example*

````php
<?php
$err = uv_last_error();
var_dump(uv_strerror($err));
````



### void uv_update_time(resource $uv_loop)


### void uv_ref(resource $uv_handle)

##### *Description*

increment reference count

##### *Parameters*

*resource $uv_handle*: uv resource.

##### *Return Value*

*void*:

##### *Example*

````php
<?php
$tcp = uv_tcp_init();
uv_ref($tcp);
````

##### *TODO*

* support uv_loop resource



### void uv_run([resource $uv_loop])

##### *Description*

run event loop

##### *Parameters*

*resource $uv_loopg*: uv_loop resource

##### *Return Value*

*void*:

##### *Example*

````php
<?php
$loop = uv_default_loop();
$async = uv_async_init($loop, function($async, $status){
    var_dump(1);
    uv_close($async);
});

uv_async_send($async);

uv_run();
````



### void uv_run_once([resource $uv_loop])


### void uv_loop_delete(resource $uv_loop)

##### *Description*

delete specified loop resource.

##### *Parameters*

*resource $uv_loop*: uv_loop resource

##### *Return Value*

*void*:

##### *Example*



### long uv_now(resource $uv_loop)


### void uv_tcp_bind(resource $uv_tcp, resource $uv_sockaddr)

##### *Description*

binds a name to a socket.

##### *Parameters*

*resource $uv_tcp*: uv_tcp resource

*resource $uv_sockaddr*: uv sockaddr4 resource.

##### *Return Value*

*void*:

##### *Example*

````php
<?php
$tcp = uv_tcp_init();

uv_tcp_bind($tcp, uv_ip4_addr('0.0.0.0',9999));

uv_listen($tcp,100, function($server){
    $client = uv_tcp_init();
    uv_accept($server, $client);
    var_dump(uv_tcp_getsockname($server));

    uv_read_start($client, function($socket, $nread, $buffer) use ($server){
        var_dump($buffer);
        uv_close($socket);
        uv_close($server);
    });
});
````



### void uv_tcp_bind6(resource $uv_tcp, resource $uv_sockaddr)

##### *Description*

binds a name to a socket.

##### *Parameters*

*resource $uv_tcp*: uv_tcp resource

*resource $uv_sockaddr*: uv sockaddr6 resource.

##### *Return Value*

*void*:

##### *Example*

````php
<?php
$tcp = uv_tcp_init();
uv_tcp_bind6($tcp, uv_ip6_addr('::1',9999));

uv_listen($tcp,100, function($server){
    $client = uv_tcp_init();
    uv_accept($server, $client);
    var_dump(uv_tcp_getsockname($server));

    uv_read_start($client, function($socket, $nread, $buffer) use ($server){
        var_dump($buffer);
        uv_close($socket);
        uv_close($server);
    });
});
````



### void uv_write(resource $handle, string $data, callable $callback)

##### *Description*

send buffer to speicified uv resource.

##### *Parameters*

*resource $handle*: uv resources (uv_tcp, uv_udp, uv_pipe ...etc.)
*string $data*: buffer.
*callable $callback*: callable variables. this callback expects (resource $handle, long $status)

##### *Return Value*

*void*:

##### *Example*



### void uv_write2(resource $handle, string $data, resource $send, callable $callback)


### void uv_tcp_nodelay(resource $handle, bool $enable)

##### *Description*

set Nagel's flags for specified tcp resource.

##### *Parameters*

*resource $handle*: libuv tcp resource

*bool $enable*: true means enabled. false means disabled.

##### *Return Value*

*void*:

##### *Example*

````php
<?php
$tcp = uv_tcp_init();
uv_tcp_nodelay($tcp, true);
````


### void uv_accept(resource $server, resource $client)

##### *Description*

accepts a connection on a socket.

##### *Parameters*

*resource $uv*: uv_tcp or uv_pipe server resource

*resource $uv*: uv_tcp or uv_pipe client resource.

##### *Return Value*

*void*:

##### *Example*

````php
<?php
$tcp = uv_tcp_init();

uv_tcp_bind($tcp, uv_ip4_addr('0.0.0.0',9999));

uv_listen($tcp,100, function($server){
    $client = uv_tcp_init();
    uv_accept($server, $client);
    var_dump(uv_tcp_getsockname($server));

    uv_read_start($client, function($socket, $nread, $buffer) use ($server){
        var_dump($buffer);
        uv_close($socket);
        uv_close($server);
    });
});
````



### void uv_shutdown(resource $handle, callable $callback)

##### *Description*

shutdown uv handle.

##### *Parameters*

*resource $handle*: uv resources (uv_tcp, uv_udp, uv_pipe ...etc.)
*callable $callback*: callable variables. this callback expects (resource $handle, long $status)

##### *Return Value*

*void*:

##### *Example*



### void uv_close(resource $handle, callable $callback)

##### *Description*

close uv handle.

##### *Parameters*

*resource $handle*: uv resources (uv_tcp, uv_udp, uv_pipe ...etc.)
*callable $callback*: callable variables. this callback expects (resource $handle, long $status)

##### *Return Value*

*void*:

##### *Example*



### void uv_read_start(resource $handle, callable $callback)

##### *Description*

starts read callback for uv resources.

##### *Parameters*

*resource $handle*: uv resources (uv_tcp, uv_udp, uv_pipe ...etc.)

*callable $callback*: callable variables. this callback parameter expects (resource $handle, long $nread, string buffer)

##### *Return Value*

*void*:

##### *Example*

##### *Note*

* You have to handle erorrs correctly. otherwise this will leak.
* if you want to use PHP's stream or socket resource. see uv_fs_poll_init and uv_fs_read.



### void uv_read2_start(resource $handle, callable $callback)


### void uv_read_stop(resource $handle)

##### *Description*

stop read callback

##### *Parameters*

*resource $uv*: uv resource handle which started uv_read.

##### *Return Value*

*void*:

##### *Example*

````php
<?php
$tcp = uv_tcp_init();

uv_tcp_bind($tcp, uv_ip4_addr('0.0.0.0',9999));

uv_listen($tcp,100, function($server){
    $client = uv_tcp_init();
    uv_accept($server, $client);
    var_dump(uv_tcp_getsockname($server));

    uv_read_start($client, function($socket, $nread, $buffer) use ($server){
        uv_read_stop($socket);
        var_dump($buffer);
        uv_close($socket);
        uv_close($server);
    });
});
````



### resource uv_ip4_addr(string $ipv4_addr, long $port)

##### *Description*

create a ipv4 sockaddr.

##### *Parameters*

*string $ipv4_addr*: ipv4 address

*long $port*: port number.

##### *Return Value*

*resource $uv_sockaddr*: sockaddr resource

##### *Example*

````php
<?php
$sockaddr = uv_ip4_addr("127.0.0.1", 8080);
````

##### *Todo*

* check passed ip address is valid.
* check port number is valid



### resource uv_ip6_addr(string $ipv6_addr, long $port)

##### *Description*

create a ipv6 sockaddr.

##### *Parameters*

*string $ipv6_addr*: ipv6 address

*long $port*: port number.

##### *Return Value*

*resource $uv_sockaddr*: sockaddr resource

##### *Example*

````php
<?php
$sockaddr = uv_ip6_addr("::1", 8080);
````

##### *Todo*

* check passed ip address is valid.
* check port number is valid



### void uv_listen(resource $handle, long $backlog, callable $callback)

##### *Description*

listens for a connection on a uv handle.

##### *Parameters*

*resource $handle*: uv resource handle (tcp, udp and pipe)

*long $backlog*: backlog

*callable $callback*: this callback parameter expects (resource $connection, long $status)

##### *Return Value*

*void *:

##### *Example*

````php
<?php
$tcp = uv_tcp_init();

uv_tcp_bind($tcp, uv_ip4_addr('0.0.0.0',9999));

uv_listen($tcp,100, function($server, $status){
    $client = uv_tcp_init();
    uv_accept($server, $client);
    uv_read_start($client, function($socket, $nread, $buffer) use ($server){
        var_dump($buffer);
        uv_close($socket);
        uv_close($server);
    });
});
uv_run();

````



### void uv_tcp_connect(resource $handle, resource $ipv4_addr, callable $callback)

##### *Description*

connect to specified ip address and port.

##### *Parameters*

*resource $handle*: requires `uv_tcp_init()` resource.
*resource $ipv4_addr*: requires uv_sockaddr resource.
*callable $callback*: callable variables.

##### *Return Value*

*void*:

##### *Example*

````php
<?php
$tcp = uv_tcp_init();
uv_tcp_connect($tcp, uv_ip4_addr("127.0.0.1",8080), function($tcp_handle, $status){
	uv_close($tcp_handle);
});

uv_run();
````


### void uv_tcp_connect6(resource $handle, resource $ipv6_addr, callable $callback)

##### *Description*

connect to specified ip address and port.

##### *Parameters*

*resource $handle*: requires `uv_tcp_init()` resource.
*resource $ipv4_addr*: requires uv_sockaddr resource.
*callable $callback*: callable variables.

##### *Return Value*

*void*:

##### *Example*

````php
<?php
$tcp = uv_tcp_init();
uv_tcp_connect($tcp, uv_ip6_addr("::1",8080), function($tcp_handle, $status){
	uv_close($tcp_handle);
});

uv_run();
````


### resource uv_timer_init([resource $loop])

##### *Description*

initialize timer handle.

##### *Parameters*

*resource $loop*: uv_loop resource.

##### *Return Value*

*resource $timer*: initialized timer resource.

##### *Example*

````php
<?php
$timer = uv_timer_init();
````


### void uv_timer_start(resource $timer, long $timeout, long $repeat, callable $callback)

##### *Description*

initialize timer handle.

##### *Parameters*

*resource $loop*: uv_loop resource.

*long $timeout*: periodical event starts when after this timeout. 1000 is 1 sec.

*long $repeat*: repeat interval. 1000 is 1 sec.

##### *Return Value*

*void:

##### *Example*

````php
<?php
$timer = uv_timer_init();
$after_1_second = 1000;
$period_is_1_second = 1000;
uv_timer_start($timer, $after_1_seconds, $period_is_1_second, function($timer, $status){
	echo "Hello\n";
});

uv_run();
````


### void uv_timer_stop(resource $timer)

##### *Description*

stop specified timer.

##### *Parameters*

*resource $timer*: uv timer resource.

##### *Return Value*

*long $retval*:

##### *Example*

````php
<?php
$timer = uv_timer_init();
uv_timer_start($timer, 100, 100, function($timer, $status){
	echo "Hello\n";
	uv_timer_stop($timer);
});

uv_run();
````


### void uv_timer_again(resource $timer)

##### *Description*

restart timer.

##### *Parameters*

*resource $timer*: uv_timer resource.

##### *Return Value*

*void*:

##### *Example*



### void uv_timer_set_repeat(resource $timer, long $repeat)

##### *Description*

set repeat count.

##### *Parameters*

*resource $uv_timer*: uv_timer resource

*long $repeat*: repeat count

##### *Return Value*

*void*:

##### *Example*



### long uv_timer_get_repeat(resource $timer)

##### *Description*

returns repeat interval.

##### *Parameters*

*resource $uv_timer*: uv_timer resource

##### *Return Value*

*long $repeat_time*:

##### *Example*



### resource uv_idle_init([resource $loop])

##### *Description*

initialize uv idle handle.

##### *Parameters*

*resource $loop*: uv_loop resource.

##### *Return Value*

*resource $idle*: initialized idle handle.

##### *Example*

````php
<?php
$loop = uv_default_loop();
$idle = uv_idle_init($loop);
````



### void uv_idle_start(resource $idle, callable $callback)

##### *Description*

start idle callback.

##### *Parameters*

*resource $idle*: uv_idle resource.
*callable $callback*: idle callback.

##### *Return Value*

*long result*:

##### *Example*

````php
<?php
$loop = uv_default_loop();
$idle = uv_idle_init();

$i = 0;
uv_idle_start($idle, function($idle_handle, $stat) use (&$i){
    echo "count: {$i}" . PHP_EOL;
    $i++;

    if ($i > 3) {
        uv_idle_stop($idle);
    }
    sleep(1);
});

uv_run();
````



### void uv_idle_stop(resource $idle)

##### *Description*

stop idle callback.

##### *Parameters*

*resource $idle*: uv_idle resource.

##### *Return Value*

*long result*:

##### *Example*

````php
<?php
$loop = uv_default_loop();
$idle = uv_idle_init();

$i = 0;
uv_idle_start($idle, function($idle_handle, $stat) use (&$i){
    echo "count: {$i}" . PHP_EOL;
    $i++;

    if ($i > 3) {
        uv_idle_stop($idle);
    }
    sleep(1);
});

uv_run();
````



### void uv_getaddrinfo(resource $loop, callable $callback, string $node, string $service, array $hints)


### resource uv_tcp_init([resource $loop])

##### *Description*

create a tcp socket.

##### *Parameters*

*resource $loop*: loop resource or null. if not specified loop resource then use uv_default_loop resource.

##### *Return Value*

*resource php_uv*: uv resource which initialized for tcp.

##### *Example*

````php
<?php
$tcp = uv_tcp_init();
````



### resource uv_default_loop()

##### *Description*

return default loop handle.

##### *Parameters*

##### *Return Value*

*resource $loop*:

##### *Example*

````php
<?php
$loop = uv_default_loop();
````



### resource uv_loop_new()

##### *Description*

create a new loop handle.

##### *Parameters*

##### *Return Value*

*resource $loop*:

##### *Example*

````php
<?php
$loop = uv_loop_new();
````



### resource uv_udp_init([resource $loop])

##### *Description*

create a udp socket.

##### *Parameters*

*resource $loop*: loop resource or null. if not specified loop resource then use uv_default_loop resource.

##### *Return Value*

*resource php_uv*: uv resource which initialized for udp.

##### *Example*

````php
<?php
$udp = uv_udp_init();
````



### void uv_udp_bind(resource $resource, resource $address, long $flags)

##### *Description*

listens for a connection on a uv udp handle.

##### *Parameters*

*resource $handle*: uv resource handle (udp)

*resource $uv_ip_addr*: uv sockaddr(ipv4) resource.

*long $flags*: unused.

##### *Return Value*

*void *:

##### *Example*

````php
<?php
$udp = uv_udp_init();
var_dump($udp);

uv_udp_bind($udp, uv_ip4_addr('0.0.0.0',10000));

uv_udp_recv_start($udp,function($stream, $nread, $buffer){
    echo "recv:" .  $buffer;

    uv_close($stream);
});

$uv = uv_udp_init();
uv_udp_send($uv, "Hello", uv_ip4_addr("0.0.0.0",10000),function($uv, $s){
    echo "success" . PHP_EOL;
    uv_close($uv);
});

uv_run();
````



### void uv_udp_bind6(resource $resource, resource $address, long $flags)

##### *Description*

listens for a connection on a uv udp handle.

##### *Parameters*

*resource $handle*: uv resource handle (udp)

*resource $uv_ip_addr*: uv sockaddr(ipv6) resource.

*long $flags*: Should be 0 or UV::UDP_IPV6ONLY

##### *Return Value*

*void *:

##### *Example*

````php
<?php
$udp = uv_udp_init();
var_dump($udp);

uv_udp_bind6($udp, uv_ip6_addr('::1',10000));

uv_udp_recv_start($udp,function($stream, $nread, $buffer){
    echo "recv:" .  $buffer;

    uv_close($stream);
});

$uv = uv_udp_init();
uv_udp_send6($uv, "Hello", uv_ip6_addr("::1",10000),function($uv, $s){
    echo "success" . PHP_EOL;
    uv_close($uv);
});

uv_run();
````



### void uv_udp_recv_start(resource $handle, callable $callback)

##### *Description*

start receive callback.

##### *Parameters*

*resource $handle*: uv resource handle (udp)

*callable $callback*: this callback parameter expects (resource $stream, long $nread, string $buffer).

##### *Return Value*

*void *:

##### *Example*

````php
<?php
$udp = uv_udp_init();
var_dump($udp);

uv_udp_bind6($udp, uv_ip6_addr('::1',10000));

uv_udp_recv_start($udp,function($stream, $nread, $buffer){
    echo "recv:" .  $buffer;

    uv_close($stream);
});

$uv = uv_udp_init();
uv_udp_send6($uv, "Hello", uv_ip6_addr("::1",10000),function($uv, $s){
    echo "success" . PHP_EOL;
    uv_close($uv);
});

uv_run();
````



### void uv_udp_recv_stop(resource $handle)

##### *Description*

stop receive callback.

##### *Parameters*

*resource $handle*: uv resource handle (udp)

##### *Return Value*

*void *:



### long uv_udp_set_membership(resource $handle, string $multicast_addr, string $interface_addr, long $membership)

##### *Description*

join or leave udp muticast group..

##### *Parameters*

*resource $handle*: uv resource handle (udp)

*string $multicast_addr*: multicast address

*string $interface_addr*: interface address

*long $membership*: UV::JOIN_GROUP or UV::LEAVE_GROUP

##### *Return Value*

*long *: result code

##### *Example*



### void uv_udp_set_multicast_loop(resource $handle, long $enabled)

##### *Description*

set multicast loop

##### *Parameters*

*resource $handle*: uv resource handle (udp)

*long $enabled*:

##### *Return Value*

*void*:

##### *Example*



### void uv_udp_set_multicast_ttl(resource $handle, long $ttl)

##### *Description*

set multicast ttl

##### *Parameters*

*resource $handle*: uv resource handle (udp)

*long $ttl*: multicast ttl

##### *Return Value*

*void*:

##### *Example*



### void uv_udp_set_broadcast(resource $handle, bool $enabled)

##### *Description*

set udp broadcast

##### *Parameters*

*resource $handle*: uv resource handle (udp)

*long $enabled*:

##### *Return Value*

*void*:

##### *Example*



### void uv_udp_send(resource $handle, string $data, resource $uv_addr, callable $callback)

##### *Description*

send buffer to specified address.

##### *Parameters*

*resource $handle*: uv resource handle (udp)

*string $data*: data

*resource uv_addr*: uv_ip4_addr

*callable $callback*: this callback parameter expects (resource $stream, long $status).

##### *Return Value*

*void *:

##### *Example*

````php
<?php
$udp = uv_udp_init();
var_dump($udp);

uv_udp_bind($udp, uv_ip4_addr('::1',10000));

uv_udp_recv_start($udp,function($stream, $nread, $buffer){
    echo "recv:" .  $buffer;

    uv_close($stream);
});

$uv = uv_udp_init();
uv_udp_send($uv, "Hello", uv_ip4_addr("::1",10000),function($uv, $s){
    echo "success" . PHP_EOL;
    uv_close($uv);
});

uv_run();
````


### void uv_udp_send6(resource $handle, string $data, resource $uv_addr6, callable $callback)

##### *Description*

send buffer to specified address.

##### *Parameters*

*resource $handle*: uv resource handle (udp)

*string $data*: data

*resource uv_addr*: uv_ip6_addr

*callable $callback*: this callback parameter expects (resource $stream, long $status).

##### *Return Value*

*void *:

##### *Example*

````php
<?php
$udp = uv_udp_init();
var_dump($udp);

uv_udp_bind6($udp, uv_ip6_addr('::1',10000));

uv_udp_recv_start($udp,function($stream, $nread, $buffer){
    echo "recv:" .  $buffer;

    uv_close($stream);
});

$uv = uv_udp_init();
uv_udp_send6($uv, "Hello", uv_ip6_addr("::1",10000),function($uv, $s){
    echo "success" . PHP_EOL;
    uv_close($uv);
});

uv_run();
````


### bool uv_is_active(resource $handle)


### bool uv_is_readable(resource $handle)


### bool uv_is_writable(resource $handle)


### bool uv_walk(resource $loop, callable $closure[, array $opaque])

##### *TODO*

* implement this.



### long uv_guess_handle(resource $uv)


### long uv_handle_type(resource $uv)

##### *Description*

returns current uv type. (this is not libuv function. util for php-uv)

##### *Parameters*

*resource $uv_handle*: uv_handle

##### *Return Value*

*long $handle_type*: should return UV::IS_UV_* constatns. e.g) UV::IS_UV_TCP

##### *Example*

````php
<?php
$tcp = uv_tcp_init();
var_dump(uv_handle_type($tcp));
````

##### *Note*

* this may change.



### resource uv_pipe_init(resource $loop, long $ipc)

##### *Description*

initialize pipe resource

##### *Parameters*

*resource $uv_loop*: uv_loop resource

*bool $ipc*: when this pipe use for ipc, please set true otherwise false.

##### *Return Value*

*resource $uv_pipe*:

##### *Example*

````php
<?php
$pipe = uv_pipe_init(uv_default_loop(), true);
````



### void uv_pipe_open(resource $handle, long $pipe)

##### *Description*

open a pipe resource.

##### *Parameters*

*resource $uv_handle*: uv pipe handle

*long $pipe: dunnno. maybe file descriptor.

##### *Return Value*

*void*:

##### *Example*



### long uv_pipe_bind(resource $handle, string $name)

##### *Description*

create a named pipe.

##### *Parameters*

*resource $uv_handle*: uv pipe handle

*long $pipe: dunnno. maybe file descriptor.

##### *Return Value*

*void*:

##### *Example*



### void uv_pipe_connect(resource $handle, string $path, callable $callback)

##### *Description*

connect to named pipe.

##### *Parameters*

*resource $uv_handle*: uv pipe handle

*string $path: named pipe path

*callable $callback: this callback parameter expects (resource $pipe, long $status)

##### *Return Value*

*void*:

##### *Example*

````php
<?php
b = uv_pipe_init(uv_default_loop(), 0);
uv_pipe_connect($b, PIPE_PATH, function($a,$b){
    uv_write($b,"Hello", function($stream,$stat){
        uv_close($stream);
    });
});

uv_run();
````



### void uv_pipe_pending_instances(resource $handle, long $count)


### resource uv_ares_init_options(resource $loop, array $options, long $optmask)


### void ares_gethostbyname(resource $handle, string $name, long $flag, callable $callback)


### array uv_loadavg(void)

##### *Description*

retunrs current loadaverage.

##### *Parameters*

##### *Return Value*

*array $loadaverage*:

##### *Example*

````php
<?php
var_dump(uv_loadavg());
//array(3) {
//  [0]=>
//  float(1.7421875)
//  [1]=>
//  float(1.427734375)
//  [2]=>
//  float(1.3955078125)
//}
````

##### *Note*

returns array on windows box. (does not support load average on windows)



### double uv_uptime(void)

##### *Description*

returns current uptime.

##### *Parameters*

##### *Return Value*

*long $uptime*:

##### *Example*

````php
<?php
var_dump(uv_uptime());
//float(1247516)
````



### long uv_get_free_memory(void)

##### *Description*

returns current free memory size.

##### *Parameters*

##### *Return Value*

*long $free*:

##### *Example*

````php
<?php
var_dump(uv_get_free_memory());
//int(135860224)
````



### long uv_get_total_memory(void)

##### *Description*

returns total memory size.

##### *Parameters*

##### *Return Value*

*long $free*:

##### *Example*

````php
<?php
var_dump(uv_get_total_memory());
//int(8589934592)
````



### long uv_hrtime(void)

##### *TODO*

check implmentation



### string uv_exepath(void)

##### *Description*

returns current exepath. basically this will returns current php path.

##### *Parameters*

##### *Return Value*

*string $exepath*:

##### *Example*

````php
<?php
var_dump(uv_exepath());
//string(53) "/Users/chobie/.phpenv/versions/5.4.1-zts-goto/bin/php"
```



### string uv_cwd(void)

##### *Description*

returns current working directory.

##### *Parameters*

##### *Return Value*

*string $cwd*:

##### *Example*

````php
<?php
var_dump(uv_cwd());
//string(24) "/Users/chobie/src/php-uv"
````



### array uv_cpu_info(void)

##### *Description*

returns current cpu informations

.

##### *Parameters*

##### *Return Value*

*array $cpu_info*:

##### *Example*

````php
<?php
var_dump(uv_cpu_info());
//array(8) {
//  [0]=>
//  array(3) {
//    ["model"]=>
//    string(13) "MacBookPro8,2"
//    ["speed"]=>
//    int(2200)
//    ["times"]=>
//    array(5) {
//      ["sys"]=>
//      int(69952140)
//      ["user"]=>
//      int(38153450)
//      ["idle"]=>
//      int(776709120)
//      ["irq"]=>
//      int(0)
//      ["nice"]=>
//      int(0)
//    }
//  }...
````



### array uv_interface_addresses(void)

### resource uv_stdio_new(zval $fd, long $flags)

### resource uv_spawn(resource $loop, string $command, array $args, array $stdio, string $cwd, array $env = array(), callable $callback [,long $flags,  array $options])


### void uv_process_kill(resource $handle, long $signal)

##### *Description*

send signal to specified uv process resource.

##### *Parameters*

*resource $handle*: uv resource handle (process)

*long $signal*:

##### *Return Value*

*void*:

##### *Example*



### void uv_kill(long $pid, long $signal)

##### *Description*

send signal to specified pid.

##### *Parameters*

*long $pid*: process id

*long $signal*:

##### *Return Value*

*void*:

##### *Example*



### bool uv_chdir(string $directory)

##### *Description*

change working directory.

##### *Parameters*

*string $directory*:

##### *Return Value*

*bool *:

##### *Example*



### resource uv_rwlock_init(void)

##### *Description*

initialize rwlock resource

##### *Parameters*

##### *Return Value*

*resource $rwlock*: returns uv rwlock resource

##### *Example*



### uv_rwlock_rdlock(resource $handle)

##### *Description*

set read lock

##### *Parameters*

*resource $handle*: uv resource handle (uv rwlock)

##### *Return Value*

*void *:

##### *Example*



### bool uv_rwlock_tryrdlock(resource $handle)

##### *TODO*

* implemnt this correctly



### void uv_rwlock_rdunlock(resource $handle)

##### *Description*

unlock read lock

##### *Parameters*

*resource $handle*: uv resource handle (uv rwlock)

##### *Return Value*

*void*:

##### *Example*



### uv_rwlock_wrlock(resource $handle)

##### *Description*

set write lock

##### *Parameters*

*resource $handle*: uv resource handle (uv rwlock)

##### *Return Value*

*void *:

##### *Example*



### uv_rwlock_trywrlock(resource $handle)

##### *TODO*

* implement this correctly



### uv_rwlock_wrunlock(resource $handle)

##### *Description*

unlock write lock

##### *Parameters*

*resource $handle*: uv resource handle (uv rwlock)

##### *Return Value*

*void*:

##### *Example*



### uv_lock uv_mutex_init(void)

##### *Description*

initialize mutex resource

##### *Parameters*

##### *Return Value*

*resource $uv_mutex*: uv mutex resource

##### *Example*



### void uv_mutex_lock(uv_lock $lock)

##### *Description*

lock mutex

##### *Parameters*

*resource $handle*: uv resource handle (uv mutex)

##### *Return Value*

*void*:

##### *Example*



### bool uv_mutex_trylock(uv_lock $lock)

##### *TODO*

* implement this correctly



### uv_lock uv_sem_init(long $value)

##### *Description*

initialize semaphore resource

##### *Parameters*

##### *Return Value*

*resource $uv_sem*:

##### *Example*



### void uv_sem_post(uv_lock $sem)

##### *Description*

post semaphore

##### *Parameters*

*resource $handle*: uv resource handle (uv sem)

##### *Return Value*

*void*:

##### *Example*



### void uv_sem_wait(uv_lock $sem)

##### *Todo*

* implemnt this correctly



### void uv_sem_trywait(uv_lock $sem)

##### *Todo*

* implment this correctly



### resource uv_prepare_init(resource $loop)

##### *Description*

initialize prepare resource

##### *Parameters*

*resource $loop*: uv loop handle

##### *Return Value*

*resource $uv_prepare*:

##### *Example*

````php
<?php
$prepare = uv_prepare_init(uv_default_loop());
````



### void uv_prepare_start(resource $handle, callable $callback)

##### *Description*

setup prepare loop callback. (pre loop callback)

##### *Parameters*

*resource $handle*: uv resource handle (prepare)

*callable $callback*: this callback parameter expects (resource $prepare, long $status).

##### *Return Value*

*long *:

##### *Example*
````php

<?php
$loop = uv_default_loop();
$prepare = uv_prepare_init($loop);

uv_prepare_start($prepare, function($rsc, $status){
    echo "Hello";
    uv_unref($rsc);
});

uv_run();
````


### void uv_prepare_stop(resource $handle)

##### *Description*

stop prepare callback

##### *Parameters*

*resource $prepare*: uv resource handle (prepare)

##### *Return Value*

*long*:



### resource uv_check_init([resource $loop])

##### *Description*

setup check resource

##### *Parameters*

*resource $loop*: uv loop handle

##### *Return Value*

*resource uv_check*:

##### *Example*
````php
<?php
$check = uv_check_init(uv_default_loop());
````


### void uv_check_start(resource $handle, callable $callback)

##### *Description*

stats check loop callback. (after loop callback)

##### *Parameters*

*resource $handle*: uv resource handle (check)

*callable $callback*: this callback parameter expects (resource $check, long $status).

##### *Return Value*

*long *:

##### *Example*
````php
<?php
$loop = uv_default_loop();
$check = uv_check_init($loop);

$idle = uv_idle_init();

$i = 0;
uv_idle_start($idle, function($stat) use (&$i, $idle, $loop){
    echo "count: {$i}" . PHP_EOL;
    $i++;

    if ($i > 3) {
        uv_idle_stop($idle);
    }
    sleep(1);
});

uv_check_start($check, function($check, $status){
    echo "Hello";
    uv_check_stop($check);
});

uv_run();
````


### void uv_check_stop(resource $handle)

##### *Description*

stop check callback

##### *Parameters*

*resource $check*: uv resource handle (check)

##### *Return Value*

*void *:



### resource uv_async_init(resource $loop, callable $callback)

##### *Description*

setup async callback

##### *Parameters*

*resource $loop*: uv loop resource

*callback $callback*:

##### *Return Value*

*resource *: uv async resource

##### *Example*



### void uv_async_send(resource $handle)

##### *Description*

send async callback immidiately

##### *Parameters*

*resource $handle*: uv async handle

##### *Return Value*

*void*:

##### *Example*


### void uv_queue_work(resource $loop, callable $callback, callable $after_callback)

##### *Description*

execute callbacks in another thread (requires Thread Safe enabled PHP)


### resource uv_fs_open(resource $loop, string $path, long $flag, long $mode, callable $callback)

##### *Description*

open specified file

##### *Parameters*

*resource $loop*: uv_loop resource.

*string $path*: file path

*long $flag*: file flag. this should be UV::O_RDONLY and some constants flag.

*long $mode*: mode flag. this should be UV::S_IRWXU and some mode flag.

*callable $calback*: this callback parameter expects (resource $stream)


##### *Return Value*

*void*:

##### *Example*

````php
<?php
uv_fs_open(uv_default_loop(),"/tmp/hello",
    UV::O_WRONLY | UV::O_CREAT | UV::O_APPEND,
    UV::S_IRWXU | UV::S_IRUSR,
    function($r){

    uv_fs_write(uv_default_loop(),$r,"hello",0, function($a) use ($r){
        uv_fs_fdatasync(uv_default_loop(),$r,function(){
            echo "fsync finished";
        });
    });
});

uv_run();
````



### void uv_fs_read(resource $loop, zval $fd, long $offset, long $length, callable $callback)

##### *Description*

async read.

##### *Parameters*

*resource $loop*: uv loop handle

*zval $fd*: this expects long $fd, resource $php_stream or resource $php_socket.

*long $offset*: the offset position in the file at which reading should commence.

*long $length*: the length in bytes that should be read starting at position *$offset*.

*resource $callback*: this callback parameter expects (zval $fd, long $nread, string $buffer).

##### *Return Value*

*void *:



### void uv_fs_close(resource $loop, zval $fd, callable $callback)

##### *Description*

close specified file descriptor.

##### *Parameters*

*resource $loop*: uv_loop resource.

*zval $fd*: file descriptor. this expects long $fd, resource $php_stream or resource $php_socket.

*callable $calback*: this callback parameter expects (resource $stream)

##### *Return Value*

*void*:

##### *Example*

##### *todo*

* handling PHP's stream and socket correctly.



### void uv_fs_write(resource $loop, zval $fd, string $buffer, long $offset, callable $callback)

##### *Description*

write buffer to specified file descriptor.

##### *Parameters*

*resource $loop*: uv_loop resource.

*zval $fd*: file descriptor. this expects long $fd, resource $php_stream or resource $php_socket.

*string $buffer*: buffer.

*callable $calback*: this callback parameter expects (resource $stream, long $result)

##### *Return Value*

*void*:

##### *Example*



### void uv_fs_fsync(resource $loop, zval $fd, callable $callback)

##### *Description*

async fsync

##### *Parameters*

*resource $handle*: uv loop handle

*zval $fd*:


*callable $callback*:

##### *Return Value*

*void*:

##### *Example*



### void uv_fs_fdatasync(resource $loop, zval $fd, callable $callback)

##### *Description*

async fdatasync

##### *Parameters*

*resource $handle*: uv loop handle

*zval $fd*:

*callable $callback*:

##### *Return Value*

*void*:

##### *Example*


### void uv_fs_ftruncate(resource $loop, zval $fd, long $offset, callable $callback)

##### *Description*

async ftruncate

##### *Parameters*

*resource $handle*: uv loop handle

*zval $fd*:

*long $offset*:

*callable $callback*:

##### *Return Value*

*void*:

##### *Example*


### void uv_fs_mkdir(resource $loop, string $path, long $mode, callable $callback)

##### *Description*

async mkdir

##### *Parameters*

*resource $handle*: uv loop handle

*string $path*:

*long $mode*:

*callable $callback*:

##### *Return Value*

*void*:

##### *Example*


### void uv_fs_rmdir(resource $loop, string $path, callable $callback)

##### *Description*

async rmdir

##### *Parameters*

*resource $handle*: uv loop handle

*string $path*:

*callable $callback*:

##### *Return Value*

*void*:

##### *Example*


### void uv_fs_unlink(resource $loop, string $path, callable $callback)

##### *Description*

async unlink

##### *Parameters*

*resource $handle*: uv loop handle

*string $path*:

*callable $callback*:

##### *Return Value*

*void*:

##### *Example*


### void uv_fs_rename(resource $loop, string $from, string $to, callable $callback)

##### *Description*

async rename

##### *Parameters*

*resource $handle*: uv loop handle

*string $from*:

*string $to*:

*callable $callback*:

##### *Return Value*

*void*:

##### *Example*



### void uv_fs_utime(resource $loop, string $path, long $utime, long $atime, callable $callback)

##### *Description*

async utime

##### *Parameters*

*resource $handle*: uv loop handle

*string $path*:

*long $utime*:

*long $atime*:

*callable $callback*:

##### *Return Value*

*void*:

##### *Example*



### void uv_fs_futime(resource $loop, zval $fd, long $utime, long $atime callable $callback)

##### *Description*

async futime

##### *Parameters*

*resource $handle*: uv loop handle

*zval $fd*:

*long $utime*:

*long $atime*:

*callable $callback*:

##### *Return Value*

*void*:

##### *Example*


### void uv_fs_chmod(resource $loop, string $path, long $mode, callable $callback)

##### *Description*

async chmod

##### *Parameters*

*resource $handle*: uv loop handle

*string $path*:

*long $mode*:

*callable $callback*:

##### *Return Value*

*void*:

##### *Example*


### void uv_fs_fchmod(resource $loop, zval $fd, long $mode, callable $callback)

##### *Description*

async fchmod

##### *Parameters*

*resource $handle*: uv loop handle

*zval $fd*:

*long $mode*:

*callable $callback*:

##### *Return Value*

*void*:

##### *Example*


### void uv_fs_chown(resource $loop, string $path, long $uid, long $gid, callable $callback)

##### *Description*

async chown

##### *Parameters*

*resource $handle*: uv loop handle

*string $paht*:

*long $uid*:

*long $gid*:

*callable $callback*:

##### *Return Value*

*void*:

##### *Example*


### void uv_fs_fchown(resource $loop, zval $fd, long $uid, $long $gid, callable $callback)

##### *Description*

async fchown

##### *Parameters*

*resource $handle*: uv loop handle

*zval $fd*:

*long $uid*:

*long $gid*:

*callable $callback*:

##### *Return Value*

*void*:

##### *Example*


### void uv_fs_link(resource $loop, string $from, string $to, callable $callback)

##### *Description*

async link

##### *Parameters*

*resource $handle*: uv loop handle

*string $from*:

*string $to*:

*callable $callback*:

##### *Return Value*

*void*:

##### *Example*


### void uv_fs_symlink(resource $loop, string $from, string $to, long $flags, callable $callback)

##### *Description*

async symlink

##### *Parameters*

*resource $handle*: uv loop handle

*string $from*:

*string $to*:

*long $flags*:

*callable $callback*:

##### *Return Value*

*void*:

##### *Example*


### void uv_fs_readlink(resource $loop, string $path, callable $callback)

##### *Description*

async readlink

##### *Parameters*

*resource $handle*: uv loop handle

*string $path*:

*callable $callback*:

##### *Return Value*

*void*:

##### *Example*


### void uv_fs_stat(resource $loop, string $path, callable $callback)

##### *Description*

async stat

##### *Parameters*

*resource $handle*: uv loop handle

*string $path*:

*callable $callback*: this callback parameter expects (resource $stream, array $stat)

##### *Return Value*

*void*:

##### *Example*



### void uv_fs_lstat(resource $loop, string $path, callable $callback)

##### *Description*

async lstat

##### *Parameters*

*resource $handle*: uv loop handle

*string $path*:

*callable $callback*:

##### *Return Value*

*void*:

##### *Example*



### void uv_fs_fstat(resource $loop, zval $fd, callable $callback)

##### *Description*

async fstat

##### *Parameters*

*resource $handle*: uv loop handle

*zval $fd*:

*callable $callback*:

##### *Return Value*

*void*:

##### *Example*



### uv_fs_readdir(resource $loop, string $path, long $flags, callable $callback)

##### *Description*

async readdir

##### *Parameters*

*resource $handle*: uv loop handle

*string $path*:

*long $flags*:

*callable $callback*:

##### *Return Value*

*void*:

##### *Example*


### void uv_fs_sendfile(resource $loop, zval $in_fd, zval $out_fd, long $offset, long $length, callable $callback)

##### *Description*

async sendfile

##### *Parameters*

*resource $handle*: uv loop handle

*zval $in_fd*:

*zval $out_fd*:

*long $offset*:

*long $length*:

*callable $callback*:

##### *Return Value*

*void*:

##### *Example*


### resource uv_fs_event_init(resource $loop, string $path, callable $callback, long $flags = 0)

##### *Description*

initialize fs event.

##### *Parameters*

*resource $handle*: uv loop handle

*string $path*:

*callable $callback*:

##### *Return Value*

*void*:

##### *Example*



### resource uv_tty_init(resource $loop, zval $fd, long $readable)

##### *Description*

initialize tty resource. you have to open tty your hand.

##### *Parameters*

*resource $handle*: uv loop handle

*zval $fd*:

*long $readable*:

##### *Return Value*

*resource $uv_tty*:

##### *Example*



### long uv_tty_get_winsize(resource $tty, long &$width, long &$height)


### long uv_tty_set_mode(resource $tty, long $mode)


### void uv_tty_reset_mode(void)


### string uv_tcp_getsockname(resource $uv_sockaddr)


### string uv_tcp_getpeername(resource $uv_sockaddr)


### string uv_udp_getsockname(resource $uv_sockaddr)


### long uv_resident_set_memory(void)


### string uv_ip4_name(resource uv_sockaddr $address)


### string uv_ip6_name(resource uv_sockaddr $address)


### uv uv_poll_init([resource $uv_loop], zval fd)

##### *Description*

initialize poll

##### *Parameters*

*resource $uv_loop*: uv_loop resource.

*mixed $fd*: this expects long fd, PHP's stream or PHP's socket resource.

##### *Return Value*

*resource uv*: uv resource which initialized poll.

##### *Example*

````php
<?php
$fd = fopen("php://stdout","w+");

$poll = uv_poll_init(uv_default_loop(), $fd);

````

##### *Note*

* some platform doesn't support file descriptor on these method.


### uv uv_poll_start(resource $handle, $events, $callback)

##### *Description*

start polling

##### *Parameters*

*resource $poll*: uv poll resource.

*long $events*: UV::READBLE and UV::WRITABLE flags.

*callable $callback*: this callback parameter expects (resource $poll, long $status, long $events, mixed $connection). the connection parameter passes uv_poll_init'd fd.

##### *Return Value*

*void*:

##### *Example*

````php
<?php
$fd = fopen("php://stdout","w+");

$poll = uv_poll_init(uv_default_loop(), $fd);
uv_poll_start($poll, UV::WRITABLE, function($poll, $stat, $ev, $conn){
        fwrite($conn, "Hello");
        fclose($conn);
        uv_poll_stop($poll);
});

uv_run();
````

##### *Note*

* if you want to use a socket. please use uv_poll_init_socket instead of this. Windows can't handle socket with this function.



### void uv_poll_stop(resource $poll)


### uv uv_fs_poll_init([resource $uv_loop])


### uv uv_fs_poll_start(resource $handle, $callback, string $path, long $interval)


### void uv_fs_poll_stop(resource $poll)


### void uv_stop([resource $uv_loop])

##### *Description*

##### *Parameters*

*resource $uv_loop*: uv loop handle

##### *Return Value*

*void*:

##### *Example*


### resource uv_signal_init([resource $uv_loop])

##### *Description*

##### *Parameters*

*resource $uv_loop*: uv loop handle

##### *Return Value*

*resource*:

##### *Example*

### void uv_signal_start(resource $sig_handle, callable $sig_callback, int $sig_num)

##### *Description*

##### *Parameters*

*resource $sig_handle*: 

*callable $callable*: signal callback

*int $sig_num*: signal

##### *Return Value*

*void*:

##### *Example*

### int uv_signal_stop(resource $sig_handle)

##### *Description*

##### *Parameters*

*resource $sig_handle*: 

##### *Return Value*

*int $sig_num*: 

##### *Example*

