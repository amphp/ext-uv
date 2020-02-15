--TEST--
Check for tcp bind
--FILE--
<?php
$tcp = uv_tcp_init();
uv_tcp_bind($tcp, uv_ip4_addr('0.0.0.0',0));
uv_listen($tcp, 100, function($server){
    $client = uv_tcp_init();
    uv_accept($server, $client);
    uv_read_start($client, function($socket, $buffer) use ($server) {
        echo $buffer . PHP_EOL;
        uv_close($socket);
        uv_close($server);
    });
});

$addrinfo = uv_tcp_getsockname($tcp);

$c = uv_tcp_init();
uv_tcp_connect($c, uv_ip4_addr($addrinfo['address'],$addrinfo['port']), function($client, $stat) {
    if ($stat == 0) {
        uv_write($client,"Hello",function($socket, $stat) {
            uv_close($socket,function() { });
        });
    }
});

uv_run();
--EXPECT--
Hello
