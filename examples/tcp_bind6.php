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

$c = uv_tcp_init();
uv_tcp_connect($c, uv_ip6_addr('::1',9999), function($client, $stat){
    if ($stat == 0) {
        uv_write($client,"Hello",function($socket, $stat){
            uv_close($socket);
        });
    }
});

uv_run();
