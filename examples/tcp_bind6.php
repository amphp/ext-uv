<?php
$tcp = uv_tcp_init();

uv_tcp_bind6($tcp, uv_ip6_addr('::1',9999));

uv_listen($tcp,100, function($server){
    $client = uv_tcp_init();
    uv_accept($server, $client);
    var_dump(uv_tcp_getsockname($server));

    uv_read_start($client, function($socket, $buffer, $nread){
        echo $buffer;
        uv_close($socket);
    });
});

$c = uv_tcp_init();
uv_tcp_connect6($c, uv_ip6_addr('::1',9999), function($stat, $client){
    if ($stat == 0) {
        uv_write($client,"Hello",function($stat,$socket){
            uv_close($socket);
        });
    }
});

uv_run();
