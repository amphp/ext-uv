<?php
$tcp = uv_tcp_init();

uv_tcp_bind($tcp, uv_ip4_addr('0.0.0.0', 9999));

uv_listen($tcp, 100, function($server){
    $client = uv_tcp_init();
    uv_accept($server, $client);
    var_dump(uv_tcp_getsockname($server));

    uv_read_start($client, function($socket, $buffer) use ($server) {
        var_dump($buffer);
        uv_close($socket);
        uv_close($server);
    });
});

$c = uv_tcp_init();
uv_tcp_connect($c, uv_ip4_addr('0.0.0.0',9999), function($client, $status) {
    if ($status == 0) {
        uv_write($client, "Hello", function($socket, $status) {
            uv_close($socket);
        });
    }
});

uv_run();
