--TEST--
Check for poll read and close
--FILE--
<?php
$socket = stream_socket_server("tcp://0.0.0.0:9999", $errno, $errstr);
stream_set_blocking($socket, 0);

$poll = uv_poll_init(uv_default_loop(), $socket);
uv_poll_start($poll, UV::READABLE, function($poll, $stat, $ev, $socket) {
    $conn = stream_socket_accept($socket);

    uv_poll_stop($poll);
    $pp = uv_poll_init(uv_default_loop(), $conn);
    uv_poll_start($pp, UV::WRITABLE, function($poll, $stat, $ev, $conn) use (&$pp) {
        uv_poll_stop($poll);
        uv_fs_write(uv_default_loop(), $conn, "OK", -1, function($conn, $nwrite){
            fclose($conn);
        });
    });
});

$address = uv_ip4_addr("0.0.0.0","9999");
$tcp = uv_tcp_init();
uv_tcp_connect($tcp, $address, function($client, $stat) {
    $request = <<<EOF
HELO
EOF;
    uv_write($client, $request, function($client, $stat) {
        if ($stat == 0) {
            uv_read_start($client, function($client, $buffer) {
                echo "$buffer\n";
                uv_close($client);
            });
        } else {
            uv_close($client);
        }
    });
});


uv_run();
--EXPECT--
OK
