<?php

$socket = stream_socket_server("tcp://0.0.0.0:9999", $errno, $errstr);
stream_set_blocking($socket, 0);

$poll = uv_poll_init(uv_default_loop(), $socket);

uv_poll_start($poll, UV::READABLE, function($poll, $stat, $ev, $socket) {
    echo "parent poll:\n";
    var_dump($stat);
    $conn = stream_socket_accept($socket);

    $pp = uv_poll_init(uv_default_loop(), $conn);
    uv_poll_start($pp, UV::WRITABLE, function($poll, $stat, $ev, $conn) {
        echo "  cb";
        var_dump($stat);
        var_dump($conn);

        uv_poll_stop($poll);
        uv_fs_write(uv_default_loop(), $conn, "Hello World", -1, function($conn, $nwrite) {
            var_dump($conn);
            fclose($conn);
        });
    });
});

uv_run();
