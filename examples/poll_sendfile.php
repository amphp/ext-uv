<?php

$socket = stream_socket_server("tcp://0.0.0.0:9999", $errno, $errstr);

$poll = uv_poll_init(uv_default_loop(), $socket);

uv_poll_start($poll, UV::READABLE, function ($poll, $stat, $ev, $socket) {
    echo "parent poll:\n";
    var_dump($stat);
    $conn = stream_socket_accept($socket);

    $pp = uv_poll_init(uv_default_loop(), $conn);
    uv_poll_start($pp, UV::WRITABLE, function ($poll, $stat, $ev, $conn) {
        echo "  connected callback has: stat -";
        print_r($stat);
        echo "  event -";
        print_r($ev);
        echo "  poll -";
        print_r($poll);

        echo "  stream_get_meta_data(conn) -";
        print_r(\stream_get_meta_data($conn));
        uv_poll_stop($poll);
        uv_fs_open(uv_default_loop(), __FILE__, UV::O_RDONLY, 0, function ($read_fd) use ($conn) {
            uv_fs_fstat(uv_default_loop(), $read_fd, function ($r, $stat) use ($conn) {
                uv_fs_sendfile(uv_default_loop(), $conn, $r, 0, $stat['size'], function ($conn) {
                    fclose($conn);
                    uv_stop(uv_default_loop());
                });
            });
        });
    });
});

uv_run();
