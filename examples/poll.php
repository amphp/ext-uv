<?php

$socket = stream_socket_server("tcp://0.0.0.0:9999", $errno, $errstr);

$poll = uv_poll_init(uv_default_loop(), $socket);
uv_poll_start($poll, UV::READABLE, function($poll, $stat, $ev, $fd) use ($socket){
    $conn = stream_socket_accept($socket);
    echo "poll";
    $pp = uv_poll_init(uv_default_loop(), $conn);
    uv_poll_start($pp, UV::READABLE | UV::WRITABLE, function($poll, $stat, $ev, $fd) use ($conn){
        echo "cb";
        
        uv_fs_write(uv_default_loop(), $fd, "echo", -1, function($fs, $fd){
            var_dump($fs);
        });
        
        uv_fs_close(uv_default_loop(), $fd, function(){
            echo "close";
        });
    });
});

uv_run();