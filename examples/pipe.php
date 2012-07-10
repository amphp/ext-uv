<?php

$pipe = uv_pipe_init(uv_default_loop(), 0);
uv_pipe_open($pipe, 1);
//uv_pipe_bind($pipe,"/tmp/hoge.sock");

uv_write($pipe, "Hello",function($b,$s){
    echo 1;
    uv_close($b);
});

uv_run();
