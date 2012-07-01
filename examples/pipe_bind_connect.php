<?php
$a = uv_pipe_init(0,0);
uv_pipe_bind($a,"/tmp/test.sock");
uv_listen($a,8192,function($a){
    $pipe = uv_pipe_init(0,0);
    uv_accept($a,$pipe);
    uv_read_start($pipe,function($p, $nread, $b) use ($pipe){
        var_dump($b);
        var_dump($p);
        echo "'no2x'";
        uv_close($p);
        uv_read_stop($pipe);
    });
});

$b = uv_pipe_init(0,0);
uv_pipe_connect($b, "/tmp/test.sock", function($a,$b){
    uv_write($b,"Hello", function($b,$c){
        uv_close($c);
    });
});

uv_run();
exit;
/*
$ares = uv_ares_init_options($loop,array('servers'=>array(), 'tcp_port', 'flags'), $mask)
*/