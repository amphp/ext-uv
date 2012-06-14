<?php

$out = uv_pipe_init(uv_default_loop,0);
uv_spawn(uv_default_loop(), "ps", array(), array(
    "pipes" => array(
        $out,
    )
),function($process,$stat,$signal){
    echo "spawn_close_cb\n";
    
    var_dump($process);
    var_dump($stat);
    var_dump($signal);
    
    uv_close($process,function(){
        echo "close";
        uv_unref(uv_default_loop());
    });
});

uv_read_start($out,function($buffer,$stat) use ($out){
    var_dump($out);
    var_dump($stat);
    var_dump($buffer);
    uv_close($out,function(){
        uv_unref(uv_default_loop());
    });

});

uv_run();
