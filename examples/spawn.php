<?php

$in  = uv_pipe_init(uv_default_loop(), 1);
$out = uv_pipe_init(uv_default_loop(), 1);

$process = uv_spawn(uv_default_loop(), "php", array('-r','var_dump($_ENV);'), array(
    "cwd" => "/usr/bin/",
    "pipes" => array(
	$in,
        $out,
    ),
    "env" => array(
        "KEY" => "VALUE",
        "HELLO" => "WORLD",
    )
),function($process, $stat, $signal) use ($out){
    echo "spawn_close_cb\n";
    
    var_dump($process);
    var_dump($stat);
    var_dump($signal);

    uv_close($process,function(){
        echo "close";
    });
});

uv_read2_start($out, function($out, $buffer,$stat){
    echo "read2_start";
    var_dump($out);
    var_dump($stat);
    var_dump($buffer);

    uv_close($out,function(){
    });

});

uv_run();
