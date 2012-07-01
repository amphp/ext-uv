--TEST--
Check for uv_spawn
--FILE--
<?php
$in  = uv_pipe_init(uv_default_loop(), 1);
$out = uv_pipe_init(uv_default_loop(), 1);

echo "HELLO ";

/* TODO: ENV parameter does not work linux. */
$process = uv_spawn(uv_default_loop(), "php", array('-r','echo "WORLD";'), array(
    "cwd" => dirname(uv_exepath()),
    "pipes" => array(
	$in,
        $out,
    ),
    "env" => array(
        "KEY" => "VALUE",
        "HELLO" => "WORLD",
    )
),function($process, $stat, $signal) use ($out){
    uv_close($process,function(){
    });
});

uv_read_start($out, function($out, $nread, $buffer){
    echo $buffer . PHP_EOL;

    uv_close($out,function(){});
});

uv_run();
--EXPECT--
HELLO WORLD