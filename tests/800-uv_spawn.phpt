--TEST--
Check for uv_spawn
--FILE--
<?php
$in  = uv_pipe_init(uv_default_loop(), true);
$out = uv_pipe_init(uv_default_loop(), true);

echo "HELLO ";

$stdio = array();
$stdio[] = uv_stdio_new($in, UV::CREATE_PIPE | UV::READABLE_PIPE);
$stdio[] = uv_stdio_new($out, UV::CREATE_PIPE | UV::WRITABLE_PIPE);

$flags = 0;
uv_spawn(uv_default_loop(), "php", array('-r','echo "WORLD";'), $stdio, dirname(uv_exepath()), 
    array("key"=>"hello"), 
    function($process, $stat, $signal){
	    uv_close($process,function(){});

}, $flags);

uv_read_start($out, function($out, $nread, $buffer) {
    echo $buffer;

    uv_close($out,function(){});
});

uv_run();

--EXPECT--
HELLO WORLD
