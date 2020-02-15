--TEST--
Check for uv_check
--FILE--
<?php
$loop = uv_default_loop();
$check = uv_check_init($loop);

$idle = uv_idle_init();

$i = 0;
uv_idle_start($idle, function($stat) use (&$i, $idle, $loop){
    $i++;
    
    if ($i > 3) {
        uv_idle_stop($idle);
    }
});

uv_check_start($check, function($check) {
    echo "Hello";
    uv_check_stop($check);
});

uv_run();
--EXPECT--
Hello
