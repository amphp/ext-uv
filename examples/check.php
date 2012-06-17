<?php
$loop = uv_default_loop();
$check = uv_check_init($loop);

$idle = uv_idle_init();

$i = 0;
uv_idle_start($idle, function($stat) use (&$i, $idle, $loop){
    echo "count: {$i}" . PHP_EOL;
    $i++;
    
    if ($i > 3) {
        uv_idle_stop($idle);
        uv_unref($loop);
    }
    sleep(1);
});

uv_check_start($check, function($status){
    echo "Hello";
});

uv_run();
