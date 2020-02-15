<?php
$loop = uv_default_loop();
$check = uv_check_init($loop);

$idle = uv_idle_init();

$i = 0;
uv_idle_start($idle, function($status) use (&$i, $idle, $loop){
    echo "count: {$i}" . PHP_EOL;
    $i++;
    
    if ($i > 3) {
        uv_idle_stop($idle);
    }
    sleep(1);
});

uv_check_start($check, function($check) {
    echo "Hello\n";
    uv_check_stop($check);
});

uv_run();
