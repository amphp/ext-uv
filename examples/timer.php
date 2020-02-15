<?php
$loop = uv_default_loop();
$timer = uv_timer_init();

$i = 0;
uv_timer_start($timer, 1000, 1000, function($stat) use (&$i, $timer, $loop) {
    echo "count: {$i}" . PHP_EOL;
    $i++;
    
    if ($i > 3) {
        uv_timer_stop($timer);
        uv_unref($timer);
    }
});

uv_run();

echo "finished\n";
