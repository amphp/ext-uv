--TEST--
Check for uv_timer_init and uv_timer_start
--FILE--
<?php
$loop = uv_default_loop();
$timer = uv_timer_init();

$i = 0;
uv_timer_start($timer, 10, 10, function($timer) use (&$i) {
    echo "count: {$i}" . PHP_EOL;
    $i++;
    
    if ($i > 3) {
        uv_timer_stop($timer);
        uv_unref($timer);
    }
});

uv_run();

echo "finished";
--EXPECT--
count: 0
count: 1
count: 2
count: 3
finished
