--TEST--
Test uv_stop ends loop execution
--FILE--
<?php
$loop = uv_default_loop();
$timer = uv_timer_init();

$i = 0;
uv_timer_start($timer, 10, 10, function($timer) use (&$i, $loop) {
    echo "count: {$i}" . PHP_EOL;
    $i++;

    if ($i > 3) {
        uv_stop($loop);
    }
});

uv_run();

echo "finished" . PHP_EOL;
--EXPECT--
count: 0
count: 1
count: 2
count: 3
finished