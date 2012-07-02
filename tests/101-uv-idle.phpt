--TEST--
Check for uv_idle_init and uv_idle_start
--FILE--
<?php
$loop = uv_default_loop();
$idle = uv_idle_init();

$i = 0;
uv_idle_start($idle, function($stat)
   use (&$i, $idle, $loop) {

    echo "count: {$i}" . PHP_EOL;
    $i++;
    
    if ($i > 3) {
        uv_idle_stop($idle);
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
