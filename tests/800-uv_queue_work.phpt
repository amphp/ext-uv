--TEST--
Check for uv_queue_work
--FILE--
<?php
$loop = uv_default_loop();

$a = function(){
    echo "[queue]";
};

$b = function(){
    echo "[finished]";
};
$queue = uv_queue_work($loop, $a, $b);
uv_run();
--EXPECT--
[finished][queue]