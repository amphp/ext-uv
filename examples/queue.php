<?php
$loop = uv_default_loop();

$queue = uv_queue_work($loop, function(){
    echo "[queue]";
}, function(){
    echo "[finished]";
});


uv_run();

