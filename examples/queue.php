<?php
$prepare = uv_prepare_init();
uv_prepare_start($prepare,function(){


$loop = uv_default_loop();
$a = function(){
    var_dump("[queue]");
};
$b = function(){
    echo "[finished]";
};
$queue = uv_queue_work($loop, $a, $b);
$queue2 = uv_queue_work($loop, $a, $b);

});

uv_run();

