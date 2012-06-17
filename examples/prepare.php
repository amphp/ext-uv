<?php
$loop = uv_default_loop();
$prepare = uv_prepare_init($loop);

uv_prepare_start($prepare, function($status){
    echo "Hello";
    uv_unref(uv_default_loop());
});

uv_run();
