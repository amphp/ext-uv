<?php
$loop = uv_default_loop();
$prepare = uv_prepare_init($loop);

uv_prepare_start($prepare, function($prepare) {
    echo "Hello";
    uv_unref($prepare);
});

uv_run();
