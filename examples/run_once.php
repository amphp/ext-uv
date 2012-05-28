<?php
$idle = uv_idle_init();
uv_idle_start($idle, function(){
    echo "Hello";
});

uv_run_once();
