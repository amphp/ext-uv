<?php

uv_fs_stat(uv_default_loop(), __FILE__, function($result, $da){
    var_dump($da);
});

uv_run();
