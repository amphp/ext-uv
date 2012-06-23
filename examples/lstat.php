<?php

uv_fs_lstat(uv_default_loop(), __FILE__, function($result, $da){
    var_dump($da);
});

uv_run();
