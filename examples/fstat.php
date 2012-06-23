<?php

uv_fs_open(uv_default_loop(), __FILE__, UV::O_RDONLY, 0, function($r){
    uv_fs_fstat(uv_default_loop(), $r, function($result, $da){
        var_dump($da);
    });
});

uv_run();
