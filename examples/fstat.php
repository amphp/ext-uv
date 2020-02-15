<?php

uv_fs_open(uv_default_loop(), __FILE__, UV::O_RDONLY, 0, function($file) {
    uv_fs_fstat(uv_default_loop(), $file, function($file, $stat) {
        var_dump($stat);
    });
});

uv_run();
