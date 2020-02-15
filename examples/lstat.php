<?php

uv_fs_lstat(uv_default_loop(), __FILE__, function($stat) {
    var_dump($stat);
});

uv_run();
