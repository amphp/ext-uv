<?php

uv_fs_stat(uv_default_loop(), __FILE__, function($stat) {
    var_dump($stat);
});

uv_run();
