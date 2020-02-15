<?php

uv_fs_chmod(uv_default_loop(), "moe", 0777, function($result) {
    var_dump($result);
});

uv_run();
