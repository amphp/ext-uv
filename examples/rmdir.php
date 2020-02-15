<?php

uv_fs_rmdir(uv_default_loop(), "hoge", function($result) {
    var_dump($result);
});

uv_run();
