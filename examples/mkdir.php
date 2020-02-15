<?php

uv_fs_mkdir(uv_default_loop(), "hoge", 0644, function($result) {
    var_dump($result);
});

uv_run();
