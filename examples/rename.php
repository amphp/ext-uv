<?php

uv_fs_rename(uv_default_loop(), "moe", "moe2", function($result) {
    var_dump($result);
});

uv_run();
