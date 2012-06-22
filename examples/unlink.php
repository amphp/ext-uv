<?php

uv_fs_unlink(uv_default_loop(), "moe", function($result){
    var_dump($result);
});

uv_run();
