<?php

uv_fs_readdir(uv_default_loop(), ".", 0, function($result, $da){
    var_dump($da);
});

uv_run();
