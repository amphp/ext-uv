<?php

uv_fs_scandir(uv_default_loop(), ".", function($contents) {
    var_dump($contents);
});

uv_run();
