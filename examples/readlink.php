<?php

uv_fs_readlink(uv_default_loop(), "linkPath", function($buffer){
    var_dump($buffer);
});

uv_run();
