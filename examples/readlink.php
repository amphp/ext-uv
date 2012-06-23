<?php

uv_fs_readlink(uv_default_loop(), "li", function($result,$buffer){
    var_dump($result);
    var_dump($buffer);
});

uv_run();
