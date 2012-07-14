<?php

uv_fs_open(uv_default_loop(),__FILE__,UV::O_RDONLY,0, function($read_fd){
    $stdout = 0;
    uv_fs_sendfile(uv_default_loop(),$stdout,$read_fd,0,6, function($result){
    });
});

uv_run();
