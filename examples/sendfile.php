<?php

uv_fs_open(uv_default_loop(),__FILE__,UV::O_RDONLY,0, function($r){
    uv_fs_open(uv_default_loop(),"moe.out",UV::O_WRONLY | UV::O_CREAT ,0644, function($x) use ($r){
        uv_fs_sendfile(uv_default_loop(),$r,$x,0,126, function($result){
            echo "sendfile";
            var_dump($result);
    });
    });
});

uv_run();
