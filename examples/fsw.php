<?php

uv_fs_open(uv_default_loop(), "./tmp", UV::O_WRONLY | UV::O_CREAT | UV::O_APPEND,
    UV::S_IRWXU | UV::S_IRUSR,
    function($fd) {
        var_dump($fd);
        uv_fs_write(uv_default_loop(), $fd, "hello", 0, function($fd, $result) {
            var_dump($result);
            var_dump("ok");
            uv_fs_fdatasync(uv_default_loop(), $fd, function(){
               echo "fsync finished";
            });
        });
    }
);


uv_run();
