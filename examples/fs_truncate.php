<?php

uv_fs_open(uv_default_loop(),"./tmp", UV::O_WRONLY,
    UV::S_IRWXU | UV::S_IRUSR,
    function($fd) {
        var_dump($fd);
        uv_fs_ftruncate(uv_default_loop(), $fd, 0, function($fd) {
             uv_fs_close(uv_default_loop(), $fd, function(){});
        });
});

uv_run();
