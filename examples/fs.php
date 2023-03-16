<?php
uv_fs_open(uv_default_loop(),__FILE__, UV::O_RDONLY, 0, function($r){
    uv_fs_read(uv_default_loop(),$r,function($stream, $data) {
        if (is_long($data)) {
            if ($nread < 0) {
                throw new Exception("read error");
            }

                uv_fs_close(uv_default_loop(), $stream, function () {
                });
            } else {
                echo $data;
            }
        });
    });
});

uv_run();
