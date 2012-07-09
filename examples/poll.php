<?php
$poll = uv_poll_init(uv_default_loop(), 0);

uv_poll_start($poll, UV::READABLE | UV::WRITABLE, function($rsc, $stat, $ev, $fd){
    uv_fs_write(uv_default_loop(), $fd, "Hello", function($r){});
    uv_poll_stop($rsc);
});

uv_run();
