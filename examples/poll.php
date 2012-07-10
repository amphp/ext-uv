<?php
$poll = uv_poll_init(uv_default_loop(), 0);

uv_poll_start($poll, UV::READABLE | UV::WRITABLE, function($rsc, $stat, $ev, $fd){
    uv_close($rsc);
});

uv_run();
