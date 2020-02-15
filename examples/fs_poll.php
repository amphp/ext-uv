<?php

$poll = uv_fs_poll_init(uv_default_loop());

uv_fs_poll_start($poll,function($rsc,$stat,$p) {
    var_dump(1);
    var_dump($p);
    // uv_fs_poll_stop($rsc);
}, "/target/directory", 1);

uv_run();
