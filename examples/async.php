<?php
$loop = uv_default_loop();
$async = uv_async_init($loop, function($status){
    var_dump(1);
    uv_unref(uv_default_loop());
});

uv_async_send($async);

uv_run();
