<?php
$loop = uv_default_loop();
$async = uv_async_init($loop, function($async) {
    var_dump(1);
    uv_close($async);
});

uv_async_send($async);

uv_run();
