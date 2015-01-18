--TEST--
Check for uv_prepare
--FILE--
<?php
$loop = uv_default_loop();
$prepare = uv_prepare_init($loop);

uv_prepare_start($prepare, function($rsc) {
    echo "Hello";
    uv_unref($rsc);
});

uv_run();
--EXPECT--
Hello
