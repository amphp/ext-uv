--TEST--
Check to make sure uv_loop_new can be used
--SKIPIF--
<?php if(!extension_loaded("uv")) print "skip"; ?>
--FILE--
<?php
$loop = uv_loop_new();
$async = uv_async_init($loop, function($async) {
    echo "Hello";
    uv_close($async);
});
uv_async_send($async);
uv_run($loop);
--EXPECT--
Hello
