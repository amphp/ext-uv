--TEST--
Check uv_async has no memory leak
--FILE--
<?php
$m = memory_get_usage();

$loop = uv_loop_new();

$async = uv_async_init($loop, static function ($async) {
	uv_close($async);
});
uv_async_send($async);

unset($async);

uv_run($loop, UV::RUN_DEFAULT);
uv_loop_delete($loop);
unset($loop);

echo memory_get_usage() - $m, PHP_EOL;
--EXPECTF--
0
