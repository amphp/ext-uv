--TEST--
Check for uv_write multiple call with different callbacks
--FILE--
<?php
$loop = uv_loop_new();

$handler = uv_pipe_init($loop, false);
uv_pipe_open($handler, (int) STDOUT);

uv_write($handler, 'A', function () { echo 'A'; });
uv_write($handler, 'B', function () { echo 'B'; });
uv_write($handler, 'C', function () { echo 'C'; });

uv_run($loop);
uv_close($handler);
--EXPECTF--
ABCABC