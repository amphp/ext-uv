--TEST--
Segmentation fault after uv_loop_delete
--FILE--
<?php
$loop = uv_loop_new();
uv_loop_delete($loop);
--EXPECTF--
