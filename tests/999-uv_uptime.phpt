--TEST--
Check for uv_uptime
--FILE--
<?php
$uptime = uv_uptime();

echo (int)is_float($uptime);
--EXPECT--
1