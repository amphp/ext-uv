--TEST--
Check for uv_loadavg
--FILE--
<?php
$avg = uv_loadavg();

echo "count: " . count($avg) . PHP_EOL;
echo (int)is_float($avg[0]) . PHP_EOL;
echo (int)is_float($avg[1]) . PHP_EOL;
echo (int)is_float($avg[2]) . PHP_EOL;
--EXPECT--
count: 3
1
1
1