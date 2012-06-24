--TEST--
Check for uv_get_total_memory
--FILE--
<?php
$free = uv_get_total_memory();

echo (int)is_int($free);
--EXPECT--
1