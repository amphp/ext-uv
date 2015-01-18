--TEST--
Check for uv_exepath
--FILE--
<?php
$path = uv_exepath();

echo (int)preg_match("/php/", $path, $match);
--EXPECT--
1
