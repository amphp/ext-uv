--TEST--
Check for php-uv presence
--SKIPIF--
<?php if (!extension_loaded("uv")) print "skip"; ?>
--FILE--
<?php
echo "uv extension is available";
--EXPECT--
uv extension is available
