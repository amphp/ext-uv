--TEST--
Check for uv_chdir
--FILE--
<?php
uv_chdir(); // don't SEGV

uv_chdir(dirname(__FILE__));
if (uv_cwd() == dirname(__FILE__)) {
  echo "OK";
} else {
  echo "FAILED: expected " . dirname(__FILE__) . ", but " . uv_cwd();
}

--EXPECTF--

Warning: uv_chdir() expects exactly 1 parameter, 0 given in %s on line %d
OK
