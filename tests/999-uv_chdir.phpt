--TEST--
Check for uv_chdir
--FILE--
<?php
uv_chdir(); // don't SEGV

if(uv_chdir(dirname(__FILE__))) {
    echo "OK\n";
} else {
    echo "FAILED: expected uv_chdir to return true";
}

if (uv_cwd() == dirname(__FILE__)) {
  echo "OK";
} else {
  echo "FAILED: expected " . dirname(__FILE__) . ", but " . uv_cwd();
}

--EXPECTF--

Warning: uv_chdir() expects exactly 1 parameter, 0 given in %s on line %d
OK
OK
