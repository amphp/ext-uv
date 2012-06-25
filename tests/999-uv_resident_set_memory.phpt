--TEST--
Check for uv_resident_set_memory
--FILE--
<?php
$resident_mem = uv_resident_set_memory();

if ($resident_mem > 0) {
  echo "OK";
} else {
  echo "FAILED: {resident_mem} should be greater than 0 (maybe)";
}
--EXPECT--
OK