--TEST--
Check for uv_cpuinfo
--FILE--
<?php
$cpuinfo = uv_cpu_info();

$info = array_shift($cpuinfo);

if (!isset($info["model"])) {
  echo "FAILED: key `model` does not exist" . PHP_EOL;
}
if (!isset($info["speed"])) {
  echo "FAILED: key `speed` does not exist" . PHP_EOL;
}
if (!isset($info["times"])) {
  echo "FAILED: key `times` does not exist" . PHP_EOL;
}

if (!isset($info["times"]["sys"])) {
  echo "FAILED: key `times.sys` does not exist" . PHP_EOL;
}
if (!isset($info["times"]["user"])) {
  echo "FAILED: key `times.user` does not exist" . PHP_EOL;
}
if (!isset($info["times"]["idle"])) {
  echo "FAILED: key `times.idle` does not exist" . PHP_EOL;
}
if (!isset($info["times"]["irq"])) {
  echo "FAILED: key `times.irq` does not exist" . PHP_EOL;
}
if (!isset($info["times"]["nice"])) {
  echo "FAILED: key `times.nice` does not exist" . PHP_EOL;
}

--EXPECT--
