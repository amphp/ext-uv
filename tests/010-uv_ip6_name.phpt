--TEST--
Check for uv_ip6_name
--FILE--
<?php
$ip = uv_ip6_addr("::1",0);
echo uv_ip6_name($ip) . PHP_EOL;
--EXPECT--
::1