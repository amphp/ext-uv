--TEST--
Check for uv_ip6_addr
--FILE--
<?php
var_dump(uv_ip6_addr("::0",0));
--EXPECTF--
resource(%d) of type (uv_sockaddr)
