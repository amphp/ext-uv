--TEST--
Check for uv_ip4_addr
--FILE--
<?php
var_dump(uv_ip4_addr("0.0.0.0",0));
--EXPECTF--
resource(%d) of type (uv_sockaddr)
