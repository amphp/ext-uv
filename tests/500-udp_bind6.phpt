--TEST--
Check for udp bind
--FILE--
<?php
$udp = uv_udp_init();
uv_udp_bind6($udp, uv_ip6_addr('::1',10000));

uv_udp_recv_start($udp,function($stream, $buffer) {
    echo "recv: " .  $buffer;
    
    uv_close($stream);
});

$uv = uv_udp_init();
uv_udp_send($uv, "Hello", uv_ip6_addr("::1", 10000), function($uv, $s) {
    uv_close($uv);
});

uv_run();
--EXPECT--
recv: Hello
