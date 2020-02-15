<?php
$udp = uv_udp_init();
var_dump($udp);

uv_udp_bind($udp, uv_ip4_addr('0.0.0.0', 10000));
uv_udp_recv_start($udp,function($stream, $buffer){
    echo "recv:" .  $buffer;
    
    uv_close($stream);
});

$uv = uv_udp_init();
uv_udp_send($uv, "Hello", uv_ip4_addr("0.0.0.0", 10000), function($uv, $status) {
    echo "success" . PHP_EOL;
    uv_close($uv);
});

uv_run();
