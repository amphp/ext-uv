<?php
$tcp = uv_tcp_init();
$address = uv_ip4_addr("173.194.38.65","80");

uv_tcp_connect($tcp, $address, function($stat, $client){
    $request = <<<EOF
GET / HTTP/1.0
Host: google.com


EOF;
    uv_write($client,$request,function($stat, $client){
        if ($stat == 0) {
            uv_read_start($client,function($buffer, $client){
                var_dump($buffer);
                uv_close($client,function(){
                });
            });
        } else {
            uv_close($client,function(){});
        }
    });
});

uv_run();
