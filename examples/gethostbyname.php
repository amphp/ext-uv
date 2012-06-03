<?php
$uv = uv_ares_init_options(uv_default_loop(), array(
    "servers" => array(
        "8.8.8.8"
    ),
    "port"=>53
),null);

ares_gethostbyname($uv,"google.com",AF_INET, function($name, $addr){
    var_dump($name);
    var_dump($addr);
});

uv_run();
