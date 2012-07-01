<?php

$url = "http://yahoo.co.jp/";

$parts = parse_url($url);
$domain = $parts['host'];
$path = $parts['path'] . '?' . $parts['query'];

$uv = uv_ares_init_options(uv_default_loop(), array(
    "servers" => array(
        "8.8.8.8"
    ),
    "port"=>53
),null);

ares_gethostbyname($uv,$domain, AF_INET, function($name, $addr) use ($path, $host){
    $a = array_shift($addr);
    $address = uv_ip4_addr($a,"80");
    $tcp = uv_tcp_init();

    uv_tcp_connect($tcp, $address, function($client, $stat) use ($path, $host){
    var_dump(uv_tcp_getpeername($client));
    
    $request = <<<EOF
GET {$path} HTTP/1.0
Host: {$host}


EOF;
        echo $request;
        var_dump($client);
        uv_write($client,$request,function($client, $stat){
        	echo "write";
            if ($stat == 0) {
                uv_read_start($client,function($client, $nread, $buffer){
                	echo "\n1\n";
                    //var_dump($buffer);
                    uv_close($client);
                });
            } else {
            	echo 2;
                uv_close($client);
            }
        });
    });
});

uv_run();
