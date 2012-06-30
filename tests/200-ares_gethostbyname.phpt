--TEST--
Check for ares_gethostbyname
--FILE--
<?php
$uv = uv_ares_init_options(uv_default_loop(), array(
    "servers" => array(
        "8.8.8.8"
    ),
    "port"=>53
),null);

ares_gethostbyname($uv,"php.net",AF_INET, function($name, $addr){
    echo $name . PHP_EOL;
    if (is_array($addr)) {
        echo "OK";
    }  else {
        echo "FAILED";
    }
});

ares_gethostbyname($uv,"php.net",AF_INET, function($name, $addr){
    echo $name . PHP_EOL;
    if (is_array($addr)) {
        echo "OK" . PHP_EOL;
    }  else {
        echo "FAILED: 2nd parameter does not array" . PHP_EOL;
    }
});

uv_run();
--EXPECT--
php.net
OK
php.net
OK