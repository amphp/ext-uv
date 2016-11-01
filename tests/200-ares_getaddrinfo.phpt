--TEST--
Check for ares_getaddrinfo
--SKIPIF--
<?php
if (getenv("SKIP_ONLINE_TESTS")) {
    die("skip test requiring internet connection\n");
}
?>
--FILE--
<?php
uv_getaddrinfo(uv_default_loop(), function($status, $names) {
    echo "status: " . $status . PHP_EOL;
    if (is_array($names)) {
        echo "OK" . PHP_EOL;
    } else {
        echo "FAILED: 2nd parameter does not array" . PHP_EOL;
    }
},"php.net", NULL, array(
    "ai_family" => UV::AF_UNSPEC
));

uv_getaddrinfo(uv_default_loop(), function($status, $names) {
    echo "status: " . $status . PHP_EOL;
    if (is_array($names)) {
        echo "OK" . PHP_EOL;
    } else {
        echo "FAILED: 2nd parameter does not array" . PHP_EOL;
    }
},"php.net", NULL, array(
    "ai_family" => UV::AF_UNSPEC
));

uv_run();
--EXPECT--
status: 0
OK
status: 0
OK
