--TEST--
Check for fs mkdir
--FILE--
<?php
define("DIRECTORY_PATH", dirname(__FILE__) . "/fixtures/example_directory");
@rmdir(DIRECTORY_PATH);
uv_fs_mkdir(uv_default_loop(), DIRECTORY_PATH, 0755, function($result) {
    var_dump($result);
    rmdir(DIRECTORY_PATH);
});

uv_run();

--EXPECTF--
bool(true)
