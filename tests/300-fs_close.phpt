--TEST--
Check for fs read and close
--FILE--
<?php
define("FIXTURE_PATH", dirname(__FILE__) . "/fixtures/hello.data");

uv_fs_open(uv_default_loop(),FIXTURE_PATH, UV::O_RDONLY, 0, function($r){
    uv_fs_read(uv_default_loop(),$r,0, 32,function($stream, $nread, $data) {
        uv_fs_close(uv_default_loop(), 42, function($result) {
            if($result != 42) {
                echo "OK";
            }
        }); 
    });
});

uv_run();
--EXPECTF--
Warning: uv_fs_close(): invalid resource type detected in %s on line %d
