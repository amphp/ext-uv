--TEST--
Check for #14
--FILE--
<?php
$loop = uv_default_loop();
$filename ="does_not_exist.txt";
uv_fs_stat($loop, $filename, function ($result, $stat) {
    echo $result . PHP_EOL;
    if (is_null($stat)) {
        echo "NULL" . PHP_EOL;
    }
});
uv_run();

--EXPECT--
-1
NULL