--TEST--
Check for #14
--FILE--
<?php
$loop = uv_default_loop();
$filename ="does_not_exist.txt";
uv_fs_stat($loop, $filename, function ($result, $stat) {
    if($result < 0) {
        echo  'OK' . PHP_EOL;
    } else {
        echo 'FAILED: uv_fs_stat should have returned a value less than 0' . PHP_EOL;
    }

    if (is_null($stat)) {
        echo "NULL" . PHP_EOL;
    } else {
        echo "FAILED: uv_fs_stat \$stat return value should be NULL" . PHP_EOL;
    }
});

$filename = tempnam(sys_get_temp_dir(), 'test-no14');

uv_fs_stat($loop, $filename, function ($result, $stat) {
    if($result === 0) {
        echo 'OK' . PHP_EOL;
    } else {
        echo "FAILED: uv_fs_stat should have returned a result of 0" . PHP_EOL;
    }

    if(!empty($stat)) {
        echo 'OK' . PHP_EOL;
    } else {
        echo 'FAILED: $stat should be an array with values' . PHP_EOL;
    }
});

uv_run();

--EXPECT--
OK
NULL
OK
OK
