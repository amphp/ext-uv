--TEST--
uv_fs_open + uv_fs_close in a loop should not leak refcount (issue 118)
--FILE--
<?php
$loop = uv_default_loop();
$path = tempnam(sys_get_temp_dir(), 'uvtest_');

$one = function () use ($loop, $path) {
    $done = false;
    uv_fs_open($loop, $path, UV::O_WRONLY, 0, function ($stream) use (&$done, $loop) {
        uv_fs_close($loop, $stream, function () use (&$done) {
            $done = true;
        });
    });
    while (!$done) {
        uv_run($loop, UV::RUN_ONCE);
    }
};

// Warm up to settle allocator
$one();

$baseline = memory_get_usage();
for ($i = 0; $i < 1000; $i++) {
    $one();
}

$delta = memory_get_usage() - $baseline;
echo $delta < 4096 ? "OK\n" : "LEAK ($delta bytes)\n";

unlink($path);
?>
--EXPECT--
OK
