--TEST--
uv_fs_write does not leak resource refcount (issue 118)
--SKIPIF--
<?php
if (!extension_loaded('uv')) die("skip uv ext not loaded");
?>
--FILE--
<?php
$loop = uv_default_loop();
$path = tempnam(sys_get_temp_dir(), 'uvtest_');
$one = function () use ($loop, $path) {
    $stream = null;
    $done = false;
    uv_fs_open($loop, $path, UV::O_WRONLY, 0, function ($opened) use (&$stream, &$done) {
        $stream = $opened;
        $done = true;
    });
    while (!$done) {
        uv_run($loop, UV::RUN_ONCE);
    }

    $done = false;
    uv_fs_write($loop, $stream, "hello\n", 0, function () use (&$done) {
        $done = true;
    });
    while (!$done) {
        uv_run($loop, UV::RUN_ONCE);
    }

    $done = false;
    uv_fs_close($loop, $stream, function () use (&$done) {
        $done = true;
    });
    while (!$done) {
        uv_run($loop, UV::RUN_ONCE);
    }
};

/* warm up to settle the allocator */
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
