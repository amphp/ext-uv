--TEST--
uv_fs_close should not bump the resource refcount (issue 118)
--FILE--
<?php
$loop = uv_default_loop();
$path = tempnam(sys_get_temp_dir(), 'uvtest_');

$stream = null;
$done = false;
uv_fs_open($loop, $path, UV::O_WRONLY, 0, function ($opened) use (&$stream, &$done) {
    $stream = $opened;
    $done = true;
});
while (!$done) {
    uv_run($loop, UV::RUN_ONCE);
}

// rc before close (in arg context, +1 for debug_zval_dump)
ob_start();
debug_zval_dump($stream);
$before = ob_get_clean();

$done = false;
uv_fs_close($loop, $stream, function () use (&$done) {
    $done = true;
});
while (!$done) {
    uv_run($loop, UV::RUN_ONCE);
}

ob_start();
debug_zval_dump($stream);
$after = ob_get_clean();

preg_match('/refcount\((\d+)\)/', $before, $b);
preg_match('/refcount\((\d+)\)/', $after, $a);
echo "rc unchanged: " . ($b[1] === $a[1] ? "yes" : "no ($b[1] -> $a[1])") . "\n";

unlink($path);
?>
--EXPECT--
rc unchanged: yes
