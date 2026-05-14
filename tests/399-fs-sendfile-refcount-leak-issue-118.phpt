--TEST--
uv_fs_sendfile in a loop should not leak (issue 118)
--FILE--
<?php
$loop = uv_default_loop();
$src = tempnam(sys_get_temp_dir(), 'uvsrc_');
file_put_contents($src, str_repeat('x', 256));
$dst = tempnam(sys_get_temp_dir(), 'uvdst_');

// helper to do one open/sendfile/close cycle synchronously
$one = function () use ($loop, $src, $dst) {
    $in = null;
    $out = null;
    $done = false;
    uv_fs_open($loop, $src, UV::O_RDONLY, 0, function ($opened) use (&$in, &$done) {
        $in = $opened;
        $done = true;
    });
    while (!$done) {
        uv_run($loop, UV::RUN_ONCE);
    }

    $done = false;
    uv_fs_open($loop, $dst, UV::O_WRONLY | UV::O_CREAT, 0644, function ($opened) use (&$out, &$done) {
        $out = $opened;
        $done = true;
    });
    while (!$done) {
        uv_run($loop, UV::RUN_ONCE);
    }

    $done = false;
    uv_fs_sendfile($loop, $out, $in, 0, 256, function () use (&$done) {
        $done = true;
    });
    while (!$done) {
        uv_run($loop, UV::RUN_ONCE);
    }

    $done = false;
    uv_fs_close($loop, $in, function () use (&$done) {
        $done = true;
    });
    while (!$done) {
        uv_run($loop, UV::RUN_ONCE);
    }

    $done = false;
    uv_fs_close($loop, $out, function () use (&$done) {
        $done = true;
    });
    while (!$done) {
        uv_run($loop, UV::RUN_ONCE);
    }
};

/* warm up to settle the allocator */
$one();

$base = memory_get_usage();
for ($i = 0; $i < 500; $i++) {
    $one();
}

$delta = memory_get_usage() - $base;
echo $delta < 4096 ? "OK\n" : "LEAK ($delta bytes)\n";

unlink($src);
unlink($dst);
?>
--EXPECT--
OK
