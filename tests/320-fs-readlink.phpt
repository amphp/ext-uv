--TEST--
uv_fs_readlink() segfaults if file not a link
--FILE--
<?php

$uv = uv_loop_new();

uv_fs_readlink($uv, __FILE__, function ($result) {
    var_dump($result < 0);
});

uv_run($uv);

?>
--EXPECT--
bool(true)
