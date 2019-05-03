--TEST--
uv_fs_readlink() segfaults if file not a link
--FILE--
<?php

$uv = uv_loop_new();

uv_fs_readlink($uv, __FILE__, function () {
    var_dump(func_get_args());
});

uv_run($uv);

?>
--EXPECT--
array(2) {
  [0]=>
  bool(false)
  [1]=>
  NULL
}

