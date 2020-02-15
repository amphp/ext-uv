--TEST--
Basic scandir functionality
--FILE--
<?php

uv_fs_scandir(uv_default_loop(), ".", function($result) {
	var_dump(count($result) > 1);
});

uv_run();
?>
--EXPECT--
bool(true)
