--TEST--
Bad uv_spawn must not segfault (issue #79)
--FILE--
<?php
$rt = uv_spawn(
	uv_default_loop(),
	'',
	array(),
	array(),
	__DIR__,
	array(),
	static function () {
		echo 'Child Process exited'.PHP_EOL;
	}
);

var_dump($rt);

uv_run();
?>
--EXPECTF--
int(-%d)
