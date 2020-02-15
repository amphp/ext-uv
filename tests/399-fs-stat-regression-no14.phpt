--TEST--
Check for #14
--FILE--
<?php
$loop = uv_default_loop();
$filename ="does_not_exist.txt";
uv_fs_stat($loop, $filename, function ($stat) use ($loop) {
	if (is_long($stat) && $stat < 0) {
		echo 'OK' . PHP_EOL;
	} else {
		echo "FAILED: uv_fs_stat should have returned an array with values" . PHP_EOL;
	}

	$filename = tempnam(sys_get_temp_dir(), 'test-no14');

	uv_fs_stat($loop, $filename, function ($stat) {
		if (is_array($stat) || !$stat) {
			echo 'OK' . PHP_EOL;
		} else {
			echo "FAILED: uv_fs_stat should have returned an array with values" . PHP_EOL;
		}
	});

});

uv_run();

--EXPECT--
OK
OK
