--TEST--
Check for uv_poll_init with an Io\Poll\Handle
--SKIPIF--
<?php
if (PHP_VERSION_ID < 80600) {
	die("skip PHP 8.6 or later required");
}
?>
--FILE--
<?php
$loop = uv_default_loop();
[$a, $b] = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, 0);

$handle = new StreamPollHandle($a);
$poll = uv_poll_init($loop, $handle);

// the watcher keeps the handle alive, since a handle owns what it watches
unset($handle);

uv_poll_start($poll, UV::READABLE, function ($poll, $status, $events, $subject) {
	var_dump($subject instanceof StreamPollHandle);
	var_dump($subject->isValid());
	uv_poll_stop($poll);
});

fwrite($b, "x");
uv_run($loop);

echo "OK" . PHP_EOL;
?>
--EXPECT--
bool(true)
bool(true)
OK
