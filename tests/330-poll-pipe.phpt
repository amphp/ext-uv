--TEST--
Check poll of a pipe works
--FILE--
<?php
$php = (getenv('TEST_PHP_EXECUTABLE') ? : PHP_BINARY)  . ' ' . (getenv('TEST_PHP_ARGS') ? : '-n');
$fd = popen($php . " ". __DIR__ . "/fixtures/proc.php 2>&1", "w");
stream_set_blocking($fd, 0);

$loop = uv_loop_new();
$poll = uv_poll_init($loop, $fd);

uv_poll_start($poll, UV::READABLE, function($poll, $stat, $ev, $fd) {
    echo "\nOK";
    uv_poll_stop($poll);
    pclose($fd);
});
uv_run($loop);
--EXPECT--
hello
OK
