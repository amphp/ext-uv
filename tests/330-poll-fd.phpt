--TEST--
Check poll functions with with non socket file descriptors
--FILE--
<?php
$fd = fopen('php://temp', 'r+');
stream_set_blocking($fd, 0);
$loop = uv_loop_new();
$poll = uv_poll_init($loop, $fd);
uv_poll_start($poll, UV::READABLE, function($poll, $stat, $ev, $fd) {
    echo "OK";
    uv_poll_stop($poll);
    
    fclose($fd);
});
uv_run($loop);

fwrite($fd, 'hello');

--EXPECTF--
Fatal error: uv_poll_init(): invalid resource passed, this resource is not supported in %s on line %d
