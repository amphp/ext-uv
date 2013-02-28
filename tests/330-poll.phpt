--TEST--
Check for fs read and close
--FILE--
<?php
$fd = fopen("testfile","w+");

$poll = uv_poll_init(uv_default_loop(), $fd);
uv_poll_start($poll, UV::WRITABLE, function($poll, $stat, $ev, $conn){
        fwrite($conn, "Hello");
        fclose($conn);
	$data = file_get_contents("testfile");
        if ($data == "Hello") {
		echo "OK";
	}
        unlink("testfile");
        uv_poll_stop($poll);
});

uv_run();
--EXPECT--
OK
