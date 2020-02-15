--TEST--
Check for pipe bind
--FILE--
<?php
define("PIPE_PATH", dirname(__FILE__) . "/pipe_test.sock");
@unlink(PIPE_PATH);
$a = uv_pipe_init(uv_default_loop(), 0);
$ret = uv_pipe_bind($a, PIPE_PATH);

uv_listen($a, 8192, function($stream) {
    $pipe = uv_pipe_init(uv_default_loop(), 0);
    uv_accept($stream, $pipe);
    uv_read_start($pipe,function($pipe, $data) use ($stream) {
        if ($data === \UV::EOF) {
            return;
        }

        echo $data;
        uv_read_stop($pipe);
        uv_close($stream, function() {
            @unlink(PIPE_PATH);
        });
    });
});

$pipe = uv_pipe_init(uv_default_loop(), 0);
uv_pipe_connect($pipe, PIPE_PATH, function($pipe, $status) {
    uv_write($pipe, "Hello", function($stream, $stat) {
        uv_close($stream);
    });
});

uv_run();
exit;
--EXPECT--
Hello
