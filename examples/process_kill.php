<?php

$in  = uv_pipe_init(uv_default_loop(), ('/' == \DIRECTORY_SEPARATOR));
$out = uv_pipe_init(uv_default_loop(), ('/' == \DIRECTORY_SEPARATOR));

echo "Hello, ";

$stdio = array();
$stdio[] = uv_stdio_new($in, UV::CREATE_PIPE | UV::READABLE_PIPE);
$stdio[] = uv_stdio_new($out, UV::CREATE_PIPE | UV::WRITABLE_PIPE);

$flags = 0;
$pid = uv_spawn(
    uv_default_loop(),
    "php",
    array('-r', 'echo "World! ";'),
    $stdio,
    __DIR__,
    [],
    function ($process, $stat, $signal) {
        if ($signal == 9) {
            echo "The process was terminated with 'SIGKILL' or '9' signal!";
        }

        uv_close($process, function () {
        });
    },
    $flags
);

uv_process_kill($pid, 9);

uv_read_start($out, function ($out, $nread, $buffer) {
    echo $buffer;

    uv_close($out, function () {
    });
});

uv_run();
