<?php

$in  = uv_pipe_init(uv_default_loop(), ('/' == \DIRECTORY_SEPARATOR));
$out = uv_pipe_init(uv_default_loop(), ('/' == \DIRECTORY_SEPARATOR));

$signal = uv_signal_init();

uv_signal_start($signal, function ($signal) {
    print_r($signal);
    echo PHP_EOL . 'The CTRL+C signal received, click the [X] to close the window.' . PHP_EOL;
    uv_signal_stop($signal);
}, 2);

$signal = uv_signal_init();

uv_signal_start($signal, function ($signal) {
    print_r($signal);
    echo PHP_EOL . 'The SIGHUP signal received, the OS will close this session window!' . PHP_EOL;
}, 1);

echo "Hello, ";

$stdio = array();
$stdio[] = uv_stdio_new($in, UV::CREATE_PIPE | UV::READABLE_PIPE);
$stdio[] = uv_stdio_new($out, UV::CREATE_PIPE | UV::WRITABLE_PIPE);

$flags = 0;
$pid = uv_spawn(
    uv_default_loop(),
    "php",
    array('-r', 'echo "World! " . PHP_EOL;'),
    $stdio,
    __DIR__,
    [],
    function ($process, $stat, $signal) {
        if ($signal == 9) {
            echo "The process was terminated with 'SIGKILL' or '9' signal!" . PHP_EOL;
        }

        uv_close($process, function () {
        });
    },
    $flags
);

uv_read_start($out, function ($out, $nread, $buffer) {
    echo $buffer;

    uv_close($out, function () {
    });
});

uv_run();
