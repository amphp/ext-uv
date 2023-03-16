<?php
$loop = \uv_default_loop();
[$read, $write] = \stream_socket_pair((\stripos(\PHP_OS, "win") === 0 ? \STREAM_PF_INET : \STREAM_PF_UNIX),
    \STREAM_SOCK_STREAM,
    \STREAM_IPPROTO_IP
);

$function = function () use ($write) {
    echo "[queue1]";
    \fwrite($write, "Thread 1\n");
    \usleep(1);
};

\uv_queue_work($loop, $function, function () {
});

\uv_queue_work($loop, function () use ($read) {
    echo "[queue2] ";
    echo "Thread 2 Got " . \fgets($read);
}, function () {
});

\uv_run($loop);
\fclose($write);
