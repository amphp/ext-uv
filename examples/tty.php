<?php

uv_fs_open(uv_default_loop(), ('\\' === \DIRECTORY_SEPARATOR) ? '\\\\?\\CON' : '/dev/tty', UV::O_RDONLY, 0, function ($fd) {
    var_dump($fd);
    $tty = uv_tty_init(uv_default_loop(), $fd, 1);
    var_dump(uv_tty_get_winsize($tty, $width, $height));
    var_dump($width, $height);
});

uv_run();
