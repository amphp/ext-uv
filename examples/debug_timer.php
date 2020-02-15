<?php
$timer = uv_timer_init();

$stat = array();
$stat['begin'] = memory_get_usage();

uv_timer_start($timer, 10, 1000, function($timer) use (&$stat) {
    $stat["current"] = memory_get_usage();
    printf("memory: %d\n", $stat["current"] - $stat['begin']);
});

uv_run();
