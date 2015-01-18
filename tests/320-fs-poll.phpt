--TEST--
Check for fs poll
--FILE--
<?php
define("FIXTURE_PATH", dirname(__FILE__) . "/fixtures/poll");

$poll = uv_fs_poll_init(uv_default_loop());

fclose(fopen(FIXTURE_PATH, "w+"));

$i = 0;
uv_fs_poll_start($poll,function($rsc,$stat,$p,$c) use (&$i) {
    echo "OK";
    
    if ($i > 3) {
        uv_fs_poll_stop($rsc);
        uv_unref($rsc);
    }
    $i++;
}, FIXTURE_PATH, 1);

$timer = uv_timer_init();
uv_timer_start($timer, 100, 100, function($timer) use (&$i) {
    $fp = fopen(FIXTURE_PATH, "w+");
    fwrite($fp,"hoge");
    fclose($fp);
    
    if ($i > 4) {
        uv_timer_stop($timer);
        uv_unref($timer);
    }
});

uv_run();
--EXPECT--
OKOKOKOKOK
