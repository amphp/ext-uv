<?php

$loop  = uv_default_loop();

$thread = function () {
  echo "THREAD-CALL\n";
};

$after = function () {
  echo "THREAD-CALL-AFTER\n";
};

uv_queue_work($loop, $thread, $after);
uv_queue_work($loop, $thread, $after);

$timer = uv_timer_init($loop);

uv_timer_start($timer, 1000, 1000, function ($time) {
  static $i = 0;

  echo "TIMER: $i\n";

  $i++;
  if ($i === 11)
    uv_timer_stop($time);
});

uv_run($loop);
