--TEST--
Check for fs event
--FILE--
<?php
/* WIP
$ev = uv_fs_event_init(uv_default_loop(),dirname(DIRECTORY_PATH), function($rsc, $name, $event, $stat) {
  echo "stat: " . $stat . PHP_EOL;
  var_dump($rsc);

  uv_close($rsc, function(){
  });
  sleep(1);
},0);

uv_fs_mkdir(uv_default_loop(), DIRECTORY_PATH, 0755, function($result){
    var_dump($result);
    echo "finished" . PHP_EOL;
    @rmdir(DIRECTORY_PATH);
});

uv_run();
*/
--EXPECT--
