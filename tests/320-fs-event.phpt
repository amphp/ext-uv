--TEST--
Check for fs event
--FILE--
<?php
define("DIRECTORY_PATH", dirname(__FILE__) . "/fixtures/example_directory");

$ev = uv_fs_event_init(uv_default_loop(), dirname(DIRECTORY_PATH), function($rsc, $name, $event, $stat) {
  var_dump($name);
  uv_close($rsc);
}, 0);

uv_fs_mkdir(uv_default_loop(), DIRECTORY_PATH, 0755, function($result) {
    @rmdir(DIRECTORY_PATH);
});

uv_run();
--EXPECT--
string(17) "example_directory"
