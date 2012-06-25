--TEST--
Check for uv_get_process_title
--FILE--
<?php
uv_setup_args($_SERVER['argc'], $_SERVER['argv']);
// NOTE: have to call uv_setup_args before uv_get_process_title. (or I have to call RINIT phase.)
$title = uv_get_process_title();

if (strlen($title) > 0) {
  echo "OK";
} else {
  echo "FAILED: {$title}";
}
--EXPECT--
OK